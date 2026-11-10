import { dirname, join } from "node:path";
import { spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import { mkdirSync } from "node:fs";
import { fileURLToPath } from "node:url";
import type { ProviderSession, TurnContext } from "../types.js";
import { msg } from "../messages.js";
import { cliPath, findCli } from "./locate.js";
import { approvalIdFromText, displayToolName, runIdFromText, summarizeText } from "../tools.js";

/**
 * Agents that bring their own loop (Claude Code, Codex) and run on the operator's own
 * subscription. Penteos launches them with its MCP server as their ONLY way to act: their
 * built-in shell/file/web tools are disabled or sandboxed without network, so nothing can reach
 * a target without passing through the scope checks.
 */

/** How an MCP client starts the Penteos bridge (same Node, same sources as this process). */
export function mcpLaunch(dataDir: string): { command: string; args: string[]; env: Record<string, string> } {
  const here = fileURLToPath(import.meta.url);
  const fromSource = here.endsWith(".ts");
  // Packaged: the core is one bundled file (core.mjs) with the bridge next to it (mcp.mjs).
  const bundled = here.endsWith("core.mjs");
  const bridge = bundled ? join(dirname(here), "mcp.mjs") : fileURLToPath(new URL(fromSource ? "../../mcp.ts" : "../../mcp.js", import.meta.url));
  const args = fromSource ? ["--conditions=penteos-source", "--import", import.meta.resolve("tsx"), bridge] : [bridge];
  // Inside the desktop app this process is Electron running as Node: the bridge needs the same.
  const env: Record<string, string> = { PENTEOS_DATA_DIR: dataDir, ...(process.versions.electron ? { ELECTRON_RUN_AS_NODE: "1" } : {}) };
  return { command: process.execPath, args, env };
}

/** Environment for a child agent: drop variables that would make it think it is nested in another session. */
function childEnv(): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = { ...process.env, PATH: cliPath() };
  for (const key of Object.keys(env)) {
    if (key === "CLAUDECODE" || key.startsWith("CLAUDE_CODE_") || key === "ELECTRON_RUN_AS_NODE") delete env[key];
  }
  return env;
}

function runJsonLines(
  command: string,
  args: string[],
  ctx: TurnContext,
  stdin: string | undefined,
  onLine: (event: Record<string, unknown>) => void,
): Promise<void> {
  mkdirSync(ctx.workDir, { recursive: true });
  return new Promise((resolve, reject) => {
    const child = spawn(findCli(command) ?? command, args, { cwd: ctx.workDir, env: childEnv(), stdio: ["pipe", "pipe", "pipe"] });
    const abort = () => child.kill("SIGTERM");
    ctx.signal.addEventListener("abort", abort, { once: true });
    let buffer = "";
    let stderr = "";
    child.stdout.on("data", (chunk: Buffer) => {
      buffer += chunk.toString("utf8");
      let nl: number;
      while ((nl = buffer.indexOf("\n")) >= 0) {
        const line = buffer.slice(0, nl).trim();
        buffer = buffer.slice(nl + 1);
        if (!line.startsWith("{")) continue;
        try {
          onLine(JSON.parse(line) as Record<string, unknown>);
        } catch {
          /* not JSON: ignore */
        }
      }
    });
    child.stderr.on("data", (chunk: Buffer) => {
      stderr = (stderr + chunk.toString("utf8")).slice(-4000);
    });
    child.on("error", (error) => reject(new Error(`${command}: ${error.message}`)));
    child.on("close", (code) => {
      ctx.signal.removeEventListener("abort", abort);
      if (code === 0 || ctx.signal.aborted) resolve();
      else reject(new Error(cliError(command, code, stderr)));
    });
    if (stdin !== undefined) child.stdin.end(stdin);
    else child.stdin.end();
  });
}

/** A readable one-line error from a CLI's stderr (they can dump whole prompts on failure). */
function cliError(command: string, code: number | null, stderr: string): string {
  const detail = /"detail":"([^"]+)"/.exec(stderr)?.[1] ?? /"message":"([^"]+)"/.exec(stderr)?.[1];
  const last = stderr.trim().split("\n").filter(Boolean).at(-1) ?? "";
  const text = detail ?? (last.length > 300 ? `${last.slice(0, 300)}…` : last);
  return `${command} exited with code ${code}${text ? `: ${text}` : ""}`;
}

function short(value: unknown): string {
  const text = typeof value === "string" ? value : JSON.stringify(value ?? "");
  return text.length > 80 ? `${text.slice(0, 80)}…` : text;
}

// ---------------------------------------------------------------------------------------------
// Claude Code
// ---------------------------------------------------------------------------------------------

export class ClaudeCodeSession implements ProviderSession {
  // Claude Code keeps the session on disk itself: remembering its id is enough to resume.
  private readonly sessionId: string;
  private started: boolean;

  constructor(state?: unknown) {
    const s = state as { sessionId?: string; started?: boolean } | undefined;
    this.sessionId = s?.sessionId ?? randomUUID();
    this.started = Boolean(s?.started);
  }

  snapshot(): unknown {
    return { sessionId: this.sessionId, started: this.started };
  }

  async send(text: string, ctx: TurnContext): Promise<void> {
    const mcp = mcpLaunch(ctx.dataDir);
    const args = [
      "-p",
      "--output-format", "stream-json",
      "--verbose",
      "--include-partial-messages",
      "--tools", "", // no built-in tools: no shell, no files, no web
      "--mcp-config", JSON.stringify({ mcpServers: { penteos: { type: "stdio", ...mcp } } }),
      "--strict-mcp-config",
      "--allowedTools", "mcp__penteos",
      "--permission-mode", "dontAsk",
      "--system-prompt", ctx.system,
      ...(ctx.settings.model ? ["--model", ctx.settings.model] : []),
      ...(this.started ? ["--resume", this.sessionId] : ["--session-id", this.sessionId]),
    ];
    this.started = true;
    let streamedText = false;
    const tools = new Map<string, { name: string; input: unknown }>();

    await runJsonLines("claude", args, ctx, text, (e) => {
      if (e.type === "stream_event") {
        const event = e.event as { type?: string; delta?: { type?: string; text?: string } };
        if (event.type === "content_block_delta" && event.delta?.type === "text_delta" && event.delta.text) {
          streamedText = true;
          ctx.emit({ kind: "delta", text: event.delta.text });
        }
        return;
      }
      if (e.type === "assistant") {
        const content = ((e.message as { content?: unknown[] })?.content ?? []) as Array<Record<string, unknown>>;
        for (const block of content) {
          if (block.type === "text" && !streamedText) ctx.emit({ kind: "text", text: String(block.text) });
          if (block.type === "tool_use") {
            const name = displayToolName(String(block.name));
            tools.set(String(block.id), { name, input: block.input });
            ctx.emit({ kind: "tool", id: String(block.id), name, input: block.input, status: "running" });
          }
        }
        streamedText = false;
        return;
      }
      if (e.type === "user") {
        const content = ((e.message as { content?: unknown[] })?.content ?? []) as Array<Record<string, unknown>>;
        for (const block of content) {
          if (block.type !== "tool_result") continue;
          const id = String(block.tool_use_id);
          const tool = tools.get(id) ?? { name: "tool", input: {} };
          const body = Array.isArray(block.content) ? (block.content as Array<{ text?: string }>).map((c) => c.text ?? "").join("") : String(block.content ?? "");
          const approvalId = block.is_error ? undefined : approvalIdFromText(body);
          const runId = block.is_error ? undefined : runIdFromText(body);
          ctx.emit({ kind: "tool", id, name: tool.name, input: tool.input, status: block.is_error ? "error" : "ok", summary: block.is_error ? short(body) : summarizeText(tool.name, body), ...(approvalId ? { approvalId } : {}), ...(runId ? { runId } : {}) });
        }
        return;
      }
      if (e.type === "result" && e.is_error) {
        ctx.emit({ kind: "error", text: String(e.result ?? e.subtype ?? "Claude Code returned an error") });
      }
    });
  }
}

// ---------------------------------------------------------------------------------------------
// Codex
// ---------------------------------------------------------------------------------------------

const toml = (value: string) => JSON.stringify(value); // TOML basic strings share JSON escaping

export class CodexSession implements ProviderSession {
  private threadId: string | undefined;

  constructor(state?: unknown) {
    this.threadId = (state as { threadId?: string } | undefined)?.threadId;
  }

  snapshot(): unknown {
    return { threadId: this.threadId };
  }

  async send(text: string, ctx: TurnContext): Promise<void> {
    const mcp = mcpLaunch(ctx.dataDir);
    const options = [
      "--json",
      "--skip-git-repo-check",
      "-s", "read-only", // shell sandbox without network: targets are only reachable through Penteos
      "-C", ctx.workDir,
      "-c", `mcp_servers.penteos.command=${toml(mcp.command)}`,
      "-c", `mcp_servers.penteos.args=[${mcp.args.map(toml).join(", ")}]`,
      "-c", `mcp_servers.penteos.env={ ${Object.entries(mcp.env).map(([k, v]) => `${k} = ${toml(v)}`).join(", ")} }`,
      // Codex's own MCP approval prompt would block every target tool in exec mode. Penteos already
      // decides per call (scope, risk ceiling, human approvals), so Codex defers to it.
      "-c", `mcp_servers.penteos.default_tools_approval_mode="approve"`,
      ...(ctx.settings.model ? ["-m", ctx.settings.model] : []),
    ];
    // Codex has no system-prompt flag: the rules travel with the first message of the thread.
    const prompt = this.threadId ? text : `${ctx.system}\n\n---\n\nOperator: ${text}`;
    const args = this.threadId ? ["exec", ...options, "resume", this.threadId, "-"] : ["exec", ...options, "-"];

    await runJsonLines("codex", args, ctx, prompt, (e) => {
      if (e.type === "thread.started" && typeof e.thread_id === "string") this.threadId = e.thread_id;
      const item = e.item as Record<string, unknown> | undefined;
      if (item && (e.type === "item.started" || e.type === "item.completed")) {
        const id = String(item.id ?? "");
        if (item.type === "agent_message" && e.type === "item.completed") ctx.emit({ kind: "text", text: String(item.text ?? "") });
        if (item.type === "mcp_tool_call") {
          const name = displayToolName(String(item.tool ?? "tool"));
          const failed = item.status === "failed" || Boolean(item.error);
          const result = item.result as { content?: Array<{ text?: string }> } | undefined;
          const summary = failed ? short((item.error as { message?: string })?.message ?? "error") : summarizeText(name, result?.content?.[0]?.text ?? "");
          const text = e.type === "item.completed" && !failed ? (result?.content?.[0]?.text ?? "") : "";
          const approvalId = text ? approvalIdFromText(text) : undefined;
          const runId = text ? runIdFromText(text) : undefined;
          ctx.emit({ kind: "tool", id, name, input: item.arguments, status: e.type === "item.started" ? "running" : failed ? "error" : "ok", ...(e.type === "item.completed" ? { summary } : {}), ...(approvalId ? { approvalId } : {}), ...(runId ? { runId } : {}) });
        }
        if (item.type === "command_execution" && e.type === "item.completed") {
          ctx.emit({ kind: "status", text: msg(ctx.lang ?? "en", "provider.codexShell", { command: short(item.command) }) });
        }
      }
      if (e.type === "turn.failed" || e.type === "error") {
        const raw = (e.error as { message?: string })?.message ?? (e.message as string | undefined) ?? "Codex returned an error";
        const message = /"detail":"([^"]+)"/.exec(raw)?.[1] ?? raw;
        ctx.emit({ kind: "error", text: message });
      }
    });
  }
}
