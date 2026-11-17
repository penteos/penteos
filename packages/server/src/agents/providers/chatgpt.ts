import OpenAI from "openai";
import { recordEvent } from "@penteos/core";
import { type ChatGptAuth, ChatGptSignedOut } from "../chatgpt-auth.js";
import { type FailureKind, ProviderFailure } from "../failover.js";
import { msg } from "../messages.js";
import type { ProviderSession, TurnContext } from "../types.js";
import { agentOperations, displayToolName, LAST_STEP_NOTE, runTool, toolName, toolSchema } from "../tools.js";
import { announce, isContextOverflow, keepWithinBudget, memoryBudget, type MemoryAdapter, responsesAdapter } from "../memory.js";

const MAX_STEPS = 40;

/** A conversation item as the Responses API takes it back (no server-side storage: the whole history goes every time). */
type Item =
  | { role: "user" | "assistant" | "developer"; content: string }
  | { type: "function_call"; call_id: string; name: string; arguments: string }
  | { type: "function_call_output"; call_id: string; output: string };

/** What the plan route answers with, and what the operator should read (developers.openai.com/siwc errors). */
function explain(code: string | undefined, lang: TurnContext["lang"], detail?: string): string {
  const L = lang ?? "en";
  switch (code) {
    case "subscription_sharing_usage_limit_exceeded":
      return msg(L, "provider.chatgpt.limit");
    case "subscription_sharing_user_not_eligible":
      return msg(L, "provider.chatgpt.notEligible");
    case "subscription_sharing_usage_unavailable":
    case "subscription_sharing_user_unavailable":
      return msg(L, "provider.chatgpt.unavailable");
    case "subscription_sharing_invalid_user":
    case "chatpass_v2_scope_not_authorized":
    case "chatpass_v2_invalid_authorization_context":
      return msg(L, "provider.chatgpt.signedOut");
    case "subscription_sharing_unsupported_capability":
      return msg(L, "provider.chatgpt.unsupported", { detail: detail ?? "" });
    default:
      return msg(L, "provider.chatgpt.error", { detail: detail ?? code ?? "?" });
  }
}

/** The plan's answers another AI could carry on from (the Maestro's failover, failover.ts). */
function failureOf(code: string | undefined): FailureKind | undefined {
  switch (code) {
    case "subscription_sharing_usage_limit_exceeded":
      return "quota";
    case "subscription_sharing_user_not_eligible":
    case "subscription_sharing_invalid_user":
    case "chatpass_v2_scope_not_authorized":
    case "chatpass_v2_invalid_authorization_context":
      return "auth";
    case "subscription_sharing_usage_unavailable":
    case "subscription_sharing_user_unavailable":
      return "down";
    default:
      return undefined;
  }
}

/**
 * The agent on the operator's ChatGPT plan: the Responses API with their Sign in with ChatGPT
 * token. Penteos runs the loop and the tools, exactly as with an API key; the plan's rules apply
 * (store:false and streaming on every request, no system items: the brief goes as instructions).
 */
export class ChatGptPlanSession implements ProviderSession {
  private readonly items: Item[];
  /** The model's window as learned from an overflow, when smaller than the budget. */
  private window?: number;

  constructor(
    private readonly auth: ChatGptAuth,
    state?: unknown,
  ) {
    this.items = Array.isArray((state as { items?: unknown })?.items) ? ((state as { items: Item[] }).items) : [];
    // A restart in the middle of a turn can leave calls without results: close them.
    const answered = new Set(this.items.filter((i): i is Extract<Item, { type: "function_call_output" }> => "type" in i && i.type === "function_call_output").map((i) => i.call_id));
    for (const i of [...this.items]) {
      if ("type" in i && i.type === "function_call" && !answered.has(i.call_id)) this.items.push({ type: "function_call_output", call_id: i.call_id, output: "Interrupted: Penteos restarted before this call finished. Check its state before retrying." });
    }
  }

  snapshot(): unknown {
    return { items: this.items };
  }

  async send(text: string, ctx: TurnContext): Promise<void> {
    const lang = ctx.lang ?? "en";
    const tools = agentOperations(ctx.allow).map((op) => ({ type: "function" as const, name: toolName(op.name), description: op.description, parameters: toolSchema(op.name) as Record<string, unknown>, strict: false }));
    this.items.push({ role: "user", content: text });
    const budget = () => Math.min(ctx.memoryTokens ?? memoryBudget(false), this.window ?? Infinity);
    let overflowRetried = false;

    for (let step = 0; step < MAX_STEPS; step++) {
      if (ctx.signal.aborted) return;
      let token: string;
      try {
        token = await this.auth.token();
      } catch (e) {
        if (e instanceof ChatGptSignedOut) throw new ProviderFailure("auth", msg(lang, "provider.chatgpt.signedOut"));
        throw new ProviderFailure("down", msg(lang, "provider.chatgpt.unavailable"));
      }
      const client = new OpenAI({ apiKey: token, baseURL: this.auth.endpoints.api, maxRetries: 0 });
      const model = ctx.settings.model || (await this.defaultModel());
      // A long round stays within the model's memory (the plan streams, and stores nothing).
      const summarize = async (system: string, transcript: string) => {
        let out = "";
        const s = await client.responses.create({ model, instructions: system, input: [{ role: "user", content: transcript }], store: false, stream: true }, { signal: ctx.signal });
        for await (const ev of s) if (ev.type === "response.output_text.delta") out += ev.delta;
        return out;
      };
      const remember = async (force = false) => {
        const outcome = await keepWithinBudget(this.items, responsesAdapter as unknown as MemoryAdapter<Item>, budget(), summarize, { force, signal: ctx.signal });
        if (force && outcome) this.window = outcome.budgetTokens;
        announce(outcome, ctx);
      };
      await remember();
      let content = "";
      const calls: Array<{ call_id: string; name: string; arguments: string }> = [];
      let completed = false;
      let failure: { code?: string; message?: string } | undefined;
      try {
        const stream = await client.responses.create(
          {
            model,
            instructions: ctx.system,
            input: this.items as unknown as OpenAI.Responses.ResponseInput,
            tools,
            ...(step === MAX_STEPS - 1 ? { tool_choice: "none" as const } : {}),
            store: false,
            stream: true,
          },
          { signal: ctx.signal },
        );
        for await (const event of stream) {
          if (event.type === "response.output_text.delta") {
            content += event.delta;
            ctx.emit({ kind: "delta", text: event.delta });
          } else if (event.type === "response.output_item.done" && event.item.type === "function_call") {
            calls.push({ call_id: event.item.call_id, name: event.item.name, arguments: event.item.arguments });
          } else if (event.type === "response.completed") {
            completed = true;
          } else if (event.type === "response.failed") {
            failure = { code: event.response.error?.code, message: event.response.error?.message };
          } else if (event.type === "response.incomplete") {
            failure = { code: "incomplete", message: event.response.incomplete_details?.reason ?? "incomplete" };
          } else if (event.type === "error") {
            failure = { code: event.code ?? undefined, message: event.message };
          }
        }
      } catch (e) {
        if (ctx.signal.aborted) return;
        if (!overflowRetried && isContextOverflow(e)) {
          overflowRetried = true;
          await remember(true);
          step--;
          continue;
        }
        const err = e as { status?: number; code?: string; error?: { code?: string; param?: string }; message?: string };
        const kind = failureOf(err.code ?? err.error?.code);
        if (kind) throw new ProviderFailure(kind, explain(err.code ?? err.error?.code, lang, err.error?.param ?? err.message));
        // A status the SDK gave (429, 5xx, 401…): the failover classifies it.
        if (err.status && (err.status >= 500 || err.status === 429 || err.status === 401 || err.status === 403 || err.status === 402)) throw e;
        ctx.emit({ kind: "error", text: explain(err.code ?? err.error?.code, lang, err.error?.param ?? err.message) });
        return;
      }
      // Only response.completed is a success: a stream that stops, or fails half-way, is said.
      if (failure && !overflowRetried && isContextOverflow(failure)) {
        overflowRetried = true;
        await remember(true);
        step--;
        continue;
      }
      if (failure && failureOf(failure.code)) throw new ProviderFailure(failureOf(failure.code)!, explain(failure.code, lang, failure.message));
      if (failure || !completed) {
        ctx.emit({ kind: "error", text: explain(failure?.code, lang, failure?.message ?? "the stream ended early") });
        return;
      }
      overflowRetried = false;
      if (content) this.items.push({ role: "assistant", content });
      for (const c of calls) this.items.push({ type: "function_call", call_id: c.call_id, name: c.name, arguments: c.arguments || "{}" });
      if (calls.length === 0) {
        if (!content.trim()) ctx.emit({ kind: "error", text: msg(lang, "provider.error.empty") });
        return;
      }
      for (const c of calls) {
        let input: unknown;
        try {
          input = JSON.parse(c.arguments || "{}");
        } catch {
          this.items.push({ type: "function_call_output", call_id: c.call_id, output: "INVALID_JSON: the arguments were not valid JSON; call the tool again." });
          continue;
        }
        ctx.emit({ kind: "tool", id: c.call_id, name: displayToolName(c.name), input, status: "running" });
        const outcome = await runTool(c.name, input, ctx.ops, ctx.allow);
        ctx.emit({ kind: "tool", id: c.call_id, name: displayToolName(c.name), input, status: outcome.ok ? "ok" : "error", summary: outcome.summary, ...(outcome.approvalId ? { approvalId: outcome.approvalId } : {}), ...(outcome.runId ? { runId: outcome.runId } : {}) });
        this.items.push({ type: "function_call_output", call_id: c.call_id, output: outcome.content });
      }
      if (step === MAX_STEPS - 2) {
        this.items.push({ role: "developer", content: LAST_STEP_NOTE });
        ctx.emit({ kind: "status", text: msg(lang, "provider.status.lastStep", { n: MAX_STEPS }) });
        try {
          recordEvent(ctx.ops.engagement(), "stepLimit");
        } catch {
          /* no engagement */
        }
      }
    }
    ctx.emit({ kind: "error", text: msg(lang, "provider.error.maxSteps", { n: MAX_STEPS }) });
  }

  /** The account's first listed model when the operator has not picked one. */
  private async defaultModel(): Promise<string> {
    const models = await this.auth.models().catch(() => []);
    return models[0]?.slug ?? "gpt-5";
  }
}
