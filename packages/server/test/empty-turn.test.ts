import { createServer, type Server } from "node:http";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { OpenAICompatibleSession, sanitizeHistory } from "../src/agents/providers/openai-compatible.js";
import type { AgentEvent } from "../src/agents/types.js";

/**
 * A reasoning model (DeepSeek) that thinks and answers nothing must not break the conversation: an
 * empty assistant turn stored once made every later request fail with "400 Invalid assistant
 * message: content or tool_calls must be set", forever.
 */

let server: Server;
let port: number;
let plan: Array<"think-only" | "answer">;
let rejected = 0;
let requests = 0;

beforeEach(async () => {
  plan = [];
  rejected = 0;
  requests = 0;
  server = createServer((req, res) => {
    let body = "";
    req.on("data", (d) => (body += String(d)));
    req.on("end", () => {
      requests++;
      const { messages } = JSON.parse(body) as { messages: Array<{ role: string; content?: unknown; tool_calls?: unknown[] }> };
      // As strict as DeepSeek's API.
      if (messages.some((m) => m.role === "assistant" && !m.content && !(m.tool_calls?.length))) {
        rejected++;
        res.writeHead(400, { "content-type": "application/json" });
        res.end(JSON.stringify({ error: { message: "Invalid assistant message: content or tool_calls must be set" } }));
        return;
      }
      const next = plan.shift() ?? "answer";
      res.writeHead(200, { "content-type": "text/event-stream" });
      const chunk = (delta: object, finish: string | null) => `data: ${JSON.stringify({ id: "x", object: "chat.completion.chunk", created: 0, model: "m", choices: [{ index: 0, delta, finish_reason: finish }] })}\n\n`;
      if (next === "think-only") res.write(chunk({ role: "assistant", reasoning_content: "Pienso mucho y no digo nada…" }, null));
      else res.write(chunk({ role: "assistant", content: "Listo." }, null));
      res.write(chunk({}, "stop"));
      res.end("data: [DONE]\n\n");
    });
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", () => r()));
  port = (server.address() as { port: number }).port;
});
afterEach(async () => {
  await new Promise((r) => server.close(r));
});

const ctx = (events: AgentEvent[]) =>
  ({
    system: "system",
    ops: { engagement: () => { throw new Error("none"); } },
    caller: {},
    settings: { baseUrl: `http://127.0.0.1:${port}/v1`, apiKey: "k", model: "m" },
    workDir: "/tmp",
    dataDir: "/tmp",
    emit: (e: AgentEvent) => events.push(e),
    signal: new AbortController().signal,
    lang: "es",
  }) as never;

describe("an empty turn", () => {
  it("is asked again once, then said - never stored; the conversation goes on", async () => {
    const session = new OpenAICompatibleSession({ model: "m", apiKeyRequired: true });
    const events: AgentEvent[] = [];
    plan = ["think-only", "think-only"];
    await session.send("Arme un plugin que genere reportes en Word", ctx(events));
    expect(requests).toBe(2);
    expect(events.some((e) => e.kind === "error" && /razonó pero no devolvió respuesta/.test((e as { text: string }).text))).toBe(true);
    const stored = (session.snapshot() as { messages: Array<{ role: string }> }).messages;
    expect(stored.filter((m) => m.role === "assistant")).toHaveLength(0);

    const after: AgentEvent[] = [];
    await session.send("¿Seguís ahí?", ctx(after));
    expect(rejected).toBe(0);
    expect(after.some((e) => e.kind === "error")).toBe(false);
  });

  it("a retry that answers is just the answer", async () => {
    const session = new OpenAICompatibleSession({ model: "m", apiKeyRequired: true });
    const events: AgentEvent[] = [];
    plan = ["think-only", "answer"];
    await session.send("Hola", ctx(events));
    expect(events.some((e) => e.kind === "error")).toBe(false);
    expect(events.filter((e) => e.kind === "delta").map((e) => (e as { text: string }).text).join("")).toBe("Listo.");
  });

  it("a conversation stuck by an earlier version is repaired when loaded", async () => {
    const stuck = {
      messages: [
        { role: "system", content: "system" },
        { role: "user", content: "Arme un plugin" },
        { role: "assistant", content: null },
        { role: "tool", tool_call_id: "orphan", content: "x" },
      ],
    };
    const session = new OpenAICompatibleSession({ model: "m", apiKeyRequired: true }, stuck);
    const events: AgentEvent[] = [];
    await session.send("¿Y?", ctx(events));
    expect(rejected).toBe(0);
    expect(events.some((e) => e.kind === "error")).toBe(false);
  });

  it("sanitizing keeps calls and their results, and fills in missing call ids", () => {
    const out = sanitizeHistory([
      { role: "user", content: "a" },
      { role: "assistant", content: "", tool_calls: [{ id: "", type: "function", function: { name: "t", arguments: "{}" } }] },
      { role: "assistant", content: "" },
    ] as never);
    expect(out).toHaveLength(2);
    expect((out[1] as { tool_calls: Array<{ id: string }> }).tool_calls[0]!.id).toMatch(/^call_repaired_/);
  });
});
