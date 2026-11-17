import { createServer, type Server } from "node:http";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { anthropicAdapter, chatAdapter, estimateTokens, isContextOverflow, keepWithinBudget, MEMORY_HEADER, responsesAdapter, TRIM_NOTE, type MemoryAdapter } from "../src/agents/memory.js";
import { OpenAICompatibleSession, sanitizeHistory } from "../src/agents/providers/openai-compatible.js";
import type { AgentEvent } from "../src/agents/types.js";

/**
 * A long round must not outgrow the model's memory: the conversation stays within its budget, stays
 * valid for each API (a call is never parted from its result), and what it forgets is summed up
 * with the ids intact. Measured on conversations of hundreds of steps in the three formats.
 */

const big = (n: number, tag: string) => `${tag} ` + "x".repeat(n);

type Chat = { role: string; content?: unknown; tool_calls?: Array<{ id: string; type: "function"; function: { name: string; arguments: string } }>; tool_call_id?: string };

function chatRound(steps: number, resultSize = 5000): Chat[] {
  const ms: Chat[] = [{ role: "system", content: "You are the Maestro." }, { role: "user", content: "Assess http://lab.test. Never touch /admin/delete." }];
  for (let i = 0; i < steps; i++) {
    ms.push({ role: "assistant", content: i % 5 === 0 ? `Step ${i}: probing.` : null, tool_calls: [{ id: `c${i}`, type: "function", function: { name: "penteos_http_send", arguments: JSON.stringify({ url: `http://lab.test/api/item/${i}` }) } }] });
    ms.push({ role: "tool", tool_call_id: `c${i}`, content: big(resultSize, i === 3 ? "finding 01FINDINGSQLI created" : `result ${i}`) });
  }
  return ms;
}

const memo = "1. Operator instructions: never touch /admin/delete.\n4. Findings: 01FINDINGSQLI SQL injection (critical).\n5. Open leads: /api/item/{id} IDOR.";

describe("the conversation stays within its budget", () => {
  it("cuts old results first, without calling the model, when that is enough", async () => {
    const ms = chatRound(20, 4000);
    const a = chatAdapter as unknown as MemoryAdapter<Chat>;
    const budget = Math.ceil(estimateTokens(ms, a) / 0.7);
    let calls = 0;
    const out = await keepWithinBudget(ms, a, budget, async () => (calls++, memo));
    expect(calls).toBe(0);
    expect(out?.summarized).toBe(false);
    expect(out?.trimmed).toBe(4); // the 16 most recent results stay whole
    expect(String(ms[3]!.content)).toContain(TRIM_NOTE);
    expect(String(ms.at(-1)!.content).length).toBeGreaterThan(4000);
    expect(sanitizeHistory(ms as never).length).toBe(ms.length);
  });

  it("sums up the older part of a 300-step round, keeps it valid and keeps the ids", async () => {
    const ms = chatRound(300);
    const a = chatAdapter as unknown as MemoryAdapter<Chat>;
    const budget = 20_000;
    let transcript = "";
    const out = await keepWithinBudget(ms, a, budget, async (_s, t) => ((transcript = t), memo));
    expect(out?.summarized).toBe(true);
    expect(estimateTokens(ms, a)).toBeLessThanOrEqual(budget * 0.85);
    // The operator's instruction and the finding id were in what the model summed up.
    expect(transcript).toContain("Never touch /admin/delete");
    expect(transcript).toContain("01FINDINGSQLI");
    expect(ms[0]!.role).toBe("system");
    expect(ms[1]!.role).toBe("user");
    expect(String(ms[1]!.content)).toContain(MEMORY_HEADER);
    expect(String(ms[1]!.content)).toContain("01FINDINGSQLI");
    // Valid for the API: nothing for sanitizeHistory to drop, every result answers a call before it.
    expect(sanitizeHistory(ms as never).length).toBe(ms.length);
    const called = new Set<string>();
    for (const m of ms) {
      for (const c of m.tool_calls ?? []) called.add(c.id);
      if (m.role === "tool") expect(called.has(m.tool_call_id!)).toBe(true);
    }
  });

  it("a second compaction carries the first memory forward", async () => {
    const ms = chatRound(300);
    const a = chatAdapter as unknown as MemoryAdapter<Chat>;
    await keepWithinBudget(ms, a, 20_000, async () => memo);
    for (let i = 300; i < 600; i++) {
      ms.push({ role: "assistant", content: null, tool_calls: [{ id: `c${i}`, type: "function", function: { name: "penteos_http_send", arguments: "{}" } }] });
      ms.push({ role: "tool", tool_call_id: `c${i}`, content: big(5000, `result ${i}`) });
    }
    let transcript = "";
    await keepWithinBudget(ms, a, 20_000, async (_s, t) => ((transcript = t), "second memory, still with 01FINDINGSQLI"));
    expect(transcript).toContain(MEMORY_HEADER);
    expect(transcript).toContain("01FINDINGSQLI");
    expect(ms.filter((m) => String(m.content ?? "").startsWith(MEMORY_HEADER))).toHaveLength(1);
  });

  it("a summary that fails never stops the round: the older part goes, with a way back", async () => {
    const ms = chatRound(300);
    const a = chatAdapter as unknown as MemoryAdapter<Chat>;
    const out = await keepWithinBudget(ms, a, 20_000, async () => {
      throw new Error("429");
    });
    expect(out?.summaryFailed).toBe(true);
    expect(String(ms[1]!.content)).toContain("engagement.brief");
    expect(estimateTokens(ms, a)).toBeLessThanOrEqual(20_000);
    expect(sanitizeHistory(ms as never).length).toBe(ms.length);
  });

  it("stopped by the operator during the summary, the history is not cut", async () => {
    const ms = chatRound(300);
    const a = chatAdapter as unknown as MemoryAdapter<Chat>;
    const controller = new AbortController();
    const before = ms.length;
    await keepWithinBudget(
      ms,
      a,
      20_000,
      async () => {
        controller.abort();
        throw new Error("aborted");
      },
      { signal: controller.signal },
    );
    expect(ms.length).toBe(before);
  });

  it("Claude's format: alternating turns, every tool result right after its call", async () => {
    type M = { role: "user" | "assistant"; content: string | Array<Record<string, unknown>> };
    const ms: M[] = [{ role: "user", content: "Assess http://lab.test" }];
    for (let i = 0; i < 300; i++) {
      ms.push({ role: "assistant", content: [{ type: "thinking", thinking: "…", signature: "s" }, { type: "tool_use", id: `t${i}`, name: "penteos_http_send", input: { i } }, { type: "tool_use", id: `u${i}`, name: "penteos_entity_query", input: {} }] });
      ms.push({ role: "user", content: [{ type: "tool_result", tool_use_id: `t${i}`, content: big(4000, `r${i}`) }, { type: "tool_result", tool_use_id: `u${i}`, content: [{ type: "text", text: big(3000, `q${i}`) }] }] });
    }
    const a = anthropicAdapter as unknown as MemoryAdapter<M>;
    const out = await keepWithinBudget(ms, a, 20_000, async () => memo);
    expect(out?.summarized).toBe(true);
    expect(estimateTokens(ms, a)).toBeLessThanOrEqual(20_000);
    expect(ms[0]!.role).toBe("user");
    for (let i = 1; i < ms.length; i++) expect(ms[i]!.role).not.toBe(ms[i - 1]!.role);
    for (let i = 0; i < ms.length; i++) {
      const c = ms[i]!.content;
      if (!Array.isArray(c)) continue;
      for (const b of c.filter((x) => x.type === "tool_result")) {
        const prev = ms[i - 1]!.content as Array<Record<string, unknown>>;
        expect(prev.some((x) => x.type === "tool_use" && x.id === b.tool_use_id)).toBe(true);
      }
    }
  });

  it("the ChatGPT plan's format: no output without its call before it", async () => {
    type I = { role?: string; content?: string; type?: string; call_id?: string; name?: string; arguments?: string; output?: string };
    const ms: I[] = [{ role: "user", content: "Assess http://lab.test" }];
    for (let i = 0; i < 300; i++) {
      if (i % 3 === 0) ms.push({ role: "assistant", content: `step ${i}` });
      ms.push({ type: "function_call", call_id: `a${i}`, name: "penteos_http_send", arguments: "{}" }, { type: "function_call", call_id: `b${i}`, name: "penteos_entity_query", arguments: "{}" });
      ms.push({ type: "function_call_output", call_id: `a${i}`, output: big(4000, `r${i}`) }, { type: "function_call_output", call_id: `b${i}`, output: big(2000, `s${i}`) });
    }
    const a = responsesAdapter as unknown as MemoryAdapter<I>;
    const out = await keepWithinBudget(ms, a, 20_000, async () => memo);
    expect(out?.summarized).toBe(true);
    expect(estimateTokens(ms, a)).toBeLessThanOrEqual(20_000);
    const calls = new Set<string>();
    for (const m of ms) {
      if (m.type === "function_call") calls.add(m.call_id!);
      if (m.type === "function_call_output") expect(calls.has(m.call_id!)).toBe(true);
    }
  });

  it("recognises a context overflow in each provider's words", () => {
    expect(isContextOverflow({ status: 400, message: "This model's maximum context length is 131072 tokens. However, you requested 140000 tokens" })).toBe(true);
    expect(isContextOverflow({ status: 400, error: { message: "prompt is too long: 210000 tokens > 200000 maximum" } })).toBe(true);
    expect(isContextOverflow({ code: "context_length_exceeded", message: "Your input exceeds the context window of this model." })).toBe(true);
    expect(isContextOverflow({ status: 429, message: "Rate limit reached" })).toBe(false);
    expect(isContextOverflow(new Error("Invalid assistant message"))).toBe(false);
  });
});

// The provider end to end: a server as strict as a small model with an 8k window.
let server: Server;
let port: number;
let largest = 0;
let overflows = 0;
let summaries = 0;

beforeEach(async () => {
  largest = 0;
  overflows = 0;
  summaries = 0;
  server = createServer((req, res) => {
    let body = "";
    req.on("data", (d) => (body += String(d)));
    req.on("end", () => {
      const parsed = JSON.parse(body) as { messages: unknown[]; stream?: boolean };
      const size = JSON.stringify(parsed.messages).length;
      if (!parsed.stream) {
        summaries++;
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({ id: "s", object: "chat.completion", created: 0, model: "m", choices: [{ index: 0, message: { role: "assistant", content: memo }, finish_reason: "stop" }] }));
        return;
      }
      largest = Math.max(largest, size);
      if (size > 8000 * 3.5) {
        overflows++;
        res.writeHead(400, { "content-type": "application/json" });
        res.end(JSON.stringify({ error: { message: "This model's maximum context length is 8192 tokens." } }));
        return;
      }
      res.writeHead(200, { "content-type": "text/event-stream" });
      const chunk = (delta: object, finish: string | null) => `data: ${JSON.stringify({ id: "x", object: "chat.completion.chunk", created: 0, model: "m", choices: [{ index: 0, delta, finish_reason: finish }] })}\n\n`;
      res.write(chunk({ role: "assistant", content: "Going on." }, null));
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

const ctx = (events: AgentEvent[], memoryTokens: number) =>
  ({
    system: "system",
    ops: { engagement: () => { throw new Error("none"); } },
    caller: {},
    settings: { baseUrl: `http://127.0.0.1:${port}/v1`, apiKey: "k", model: "m" },
    workDir: "/tmp",
    dataDir: "/tmp",
    emit: (e: AgentEvent) => events.push(e),
    signal: new AbortController().signal,
    lang: "en",
    memoryTokens,
  }) as never;

describe("the Maestro keeps working past its window", () => {
  it("compacts before sending, and says so in one line", async () => {
    const session = new OpenAICompatibleSession({ model: "m", apiKeyRequired: true }, { messages: chatRound(120, 3000) });
    const events: AgentEvent[] = [];
    await session.send("Go on.", ctx(events, 6000));
    expect(overflows).toBe(0);
    expect(summaries).toBe(1);
    expect(largest).toBeLessThanOrEqual(6000 * 3.5);
    expect(events.some((e) => e.kind === "status" && /memory was summed up/.test(e.text))).toBe(true);
    expect(events.some((e) => e.kind === "error")).toBe(false);
  });

  it("a window smaller than the budget: compacts on the overflow and tries again once", async () => {
    const session = new OpenAICompatibleSession({ model: "m", apiKeyRequired: true }, { messages: chatRound(40, 600) });
    const events: AgentEvent[] = [];
    // The budget believes in 120k tokens; the server holds 8k.
    await session.send("Go on.", ctx(events, 120_000));
    expect(overflows).toBe(1);
    expect(events.some((e) => e.kind === "error")).toBe(false);
    expect(events.some((e) => e.kind === "text" || e.kind === "delta")).toBe(true);
  });
});
