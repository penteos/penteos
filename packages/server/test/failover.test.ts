import { mkdtempSync, rmSync } from "node:fs";
import { createServer, type Server } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { type Caller, type Engagement, type OperationContext, ToolRegistry, ToolRunner, Workspace } from "@penteos/core";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { HUMAN, MAESTRO } from "../src/actors.js";
import { classifyFailure, Cooldowns, handOver, ProviderFailure, timing, WAIT_STEPS_MS } from "../src/agents/failover.js";
import { AgentManager } from "../src/agents/manager.js";
import type { AgentEvent } from "../src/agents/types.js";

/**
 * When the Maestro's AI stops answering (out of credit, a dead key, a provider down), the round
 * goes on with the next AI the operator configured, which gets the round handed over; when none is
 * left it stops in order, with one clear message and the AI shown as unavailable.
 */

describe("why the AI stopped", () => {
  it("tells apart what another AI can carry on from", () => {
    expect(classifyFailure({ status: 402, message: "402 Insufficient Balance" })).toBe("quota");
    expect(classifyFailure({ status: 429, error: { code: "insufficient_quota", message: "You exceeded your current quota" } })).toBe("quota");
    expect(classifyFailure({ status: 429, message: "Rate limit reached for requests" })).toBe("rate");
    expect(classifyFailure({ status: 401, message: "Incorrect API key provided" })).toBe("auth");
    expect(classifyFailure({ status: 529, message: "Overloaded" })).toBe("down");
    expect(classifyFailure(Object.assign(new Error("Connection error."), { cause: { code: "ECONNREFUSED" } }))).toBe("down");
    expect(classifyFailure(new ProviderFailure("quota", "usage limit"))).toBe("quota");
    // Another model would not fix these.
    expect(classifyFailure({ status: 400, message: "Invalid assistant message" })).toBeUndefined();
    expect(classifyFailure({ status: 400, message: "This model's maximum context length is 8192 tokens" })).toBeUndefined();
  });

  it("rests a provider 1, 5 then 30 minutes for an outage, 30 for credit", () => {
    let now = 0;
    const c = new Cooldowns(() => now);
    expect(c.mark("deepseek", "down", "503").until).toBe(60_000);
    now = 61_000;
    expect(c.active("deepseek")).toBeUndefined();
    expect(c.mark("deepseek", "down", "503").until).toBe(61_000 + 300_000);
    expect(c.mark("openai-api", "quota", "402").until - now).toBe(1_800_000);
    c.clear("openai-api");
    expect(c.active("openai-api")).toBeUndefined();
  });

  it("hands the round over with what was asked and done", () => {
    const text = handOver(
      [
        { kind: "user", text: "Test the login of https://app.client.test", at: "" },
        { kind: "text", text: "Starting with the login form." },
        { kind: "tool", id: "1", name: "http_send", input: {}, status: "ok", summary: "POST /login → 401" },
      ],
      "DeepSeek",
      "Continue with the password reset.",
    );
    expect(text).toContain("taking this round over from DeepSeek");
    expect(text).toContain("OPERATOR: Test the login");
    expect(text).toContain("TOOL http_send: POST /login → 401");
    expect(text).toContain("engagement.brief");
    expect(text).toContain("Continue with the password reset.");
  });
});

// Two OpenAI-compatible servers: one out of credit (as DeepSeek says it), one that works.
let dir: string;
let ws: Workspace;
let eng: Engagement;
let broke: Server;
let good: Server;
let brokeHits = 0;
let goodBodies: string[] = [];
let manager: AgentManager;
let events: AgentEvent[];
const runners = new Map<string, ToolRunner>();

const ctx = (caller: Caller): OperationContext => ({
  workspace: ws,
  caller,
  defaultEngagementId: eng.info.id,
  engagement: () => eng,
  runner: (id) => {
    const key = id ?? eng.info.id;
    if (!runners.has(key)) runners.set(key, new ToolRunner(eng, new ToolRegistry(join(dir, "tools"))));
    return runners.get(key)!;
  },
});

const listen = (s: Server) => new Promise<number>((r) => s.listen(0, "127.0.0.1", () => r((s.address() as { port: number }).port)));

beforeEach(async () => {
  dir = mkdtempSync(join(tmpdir(), "penteos-failover-"));
  ws = new Workspace(join(dir, "data"));
  ws.setLanguage(HUMAN.actor.id, "es");
  eng = ws.create({ clientName: "Lab", name: "Failover", mode: "web" }, HUMAN.actor);
  brokeHits = 0;
  goodBodies = [];
  events = [];
  broke = createServer((req, res) => {
    req.resume();
    req.on("end", () => {
      brokeHits++;
      res.writeHead(402, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: { message: "Insufficient Balance", type: "unknown_error" } }));
    });
  });
  good = createServer((req, res) => {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      goodBodies.push(body);
      res.writeHead(200, { "content-type": "text/event-stream" });
      const chunk = (delta: object, finish: string | null) => `data: ${JSON.stringify({ id: "x", object: "chat.completion.chunk", created: 0, model: "m", choices: [{ index: 0, delta, finish_reason: finish }] })}\n\n`;
      res.write(chunk({ role: "assistant", content: "Sigo yo." }, null));
      res.write(chunk({}, "stop"));
      res.end("data: [DONE]\n\n");
    });
  });
  const [b, g] = [await listen(broke), await listen(good)];
  manager = new AgentManager(ws, dir, (caller) => ctx(caller), MAESTRO, HUMAN, (_id, e) => void events.push(e));
  manager.configure("deepseek", { apiKey: "k", baseUrl: `http://127.0.0.1:${b}/v1`, model: "m" });
  manager.select("deepseek");
  // Only for the case with a second AI.
  (manager as unknown as { goodPort: number }).goodPort = g;
});

afterEach(async () => {
  await new Promise((r) => broke.close(r));
  await new Promise((r) => good.close(r));
  ws.close();
  rmSync(dir, { recursive: true, force: true });
});

const statuses = () => events.filter((e) => e.kind === "status" || e.kind === "error").map((e) => (e as { text: string }).text);

describe("the round goes on, or stops in order", () => {
  it("out of credit: the next AI takes the round over, with the hand-over", async () => {
    manager.configure("openai-api", { apiKey: "k", baseUrl: `http://127.0.0.1:${(manager as unknown as { goodPort: number }).goodPort}/v1`, model: "m" });
    await manager.send(eng.info.id, "deepseek", "Probá el login de la app");
    expect(brokeHits).toBe(1);
    expect(statuses().some((t) => /DeepSeek se quedó sin saldo o sin cuota .* El Maestro sigue con OpenAI API/.test(t))).toBe(true);
    expect(goodBodies).toHaveLength(1);
    expect(goodBodies[0]).toContain("[Penteos - hand-over]");
    expect(goodBodies[0]).toContain("Probá el login de la app");
    expect(events.at(-1)).toMatchObject({ kind: "done", provider: "openai-api" });
    expect(events.some((e) => e.kind === "error")).toBe(false);
    // DeepSeek reads as unavailable, with the reason: the panel offers another AI.
    const deepseek = (await manager.providers(eng.info.id)).providers.find((p) => p.id === "deepseek")!;
    expect(deepseek.available).toBe(false);
    expect(deepseek.reason).toMatch(/Sin saldo o sin cuota/);
    // The next message, still addressed to DeepSeek, goes to the AI that works.
    await manager.send(eng.info.id, "deepseek", "Seguí con el reset de contraseña");
    expect(brokeHits).toBe(1);
    expect(goodBodies).toHaveLength(2);
    expect(statuses().some((t) => /DeepSeek sigue en pausa hasta las .*: el Maestro usa OpenAI API/.test(t))).toBe(true);
  });

  it("no AI left: the round stops with one clear message, and does not loop", async () => {
    await manager.send(eng.info.id, "deepseek", "Probá el login de la app");
    expect(brokeHits).toBe(1);
    const errors = events.filter((e) => e.kind === "error").map((e) => (e as { text: string }).text);
    expect(errors).toHaveLength(1);
    expect(errors[0]).toMatch(/La ronda quedó en pausa: DeepSeek se quedó sin saldo .* no hay otra IA disponible\. Recargue saldo o conecte otra IA/);
    // Nothing goes on by itself: no news turn after a stop.
    await new Promise((r) => setTimeout(r, 900));
    expect(brokeHits).toBe(1);
    // The operator writes again (they may have topped up): it is tried again at once.
    await manager.send(eng.info.id, "deepseek", "continuar");
    expect(brokeHits).toBe(2);
  });

  it("new settings for the AI (a new key) end its rest", async () => {
    await manager.send(eng.info.id, "deepseek", "Probá el login");
    expect((await manager.providers(eng.info.id)).providers.find((p) => p.id === "deepseek")!.available).toBe(false);
    manager.configure("deepseek", { apiKey: "k2" });
    expect((await manager.providers(eng.info.id, true)).providers.find((p) => p.id === "deepseek")!.available).toBe(true);
  });
});

describe("a dropped connection never stops the round", () => {
  let flaky: Server;
  let drops = 0;
  let served = 0;
  beforeEach(async () => {
    timing.cutDelayMs = 5;
    WAIT_STEPS_MS.splice(0, WAIT_STEPS_MS.length, 40);
    served = 0;
    flaky = createServer((req, res) => {
      if (req.url?.endsWith("/models")) return void res.writeHead(200, { "content-type": "application/json" }).end('{"data":[{"id":"m"}]}');
      req.resume();
      req.on("end", () => {
        served++;
        res.writeHead(200, { "content-type": "text/event-stream" });
        const chunk = (delta: object, finish: string | null) => `data: ${JSON.stringify({ id: "x", object: "chat.completion.chunk", created: 0, model: "m", choices: [{ index: 0, delta, finish_reason: finish }] })}\n\n`;
        res.write(chunk({ role: "assistant", content: "Recon base listo. " }, null));
        // The first answers are cut in the middle, as DeepSeek does now and then ("terminated").
        if (drops > 0) {
          drops--;
          // After the first part has reached the client: a drop in the middle of the answer.
          return void setTimeout(() => res.socket?.destroy(), 30);
        }
        res.write(chunk({ content: "Sigo con el mapeo." }, null));
        res.write(chunk({}, "stop"));
        res.end("data: [DONE]\n\n");
      });
    });
    const port = await listen(flaky);
    manager.configure("deepseek", { apiKey: "k", baseUrl: `http://127.0.0.1:${port}/v1`, model: "m" });
  });
  afterEach(async () => {
    timing.cutDelayMs = 1500;
    WAIT_STEPS_MS.splice(0, WAIT_STEPS_MS.length, 10_000, 20_000, 40_000, 60_000, 120_000, 180_000, 300_000);
    await new Promise((r) => flaky.close(r));
  });

  it("an answer cut in the middle is asked again at once", async () => {
    drops = 1;
    await manager.send(eng.info.id, "deepseek", "Hacé el recon");
    expect(served).toBe(2);
    expect(statuses().some((t) => /Se cortó la conexión con la IA en medio de la respuesta: se vuelve a pedir \(1 de 3\)/.test(t))).toBe(true);
    expect(events.some((e) => e.kind === "error")).toBe(false);
  });

  it("with no other AI, a provider that keeps dropping is waited for, and the round goes on", async () => {
    drops = 6; // more than the quick retries: the failover waits, then it answers
    await manager.send(eng.info.id, "deepseek", "Hacé el recon");
    expect(events.some((e) => e.kind === "error")).toBe(false);
    expect(statuses().some((t) => /DeepSeek no responde .*La ronda sigue sola: se vuelve a intentar a las/.test(t))).toBe(true);
    expect(statuses().some((t) => /DeepSeek vuelve a responder: el Maestro sigue donde estaba/.test(t))).toBe(true);
    expect(statuses().some((t) => /quedó en pausa/.test(t))).toBe(false);
    expect(events.at(-1)).toMatchObject({ kind: "done", provider: "deepseek" });
  });
});

