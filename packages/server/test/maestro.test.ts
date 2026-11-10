import { mkdtempSync, rmSync } from "node:fs";
import { createServer, type Server } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { type Caller, type Engagement, type OperationContext, ToolRegistry, ToolRunner, Workspace } from "@penteos/core";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { HUMAN, MAESTRO } from "../src/actors.js";
import { AgentManager } from "../src/agents/manager.js";
import type { AgentEvent } from "../src/agents/types.js";

/**
 * The Maestro must not go quiet right after the operator acted: an answer or an approval counts as
 * the operator talking, even when the self-continuation budget was used up by other news.
 */

let dir: string;
let ws: Workspace;
let eng: Engagement;
let model: Server;
let turns: number;
let manager: AgentManager;
let events: AgentEvent[];
/** What the model received, one request body per turn. */
let bodies: string[];
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

const waitFor = async (check: () => boolean, ms = 15000) => {
  for (let i = 0; i < ms / 50; i++) {
    if (check()) return;
    await new Promise((r) => setTimeout(r, 50));
  }
  throw new Error("timed out");
};

beforeEach(async () => {
  dir = mkdtempSync(join(tmpdir(), "penteos-maestro-"));
  ws = new Workspace(join(dir, "data"));
  // These cases read the Maestro's Spanish status lines: the operator works in Spanish.
  ws.setLanguage(HUMAN.actor.id, "es");
  eng = ws.create({ clientName: "Lab", name: "Maestro", mode: "web" }, HUMAN.actor);
  turns = 0;
  events = [];
  bodies = [];
  // A model that answers every turn with one short sentence and no tool calls (streamed).
  model = createServer((req, res) => {
    if (req.url?.endsWith("/models")) {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ data: [{ id: "fake" }] }));
      return;
    }
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      turns++;
      bodies.push(body);
      res.writeHead(200, { "content-type": "text/event-stream" });
      const chunk = (delta: object, finish: string | null) => `data: ${JSON.stringify({ id: "x", object: "chat.completion.chunk", created: 0, model: "fake", choices: [{ index: 0, delta, finish_reason: finish }] })}\n\n`;
      res.write(chunk({ role: "assistant", content: "Listo." }, null));
      res.write(chunk({}, "stop"));
      res.end("data: [DONE]\n\n");
    });
  });
  await new Promise<void>((r) => model.listen(0, "127.0.0.1", () => r()));
  const port = (model.address() as { port: number }).port;
  manager = new AgentManager(ws, dir, (caller) => ctx(caller), MAESTRO, HUMAN, (_id, e) => void events.push(e));
  manager.configure("local", { baseUrl: `http://127.0.0.1:${port}/v1`, model: "fake" });
  manager.select("local");
});

afterEach(async () => {
  await new Promise((r) => model.close(r));
  ws.close();
  rmSync(dir, { recursive: true, force: true });
});

describe("the Maestro after the operator acts", () => {
  it("parks after too much news, and an answer from the operator wakes it up", async () => {
    await manager.send(eng.info.id, "local", "Arrancá");
    expect(turns).toBe(1);
    // Five verdicts in a row: news the Maestro picks up by itself, up to its budget, then it parks.
    for (let i = 0; i < 5; i++) {
      eng.emit({ type: "verification.done", findingId: `f${i}`, title: `Hallazgo ${i}`, verdict: "reproduced", summary: "ok" });
      await waitFor(() => turns >= Math.min(i + 2, 5));
    }
    await waitFor(() => manager.parked(eng.info.id));
    const parkedAt = turns;
    expect(events.some((e) => e.kind === "status" && /novedades sin revisar/.test(e.text))).toBe(true);

    // The operator answers a question on the board: the Maestro goes on without being asked to.
    eng.emit({ type: "task.answered", taskId: "t1", title: "Credenciales", question: "¿Cuáles uso?", answer: "admin/password", by: HUMAN.actor });
    await waitFor(() => turns > parkedAt);
    expect(manager.parked(eng.info.id)).toBe(false);
  }, 40000);

  it("in auto mode it keeps working past the interactive budget instead of parking", async () => {
    const auto = ws.create({ clientName: "Lab", name: "Auto", mode: "web", autonomy: "maestro_auto" }, HUMAN.actor);
    await manager.send(auto.info.id, "local", "Arrancá");
    // More news than the interactive budget (4): in auto it self-continues, it does not park.
    for (let i = 0; i < 6; i++) {
      auto.emit({ type: "verification.done", findingId: `a${i}`, title: `H${i}`, verdict: "reproduced", summary: "ok" });
      await waitFor(() => turns >= Math.min(i + 2, 7));
    }
    expect(turns).toBeGreaterThan(5); // past the interactive ceiling (4 + the first send)
    expect(manager.parked(auto.info.id)).toBe(false);
  }, 40000);

  it("«Que siga» resumes a parked Maestro", async () => {
    await manager.send(eng.info.id, "local", "Arrancá");
    for (let i = 0; i < 5; i++) {
      eng.emit({ type: "verification.done", findingId: `f${i}`, title: `Hallazgo ${i}`, verdict: "reproduced", summary: "ok" });
      await waitFor(() => turns >= Math.min(i + 2, 5));
    }
    await waitFor(() => manager.parked(eng.info.id));
    const parkedAt = turns;
    manager.resume(eng.info.id);
    await waitFor(() => turns > parkedAt);
  }, 40000);
});

/** The newest message the model received in a turn. */
const lastMessage = (body: string) => JSON.stringify((JSON.parse(body) as { messages: unknown[] }).messages.at(-1));

describe("the operator's language", () => {
  it("tells the model when the operator switches language mid-conversation, once", async () => {
    await manager.send(eng.info.id, "local", "Empecemos");
    expect(bodies[0]).toContain("in Spanish");
    expect(bodies[0]).not.toContain("switched the interface");
    ws.setLanguage(HUMAN.actor.id, "en");
    await manager.send(eng.info.id, "local", "Go on");
    // OpenAI-compatible sessions keep their first system prompt: the switch travels with the message.
    expect(lastMessage(bodies[1]!)).toContain("switched the interface to English");
    await manager.send(eng.info.id, "local", "And then?");
    expect(lastMessage(bodies[2]!)).not.toContain("switched the interface");
  }, 40000);
});
