import { mkdtempSync, rmSync } from "node:fs";
import { createServer, type Server } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { type Caller, type Engagement, executeOperation, type OperationContext, ToolRegistry, ToolRunner, Workspace } from "@penteos/core";
import { Actor } from "@penteos/schema";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { HUMAN, MAESTRO } from "../src/actors.js";
import { SubAgent } from "../src/agents/subagent.js";
import { runTool } from "../src/agents/tools.js";
import type { ProviderSession, TurnContext } from "../src/agents/types.js";
import { VERIFIER, Verifier, type VerifierProvider } from "../src/agents/verifier.js";

let dir: string;
let ws: Workspace;
let eng: Engagement;
let server: Server;
let origin: string;
let verifier: Verifier;
let provider: VerifierProvider;
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
  verifier: { request: (...a) => verifier.request(...a) },
});

/** A provider that plays a script instead of calling a model. */
class Scripted implements ProviderSession {
  denied?: string;
  constructor(private readonly script: (ctx: TurnContext, call: (tool: string, input: unknown) => Promise<{ ok: boolean; content: string }>) => Promise<void>) {}
  snapshot() {
    return {};
  }
  async send(_text: string, c: TurnContext): Promise<void> {
    await this.script(c, async (tool, input) => {
      c.emit({ kind: "tool", id: tool, name: tool, input, status: "running" });
      const r = await runTool(`penteos_${tool}`, input, c.ops, c.allow);
      c.emit({ kind: "tool", id: tool, name: tool, input, status: r.ok ? "ok" : "error", summary: r.summary });
      return r;
    });
  }
}

const waitFor = async (check: () => boolean) => {
  for (let i = 0; i < 200; i++) {
    if (check()) return;
    await new Promise((r) => setTimeout(r, 25));
  }
  throw new Error("timed out");
};

beforeEach(async () => {
  dir = mkdtempSync(join(tmpdir(), "penteos-verifier-"));
  ws = new Workspace(join(dir, "data"));
  eng = ws.create({ language: "es", clientName: "Lab", name: "Verifier", mode: "web" }, HUMAN.actor);
  server = createServer((req, res) => {
    res.writeHead(req.url === "/admin" ? 200 : 404, { "Content-Type": "text/html" });
    res.end(req.url === "/admin" ? "<h1>Panel de administración</h1>" : "no");
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", () => r()));
  const port = (server.address() as { port: number }).port;
  origin = `http://127.0.0.1:${port}`;
  eng.addScopeRule({ effect: "include", target: { type: "ip", value: "127.0.0.1" }, ports: String(port) }, HUMAN.actor);
  runners.clear();
  verifier = new Verifier(ws, dir, (caller) => ctx(caller), () => provider, () => {});
});

afterEach(async () => {
  verifier.stopAll();
  await new Promise((r) => server.close(r));
  ws.close();
  rmSync(dir, { recursive: true, force: true });
});

async function finding(): Promise<string> {
  const f = (await executeOperation("finding.create", { title: "Panel de administración sin autenticación", severity: "high", description: `${origin}/admin responde sin sesión.` }, ctx(MAESTRO))) as { id: string };
  return f.id;
}

const verification = (id: string) => eng.get(id)!.attributes.verification as { state: string; verdict?: string; summary?: string; by?: { id: string }; evidenceIds: string[] } | undefined;

describe("independent verifier", () => {
  it("is a valid actor, distinct from the Maestro", () => {
    expect(Actor.safeParse(VERIFIER.actor).success).toBe(true);
    expect(VERIFIER.actor.id).not.toBe(MAESTRO.actor.id);
  });

  it("starts when a finding goes to review, reproduces it and records a verdict with evidence", async () => {
    let forbidden = "";
    const session = new Scripted(async (_c, call) => {
      forbidden = (await call("finding_update", { id: "x", title: "y" })).content;
      const sent = JSON.parse((await call("http_send", { origin, raw: "GET /admin HTTP/1.1\n\n", risk: "active" })).content) as { rawId: string; response: { status: number } };
      expect(sent.response.status).toBe(200);
      const ev = JSON.parse((await call("evidence_from_raw", { rawId: sent.rawId, caption: "GET /admin sin cookie → 200" })).content) as { id: string };
      const id = (eng.query({ kind: "finding" })[0]!).id;
      const r = await call("finding_verdict", { id, verdict: "reproduced", summary: "Sin cookie, /admin devuelve 200 con el panel.", evidenceIds: [ev.id] });
      expect(r.ok).toBe(true);
    });
    provider = { id: "claude-api", label: "Claude API", settings: {}, create: () => session };
    const id = await finding();
    await executeOperation("finding.set_status", { id, status: "in_review" }, ctx(MAESTRO));
    await waitFor(() => verification(id)?.state === "done");
    expect(verification(id)).toMatchObject({ state: "done", verdict: "reproduced", by: { id: VERIFIER.actor.id } });
    expect(verification(id)!.evidenceIds).toHaveLength(1);
    expect(forbidden).toMatch(/PERMISSION_DENIED/);
    expect(SubAgent.transcript(ws, eng.info.id, Verifier.key(id)).some((e) => e.kind === "tool")).toBe(true);
  });

  it("only the assigned verifier records a verdict (not the Maestro); a human can", async () => {
    const id = await finding();
    await expect(executeOperation("finding.verdict", { id, verdict: "reproduced", summary: "confiá" }, ctx(MAESTRO))).rejects.toMatchObject({ code: "PERMISSION_DENIED" });
    await executeOperation("finding.verdict", { id, verdict: "not_reproduced", summary: "Probé a mano: pide login." }, ctx(HUMAN));
    expect(verification(id)).toMatchObject({ state: "done", verdict: "not_reproduced" });
  });

  it("without an API provider: a manual request says why, going to review stays quiet", async () => {
    provider = { reason: "El verificador necesita un proveedor por API" };
    const id = await finding();
    await expect(executeOperation("finding.request_verification", { id }, ctx(HUMAN))).rejects.toThrow(/proveedor por API/);
    await executeOperation("finding.set_status", { id, status: "in_review" }, ctx(MAESTRO));
    expect(verification(id)).toBeUndefined();
  });

  it("a verifier that ends without a verdict leaves the reason", async () => {
    provider = { id: "claude-api", label: "Claude API", settings: {}, create: () => new Scripted(async () => {}) };
    const id = await finding();
    await executeOperation("finding.request_verification", { id }, ctx(HUMAN));
    await waitFor(() => verification(id)?.state === "failed");
    expect(verification(id)!.summary).toMatch(/sin emitir un veredicto/);
  });
});
