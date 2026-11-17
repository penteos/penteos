import { mkdtempSync, rmSync } from "node:fs";
import { createServer, type Server } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, expect, it } from "vitest";
import { type Caller, type Engagement, executeOperation, type LineageStep, type OperationContext, ToolRegistry, ToolRunner, Workspace } from "../src/index.js";

/**
 * How a finding was reached: from the asset discovered to the operator's approval, with the
 * agent's own words on why each step was taken, in the app and in the technical report.
 */

const HUMAN: Caller = { actor: { type: "human", id: "01JA0000000000000000000HMN" }, policy: { type: "human" } };
const AGENT: Caller = { actor: { type: "agent", id: "01JA0000000000000000000AGT" }, policy: { type: "agent", autonomy: "autonomous", maxRisk: "active" } };
let dir: string;
let ws: Workspace;
let eng: Engagement;
let runner: ToolRunner;
let server: Server;
let origin: string;
const ctx = (caller: Caller): OperationContext => ({ workspace: ws, caller, defaultEngagementId: eng.info.id, engagement: () => eng, runner: () => runner }) as unknown as OperationContext;

beforeEach(async () => {
  dir = mkdtempSync(join(tmpdir(), "penteos-lineage-"));
  ws = new Workspace(join(dir, "data"));
  eng = ws.create({ clientName: "Cliente", name: "Web", mode: "web", language: "es" }, HUMAN.actor);
  server = createServer((req, res) => {
    res.writeHead(200, { "content-type": "application/json" });
    res.end(req.url === "/api/users/8" ? '{"id":8,"email":"otra.persona@cliente.test","role":"admin"}' : "{}");
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", () => r()));
  const port = (server.address() as { port: number }).port;
  origin = `http://127.0.0.1:${port}`;
  eng.addScopeRule({ effect: "include", target: { type: "ip", value: "127.0.0.1" }, ports: String(port) }, HUMAN.actor);
  runner = new ToolRunner(eng, new ToolRegistry(join(dir, "tools")));
  eng.ingest({ format: "penteos.ingest/v0", source: { parser: "webjs", tool: "webjs" }, rawIds: [], observedAt: new Date().toISOString(), items: [{ op: "upsert", kind: "endpoint", key: { origin, path: "/api/users/{id}" }, confidence: 1 }] } as never, AGENT.actor);
});
afterEach(async () => {
  await new Promise((r) => server.close(r));
  ws.close();
  rmSync(dir, { recursive: true, force: true });
});

it("tells the chain from the asset to the approval, with why each step was taken", async () => {
  const endpoint = eng.query({ kind: "endpoint" })[0]!;
  // The agent tests it, saying why; the response proves it; the finding is written; the operator approves.
  const sent = (await executeOperation("http.send", { origin, raw: "GET /api/users/8 HTTP/1.1\n\n", intent: "check whether /api/users/{id} returns other users' records" }, ctx(AGENT))) as { rawId: string };
  const ev = (await executeOperation("evidence.from_raw", { rawId: sent.rawId, caption: "Usuario 8 visible con la sesión del usuario 7", quotes: ['"role":"admin"'] }, ctx(AGENT))) as { id: string };
  const f = (await executeOperation("finding.create", { title: "IDOR en /api/users/{id}", severity: "high", instances: [{ entityId: endpoint.id }], evidenceIds: [ev.id], intent: "record the IDOR with its proof" }, ctx(AGENT))) as { id: string };
  await executeOperation("finding.set_status", { id: f.id, status: "approved" }, ctx(HUMAN));

  const { steps } = (await executeOperation("finding.lineage", { id: f.id }, ctx(HUMAN))) as { steps: LineageStep[] };
  expect(steps.map((s) => s.kind)).toEqual(["discovered", "action", "proof", "finding", "approved"]);
  expect(steps[0]!.title).toContain("/api/users/{id}");
  expect(steps[1]).toMatchObject({ title: "http.send", why: "check whether /api/users/{id} returns other users' records", by: "agent" });
  expect(steps[2]).toMatchObject({ kind: "proof", quotes: 1, why: "check whether /api/users/{id} returns other users' records" });
  expect(steps[3]).toMatchObject({ kind: "finding", why: "record the IDOR with its proof" });

  // The technical report tells it too, in the project's language.
  const md = ((await executeOperation("report.render", {}, ctx(HUMAN))) as { markdown: string }).markdown;
  expect(md).toContain("**Cómo se llegó**");
  expect(md).toMatch(/· Descubierto: endpoint .*\/api\/users\/\{id\}/);
  expect(md).toMatch(/· Prueba: http\.send · «check whether \/api\/users\/\{id\} returns other users' records»/);
  expect(md).toMatch(/· Evidencia: Usuario 8 visible/);
});

it("works for a finding written by hand, with nothing but the finding", async () => {
  const f = (await executeOperation("finding.create", { title: "Visto a mano", severity: "low" }, ctx(HUMAN))) as { id: string };
  const { steps } = (await executeOperation("finding.lineage", { id: f.id }, ctx(HUMAN))) as { steps: LineageStep[] };
  expect(steps.map((s) => s.kind)).toEqual(["finding"]);
  await expect(executeOperation("finding.lineage", { id: "01NOTAFINDING00000000000000" }, ctx(HUMAN))).rejects.toMatchObject({ code: "NOT_FOUND" });
});
