import { mkdtempSync, rmSync } from "node:fs";
import { createServer, type Server } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { type Caller, type Engagement, executeOperation, leadFor, type OperationContext, ToolRegistry, ToolRunner, Workspace } from "../src/index.js";

/**
 * A round does not close early: surface found outside the scope gets a decision, a server error is
 * a lead to look at, and both keep the round open until they are dealt with. What a real round
 * showed: QA, automation and payments hosts silently untested, a 530 marked "not applicable", a 504
 * abandoned - and the round over in 37 minutes.
 */
const HUMAN: Caller = { actor: { type: "human", id: "01JA0000000000000000000HMN" }, policy: { type: "human" } };
const MAESTRO: Caller = { actor: { type: "agent", id: "01JA000000000000000000MSTR" }, policy: { type: "agent", autonomy: "autonomous", maxRisk: "intrusive" } };
let dir: string;
let ws: Workspace;
let eng: Engagement;
let runner: ToolRunner;
let server: Server;
let origin: string;
const ctx = (caller: Caller): OperationContext => ({ workspace: ws, caller, defaultEngagementId: eng.info.id, engagement: () => eng, runner: () => runner }) as unknown as OperationContext;
const paths = [
  { title: "Probar el panel", why: "x", needs: "nothing" },
  { title: "Probar la API", why: "y", needs: "nothing" },
];
const close = () => executeOperation("plan.propose_paths", { status: "Fin de la ronda.", paths }, ctx(MAESTRO));

beforeEach(async () => {
  dir = mkdtempSync(join(tmpdir(), "penteos-depth2-"));
  ws = new Workspace(join(dir, "data"));
  eng = ws.create({ language: "es", clientName: "Cliente", name: "Web", mode: "web" }, HUMAN.actor);
  server = createServer((req, res) => {
    req.resume();
    req.on("end", () => {
      if (req.url?.startsWith("/api/onboarding/")) {
        res.writeHead(504);
        res.end("gateway timeout");
        return;
      }
      res.writeHead(200, { "Content-Type": "text/plain" });
      res.end("ok");
    });
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", () => r()));
  const port = (server.address() as { port: number }).port;
  origin = `http://127.0.0.1:${port}`;
  eng.addScopeRule({ effect: "include", target: { type: "url", value: "https://app.cliente.test" } }, HUMAN.actor);
  eng.addScopeRule({ effect: "include", target: { type: "ip", value: "127.0.0.1" }, ports: String(port) }, HUMAN.actor);
  runner = new ToolRunner(eng, new ToolRegistry(join(dir, "tools")));
  // Reconnaissance found these, outside the scope: two of the client's, one third party.
  eng.ingest({ format: "penteos.ingest/v0", source: { parser: "test", tool: "subfinder" }, rawIds: [], observedAt: new Date().toISOString(), items: [
    { op: "upsert", kind: "domain", key: { fqdn: "automation.cliente.test" }, confidence: 1 },
    { op: "upsert", kind: "webapp", key: { origin: "https://pagos-qa.cliente.test" }, attributes: { title: "Pagos QA" }, confidence: 1 },
    { op: "upsert", kind: "domain", key: { fqdn: "api.tercero.example" }, confidence: 1 },
  ] } as never, HUMAN.actor);
});
afterEach(async () => {
  await new Promise((r) => server.close(r));
  ws.close();
  rmSync(dir, { recursive: true, force: true });
});

describe("surface found outside the scope", () => {
  it("only the client's own names, and the round does not close while they are undecided", async () => {
    const s = (await executeOperation("surface.list", {}, ctx(MAESTRO))) as { undecided: Array<{ host: string; title?: string }> };
    expect(s.undecided.map((x) => x.host)).toEqual(["automation.cliente.test", "pagos-qa.cliente.test"]);
    expect(s.undecided[1]!.title).toBe("Pagos QA");
    await expect(close()).rejects.toMatchObject({ message: expect.stringMatching(/automation\.cliente\.test.*surface_decide/s) });
  });

  it("is decided in one call: proposals the operator approves, or set aside with the reason", async () => {
    const r = (await executeOperation("surface.decide", { hosts: ["https://pagos-qa.cliente.test", "automation.cliente.test"], decision: "propose", reason: "Entorno QA y automatización expuestos" }, ctx(MAESTRO))) as { approvals: string[] };
    expect(r.approvals).toHaveLength(2);
    const cards = runner.listApprovals().filter((a) => a.request.kind === "scope");
    expect(cards.map((c) => c.reason).join(" ")).toMatch(/Entorno QA.*Pagos QA/);
    expect((await executeOperation("surface.list", {}, ctx(MAESTRO))) as { undecided: unknown[] }).toMatchObject({ undecided: [] });
    await expect(executeOperation("surface.decide", { hosts: ["api.tercero.example"], decision: "set_aside", reason: "x y z" }, ctx(MAESTRO))).rejects.toMatchObject({ code: "NOT_FOUND" });
    await expect(close()).resolves.toMatchObject({ status: "shown" });
  });
});

describe("leads", () => {
  it("a server error becomes a lead, and a CDN without origin a possible takeover", () => {
    expect(leadFor(504, "GET /x")?.sourceRule).toBe("lead:server-error");
    expect(leadFor(530, "admin.cliente.test")?.title).toMatch(/dangling record/);
    expect(leadFor(501, "x")).toBeUndefined();
    expect(leadFor(404, "x")).toBeUndefined();
  });

  it("a 504 met while testing keeps the round open until someone looks at it", async () => {
    await executeOperation("surface.decide", { hosts: ["automation.cliente.test", "pagos-qa.cliente.test"], decision: "set_aside", reason: "fuera del acuerdo con el cliente" }, ctx(MAESTRO));
    await executeOperation("http.send", { origin, raw: "GET /api/onboarding/%2e%2e%2finternal HTTP/1.1" }, ctx(MAESTRO));
    const lead = eng.query({ kind: "observation", limit: 50 }).find((o) => o.attributes.sourceRule === "lead:server-error")!;
    expect(lead.attributes.title).toMatch(/504/);
    await expect(close()).rejects.toMatchObject({ message: expect.stringMatching(/Server error/) });
    await executeOperation("observation.triage", { ids: [lead.id], triage: "false_positive", reason: "variado: timeout del proveedor, sin acceso a rutas internas" }, ctx(MAESTRO));
    await expect(close()).resolves.toMatchObject({ status: "shown" });
  });
});
