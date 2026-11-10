import { mkdtempSync, rmSync } from "node:fs";
import { createServer, type Server } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Actor } from "@penteos/schema";
import { afterEach, beforeEach, expect, it } from "vitest";
import { type Engagement, executeOperation, exposedIn, findingsToDeepen, type OperationContext, renderReport, ToolRegistry, ToolRunner, Workspace } from "../src/index.js";

/**
 * Deepening a finding: serious ones open the impact questions (reach, exposed, chain), a round does
 * not close with them open, and the reach is measured against the target instead of assumed.
 */

const agent: Actor = { type: "agent", id: "01JA000000000000000000MSTR" };
const human: Actor = { type: "human", id: "01JA00000000000000000000H1" };
let dir: string;
let ws: Workspace;
let eng: Engagement;
let runner: ToolRunner;
let server: Server;
let origin: string;

beforeEach(async () => {
  dir = mkdtempSync(join(tmpdir(), "penteos-impact-"));
  ws = new Workspace(join(dir, "data"));
  eng = ws.create({ language: "es", clientName: "Lab", name: "Impact", mode: "web" }, human);
  runner = new ToolRunner(eng, new ToolRegistry(join(dir, "tools")));
});

afterEach(async () => {
  if (server) await new Promise((r) => server.close(r));
  ws.close();
  rmSync(dir, { recursive: true, force: true });
});

const ctx = (actor: Actor = agent): OperationContext =>
  ({
    workspace: ws,
    caller: { actor, policy: { type: "agent", autonomy: "autonomous", maxRisk: "active" } },
    defaultEngagementId: eng.info.id,
    engagement: () => eng,
    runner: () => runner,
  }) as unknown as OperationContext;

function webapp(): string {
  eng.ingest({ format: "penteos.ingest/v0", source: { parser: "test", tool: "test" }, rawIds: [], observedAt: new Date().toISOString(), items: [{ op: "upsert", kind: "webapp", key: { origin: "https://app.lab" }, confidence: 1 }] } as never, human);
  return eng.query({ kind: "webapp" })[0]!.id;
}

async function makeFinding(severity: string, title = "Acceso sin autenticación"): Promise<string> {
  const app = webapp();
  const f = (await executeOperation("finding.create", { title, severity, instances: [{ entityId: app, location: "GET /api/tenants/{id}" }] }, ctx())) as { id: string };
  return f.id;
}

/** A server with records at ids 1..n (JSON), 404 otherwise; optional slug records. */
async function recordsServer(n: number, opts: { slugs?: string[]; sparse?: number[] } = {}): Promise<void> {
  const exists = opts.sparse ? (id: number) => opts.sparse!.includes(id) : (id: number) => id >= 1 && id <= n;
  server = createServer((req, res) => {
    const m = /^\/api\/tenants\/([^/?]+)/.exec(req.url ?? "");
    if (m) {
      const raw = decodeURIComponent(m[1]!);
      const asInt = /^\d+$/.test(raw) ? Number(raw) : undefined;
      const ok = asInt !== undefined ? exists(asInt) : (opts.slugs ?? []).includes(raw);
      if (ok) {
        res.writeHead(200, { "Content-Type": "application/json" });
        return res.end(JSON.stringify({ id: raw, name: `Organismo ${raw}`, token: `tok_${raw}_abcdef123456`, contactEmail: `admin${raw}@muni.example` }));
      }
      res.writeHead(404, { "Content-Type": "application/json" });
      return res.end('{"message":"Not Found"}');
    }
    res.writeHead(404, { "Content-Type": "application/json" });
    res.end('{"message":"Not Found"}');
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", () => r()));
  const port = (server.address() as { port: number }).port;
  origin = `http://127.0.0.1:${port}`;
  eng.addScopeRule({ effect: "include", target: { type: "ip", value: "127.0.0.1" }, ports: String(port) }, human);
}

// --- opening the questions -------------------------------------------------------------------

it("a high finding opens its impact questions on creation; a low one does not", async () => {
  const high = await makeFinding("high");
  expect((eng.get(high)!.attributes.deepening as { questions: unknown[] } | undefined)?.questions).toHaveLength(3);
  const low = await makeFinding("low", "Cabeceras ausentes");
  expect(eng.get(low)!.attributes.deepening).toBeUndefined();
});

it("a medium finding about exposure opens them; a medium config change does not", async () => {
  const exposure = await makeFinding("medium", "Datos de clientes expuestos sin autenticación");
  expect(eng.get(exposure)!.attributes.deepening).toBeDefined();
  const plain = await makeFinding("medium", "Cookie sin flag Secure");
  expect(eng.get(plain)!.attributes.deepening).toBeUndefined();
});

it("raising a finding to high opens the questions", async () => {
  const id = await makeFinding("low", "Endpoint interesante");
  expect(eng.get(id)!.attributes.deepening).toBeUndefined();
  await executeOperation("finding.update", { id, severity: "high" }, ctx());
  expect(eng.get(id)!.attributes.deepening).toBeDefined();
});

// --- answering -------------------------------------------------------------------------------

it("an agent answering reach or exposed needs evidence; chain does not", async () => {
  const id = await makeFinding("high");
  const rawId = eng.putRaw("HTTP/1.1 200 OK\r\n\r\n{\"total\":120}", { type: "stdout", mime: "text/plain" });
  await expect(executeOperation("finding.answer_impact", { id, key: "reach", status: "answered", answer: "Se enumeran 120 clientes midiendo /api/tenants/{id}." }, ctx())).rejects.toMatchObject({ code: "VALIDATION_ERROR" });
  const ev = (await executeOperation("evidence.from_raw", { rawId, caption: "120 registros medidos" }, ctx())) as { id: string };
  await executeOperation("finding.answer_impact", { id, key: "reach", status: "answered", answer: "Se enumeran 120 clientes midiendo /api/tenants/{id}.", evidenceIds: [ev.id] }, ctx());
  await executeOperation("finding.answer_impact", { id, key: "chain", status: "answered", answer: "El token expuesto permite crear pedidos en nombre de cada cliente." }, ctx());
  const left = findingsToDeepen(eng).find((f) => f.id === id)?.open ?? [];
  expect(left).toEqual(["exposed"]);
  // The evidence of the impact is now evidence of the finding.
  expect(eng.get(id)!.attributes.evidenceIds).toContain(ev.id);
});

it("not_applicable closes a question with a reason, no evidence needed", async () => {
  const id = await makeFinding("high", "Diccionario de datos expuesto");
  await executeOperation("finding.answer_impact", { id, key: "exposed", status: "not_applicable", answer: "La respuesta no trae secretos ni datos personales; son nombres de campos de catálogo público." }, ctx());
  const q = (eng.get(id)!.attributes.deepening as { questions: Array<{ key: string; status: string }> }).questions.find((x) => x.key === "exposed")!;
  expect(q.status).toBe("not_applicable");
});

// --- the round does not close with questions open --------------------------------------------

it("plan_propose_paths refuses while a finding has open impact questions, unless deferred with findingId", async () => {
  const id = await makeFinding("high");
  const paths = [
    { title: "Probar autorización por objeto", why: "Dos cuentas, A lee datos de B", needs: "credentials" as const },
    { title: "Barrer subrutas", why: "Rutas bajo /api/tenants", needs: "nothing" as const },
  ];
  await expect(executeOperation("plan.propose_paths", { status: "Donde estamos", paths }, ctx())).rejects.toMatchObject({ code: "VALIDATION_ERROR" });
  // Deferring it as a path (with its findingId) is allowed.
  const ok = (await executeOperation("plan.propose_paths", { status: "Donde estamos", paths: [{ ...paths[0]!, findingId: id }, paths[1]!] }, ctx())) as { status: string };
  expect(ok.status).toBe("shown");
});

it("once every question is answered or not applicable, the round closes", async () => {
  const id = await makeFinding("high");
  const rawId = eng.putRaw("body", { type: "stdout", mime: "text/plain" });
  const ev = (await executeOperation("evidence.from_raw", { rawId, caption: "p" }, ctx())) as { id: string };
  await executeOperation("finding.answer_impact", { id, key: "reach", status: "answered", answer: "120 clientes, ids correlativos 1 a 150.", evidenceIds: [ev.id] }, ctx());
  await executeOperation("finding.answer_impact", { id, key: "exposed", status: "answered", answer: "Token del formulario público en cada ficha.", evidenceIds: [ev.id] }, ctx());
  await executeOperation("finding.answer_impact", { id, key: "chain", status: "not_applicable", answer: "No hay otro hallazgo en el mismo origen por ahora." }, ctx());
  const ok = (await executeOperation("plan.propose_paths", { status: "s", paths: [{ title: "a", why: "b", needs: "nothing" as const }, { title: "c", why: "d", needs: "nothing" as const }] }, ctx())) as { status: string };
  expect(ok.status).toBe("shown");
});

// --- untriaged high-signal observations block the round close --------------------------------

function highObservation(): void {
  const app = webapp();
  eng.ingest({ format: "penteos.ingest/v0", source: { parser: "test", tool: "test" }, rawIds: [], observedAt: new Date().toISOString(), items: [
    { op: "observe", title: "Admin endpoint answers without authentication: /api/admin", sourceRule: "apiprobe:no-auth", affects: [{ kind: "webapp", key: { origin: "https://app.lab" } }], severityHint: "high", location: "/api/admin" },
  ] } as never, human);
}
const twoPaths = [{ title: "a", why: "b", needs: "nothing" as const }, { title: "c", why: "d", needs: "nothing" as const }];

it("a round does not close while a high-signal observation is neither promoted nor dismissed", async () => {
  highObservation();
  await expect(executeOperation("plan.propose_paths", { status: "s", paths: twoPaths }, ctx())).rejects.toMatchObject({ code: "VALIDATION_ERROR" });
});

it("dismissing the observation (or promoting it) lets the round close", async () => {
  highObservation();
  const obs = eng.query({ kind: "observation", limit: 10 }).find((o) => String(o.attributes.sourceRule) === "apiprobe:no-auth")!;
  const r = (await executeOperation("observation.triage", { ids: [obs.id], triage: "false_positive", reason: "it is the public status page" }, ctx())) as { status: string; count: number };
  expect(r).toMatchObject({ status: "triaged", count: 1 });
  expect(eng.get(obs.id)!.attributes.triage).toBe("false_positive");
  const ok = (await executeOperation("plan.propose_paths", { status: "s", paths: twoPaths }, ctx())) as { status: string };
  expect(ok.status).toBe("shown");
});

// --- measuring the reach ---------------------------------------------------------------------

it("measures how many records a route opens, exactly when the budget fits", async () => {
  await recordsServer(40);
  const r = (await executeOperation("web.measure_enumeration", { origin, template: "/api/tenants/{id}" }, ctx())) as { status: string; estimate: number; highest: number; exact: boolean; mode: string; fields: string[]; rawId: string };
  expect(r.status).toBe("done");
  expect(r.mode).toBe("integers");
  expect(r.exact).toBe(true);
  expect(r.highest).toBe(40);
  expect(r.estimate).toBe(40);
  expect(r.fields).toEqual(expect.arrayContaining(["id", "name", "token"]));
  // An observation and raw landed for evidence.
  expect(eng.hasRaw(r.rawId)).toBe(true);
  expect(eng.query({ kind: "observation" }).some((o) => String(o.attributes.sourceRule) === "enum:measured")).toBe(true);
});

it("finds the highest id and counts the holes when the sequence is not dense", async () => {
  await recordsServer(0, { sparse: [1, 2, 3, 5, 8, 13] });
  const r = (await executeOperation("web.measure_enumeration", { origin, template: "/api/tenants/:id", maxRequests: 200 }, ctx())) as { highest: number; estimate: number; exact: boolean; hits: string[] };
  expect(r.highest).toBe(13);
  expect(r.exact).toBe(true);
  expect(r.estimate).toBe(6);
  expect(r.hits).toEqual(["1", "2", "3", "5", "8", "13"]);
});

it("tries slugs when identifiers are not integers", async () => {
  await recordsServer(0, { slugs: ["norte", "sur"] });
  const r = (await executeOperation("web.measure_enumeration", { origin, template: "/api/tenants/{slug}", values: ["norte", "sur", "cordoba", "nope"] }, ctx())) as { mode: string; estimate: number; hits: string[]; exact: boolean };
  expect(r.mode).toBe("values");
  expect(r.estimate).toBe(2);
  expect(r.hits).toEqual(expect.arrayContaining(["norte", "sur"]));
  expect(r.exact).toBe(true);
});

it("reports zero when no identifier answers with a record", async () => {
  await recordsServer(0);
  const r = (await executeOperation("web.measure_enumeration", { origin, template: "/api/tenants/{id}" }, ctx())) as { estimate: number; note: string };
  expect(r.estimate).toBe(0);
  expect(r.note).toMatch(/No identifier/);
});

// --- what the data exposes (unit) ------------------------------------------------------------

it("detects secrets, e-mails and storage buckets in a document; secrets become markers", () => {
  const { exposed } = exposedIn(eng, {
    name: "Organismo",
    config: { apiToken: "sk_" + "live_8s7d6f5g4h3j2k1l", twoFactorPolicy: "optional" },
    contacts: [{ email: "a@muni.example" }, { email: "b@muni.example" }],
    logo: "https://villaejemplo-assets.s3.amazonaws.com/logo.png",
  });
  const secret = exposed.find((x) => x.kind === "secret");
  expect(secret?.marker).toMatch(/^«secret:\d+/);
  expect(exposed.find((x) => x.kind === "emails")?.count).toBe(2);
  expect(exposed.find((x) => x.kind === "storage")?.hosts).toEqual(["villaejemplo-assets.s3.amazonaws.com"]);
  // A policy field named with "policy" is not treated as a secret value.
  expect(exposed.some((x) => x.kind === "secret" && x.marker?.includes("optional"))).toBe(false);
});

// --- the report shows demonstrated impact ----------------------------------------------------

it("the report has a Demonstrated impact section with the answered questions", async () => {
  const id = await makeFinding("high");
  const rawId = eng.putRaw("body", { type: "stdout", mime: "text/plain" });
  const ev = (await executeOperation("evidence.from_raw", { rawId, caption: "p" }, ctx())) as { id: string };
  await executeOperation("finding.answer_impact", { id, key: "reach", status: "answered", answer: "120 clientes enumerados.", evidenceIds: [ev.id] }, ctx());
  await executeOperation("finding.set_status", { id, status: "in_review" }, ctx());
  await executeOperation("finding.set_status", { id, status: "approved" }, ctx(human));
  const md = renderReport(eng, { includeDrafts: true });
  expect(md).toContain("Impacto demostrado");
  expect(md).toContain("120 clientes enumerados.");
});
