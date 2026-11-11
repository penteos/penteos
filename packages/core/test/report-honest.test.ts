import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Actor } from "@penteos/schema";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { type Engagement, executeOperation, type OperationContext, renderReport, setPhase, ToolRegistry, ToolRunner, Workspace } from "../src/index.js";
import { WSTG } from "../src/wstg.js";

/**
 * A report says what the work can back: the overall risk only as far as the coverage reached, a
 * draft marked as one, and nothing internal (ids, credential markers, the sandbox's own commands).
 * What a real delivery showed: "Low" after one day without an account, "Pending" sections in a PDF.
 */
const human: Actor = { type: "human", id: "01JA00000000000000000000H1" };
const agent: Actor = { type: "agent", id: "01JA000000000000000000MSTR" };
let dir: string;
let ws: Workspace;
let eng: Engagement;
let runner: ToolRunner | undefined;
const ctx = (actor: Actor = human): OperationContext =>
  ({
    workspace: ws,
    caller: { actor, policy: actor.type === "human" ? { type: "human" } : { type: "agent", autonomy: "autonomous", maxRisk: "active" } },
    defaultEngagementId: eng.info.id,
    engagement: () => eng,
    runner: () => (runner ??= new ToolRunner(eng, new ToolRegistry(join(dir, "tools")))),
  }) as unknown as OperationContext;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "penteos-honest-"));
  ws = new Workspace(join(dir, "data"));
  eng = ws.create({ language: "es", clientName: "Cliente S.R.L.", name: "Web", mode: "web" }, human);
  eng.addScopeRule({ effect: "include", target: { type: "url", value: "https://app.cliente.test" } }, human);
  eng.ingest({ format: "penteos.ingest/v0", source: { parser: "test", tool: "test" }, rawIds: [], observedAt: new Date().toISOString(), items: [{ op: "upsert", kind: "webapp", key: { origin: "https://app.cliente.test" }, confidence: 1 }] } as never, human);
});
afterEach(() => {
  runner = undefined;
  ws.close();
  rmSync(dir, { recursive: true, force: true });
});

const app = () => eng.query({ kind: "webapp" })[0]!;
async function finding(severity: "low" | "high", text = "Descripción"): Promise<string> {
  const f = (await executeOperation("finding.create", { title: `Hallazgo ${severity}`, severity, description: text, instances: [{ entityId: app().id }] }, ctx())) as { id: string };
  eng.editEntity(f.id, { status: "approved" }, human);
  return f.id;
}
function coverEverything() {
  eng.editEntity(app().id, { coverage: Object.fromEntries(WSTG.map((c) => [c.id, { status: "tested" }])) }, human);
  // Phase by phase, as a round goes: exploitation was not authorized (left undone on purpose).
  for (const phase of ["mapping", "analysis", "reporting"]) setPhase(eng, phase, human);
}
const riskLine = (md: string) => md.split("\n").find((l) => /Nivel de riesgo general/.test(l)) ?? "";

describe("the overall risk follows the coverage", () => {
  it("is not determined with too little tested, and says what was missing", async () => {
    await finding("low");
    const md = renderReport(eng);
    expect(riskLine(md)).toContain("No determinado");
    expect(md).toMatch(/La cobertura alcanzada no permite determinar el riesgo general/);
    expect(md).toMatch(/Sin probar: \d+ de \d+ categorías/);
  });

  it("is at least as high as what was found, even with little coverage", async () => {
    await finding("high");
    expect(riskLine(renderReport(eng))).toContain("al menos Alto");
  });

  it("is stated plainly once the work covers it", async () => {
    await finding("low");
    coverEverything();
    const md = renderReport(eng);
    expect(riskLine(md)).toContain("Bajo");
    expect(md).not.toMatch(/no permite determinar/);
  });

  it("a person may accept the limits, and they are printed", async () => {
    await finding("low");
    const md = renderReport(eng, { limitations: "Sin cuentas de prueba; el backoffice quedó fuera." });
    expect(riskLine(md)).toContain("Bajo");
    expect(md).toContain("Limitaciones aceptadas para esta entrega:** Sin cuentas de prueba");
  });
});

describe("a draft is marked as one", () => {
  it("without an executive summary the deliverable is a draft, whatever was asked, and says why", async () => {
    await finding("low");
    coverEverything();
    const r = (await executeOperation("report.render", { format: "markdown" }, ctx())) as { readiness: { final: boolean; missing: string[] }; markdown: string };
    expect(r.readiness).toMatchObject({ final: false, missing: ["executive_summary"] });
    await executeOperation("report.set_summary", { executiveSummary: "Resumen para la gerencia." }, ctx());
    const ok = (await executeOperation("report.render", { format: "markdown" }, ctx())) as { readiness: { final: boolean } };
    expect(ok.readiness.final).toBe(true);
  });

  it("only a person accepts limits; an unfinished draft never pulls in unapproved findings", async () => {
    await expect(executeOperation("report.render", { format: "markdown", limitations: "x" }, ctx(agent))).rejects.toMatchObject({ code: "PERMISSION_DENIED" });
    const draft = (await executeOperation("finding.create", { title: "Sin aprobar", severity: "high", instances: [{ entityId: app().id }] }, ctx())) as { id: string };
    const r = (await executeOperation("report.render", { format: "markdown" }, ctx())) as { markdown: string };
    expect(r.markdown).not.toContain("Sin aprobar");
    expect(draft.id).toBeTruthy();
  });
});

describe("nothing internal reaches the reader", () => {
  it("ids become what they name, credential markers a plain mention; evidence blocks keep their content", async () => {
    const ev = (await executeOperation("evidence.from_raw", { rawId: eng.putRaw("HTTP/1.1 200 OK", { type: "stdout", mime: "text/plain" }), caption: "Respuesta del login" }, ctx())) as { id: string };
    const fid = await finding("low", `Ver la evidencia ${ev.id}. Se envió la cookie {{secret:probe_cookie}}.\n\n\`\`\`\nGET /x HTTP/1.1\nCookie: {{secret:probe_cookie}}\nX-Trace: ${ev.id}\n\`\`\``);
    const md = renderReport(eng);
    expect(md).toContain("Ver la evidencia «Respuesta del login»");
    expect(md).not.toContain("{{secret:");
    expect(md).toContain("[credencial de prueba]");
    // Inside the evidence block only the credential changes: the rest is as captured.
    expect(md).toContain(`X-Trace: ${ev.id}`);
    expect(fid).toBeTruthy();
  });

  it("the tools annex lists what touched a target, not the sandbox's local commands", () => {
    const local = eng.startRun({ actor: agent, origin: "agent_tool", tool: "ls", command: "ls -1 /usr/share/wordlists", targets: [], risk: "passive", policy: { result: "allowed" }, runner: "local" });
    eng.finishRun(local.id, { status: "finished" });
    const scan = eng.startRun({ actor: agent, origin: "agent_tool", tool: "httpx", command: "httpx -u https://app.cliente.test", targets: ["https://app.cliente.test"], risk: "passive", policy: { result: "allowed" }, runner: "local" });
    eng.finishRun(scan.id, { status: "finished" });
    const md = renderReport(eng);
    const annex = md.slice(md.indexOf("Herramientas utilizadas"));
    expect(annex).toContain("httpx");
    expect(annex).not.toMatch(/\| ls \|/);
  });

  it("what reconnaissance found outside the scope is listed as not tested", () => {
    eng.ingest({ format: "penteos.ingest/v0", source: { parser: "test", tool: "subfinder" }, rawIds: [], observedAt: new Date().toISOString(), items: [{ op: "upsert", kind: "domain", key: { fqdn: "automation.cliente.test" }, confidence: 1 }] } as never, human);
    const md = renderReport(eng);
    expect(md).toContain("Activos descubiertos fuera del alcance de esta ronda");
    expect(md).toContain("`automation.cliente.test`");
    expect(md).not.toContain("`app.cliente.test`"); // in scope: tested, not listed here
  });

  it("the reporting phase is this document, never 'not carried out' inside it", () => {
    const md = renderReport(eng);
    expect(md).not.toMatch(/\| Reporte \| No realizada/);
  });
});
