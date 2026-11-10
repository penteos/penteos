import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Actor } from "@penteos/schema";
import { strFromU8, unzipSync } from "fflate";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { type Engagement, executeOperation, type OperationContext, ToolRegistry, ToolRunner, Workspace } from "../src/index.js";

const human: Actor = { type: "human", id: "01JA0000000000000000000HMN" };
const agent: Actor = { type: "agent", id: "01JA000000000000000000MSTR" };
let dir: string;
let ws: Workspace;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "penteos-deliv-"));
  ws = new Workspace(join(dir, "data"));
});
afterEach(() => {
  ws.close();
  rmSync(dir, { recursive: true, force: true });
});

const ctx = (actor: Actor, eng: Engagement): OperationContext => ({
  workspace: ws,
  caller: { actor, policy: actor.type === "agent" ? { type: "agent", autonomy: "autonomous", maxRisk: "active" } : { type: "human" } },
  defaultEngagementId: eng.info.id,
  engagement: (id) => (id ? ws.get(id) : eng),
  runner: () => new ToolRunner(eng, new ToolRegistry(join(dir, "tools"))),
});

async function finding(eng: Engagement, title: string, severity: string, status = "approved") {
  const f = (await executeOperation("finding.create", { title, severity, description: "d", impact: "i", remediation: "r" }, ctx(human, eng))) as { id: string };
  await executeOperation("finding.set_status", { id: f.id, status }, ctx(human, eng));
  return f.id;
}

describe("CVSS", () => {
  it("scores 4.0 and 3.1 vectors and suggests a severity without changing it", async () => {
    const eng = ws.create({ language: "es", clientName: "ACME", name: "Web", mode: "web" }, human);
    const id = await finding(eng, "SQLi", "high");
    const r = (await executeOperation("finding.set_cvss", { id, vector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N" }, ctx(agent, eng))) as { score: number; suggestedSeverity: string; severity: string };
    expect(r).toMatchObject({ score: 9.3, suggestedSeverity: "critical", severity: "high" });
    expect(await executeOperation("cvss.score", { vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" }, ctx(agent, eng))).toMatchObject({ score: 9.8 });
    await expect(executeOperation("cvss.score", { vector: "CVSS:4.0/AV:Q" }, ctx(agent, eng))).rejects.toMatchObject({ code: "VALIDATION_ERROR" });
  });
});

describe("report by project type", () => {
  it("web: OWASP coverage; infrastructure: the attack paths over the directory", async () => {
    const web = ws.create({ language: "es", clientName: "ACME", name: "Web", mode: "web" }, human);
    web.addScopeRule({ effect: "include", target: { type: "domain", value: "shop.acme.test" } }, human);
    const app = web.createEntity("webapp", { origin: "https://shop.acme.test" }, human);
    await executeOperation("webapp.set_coverage", { webappId: app.id, category: "ATHN", status: "vulnerable", note: "credenciales por defecto" }, ctx(agent, web));
    const md1 = ((await executeOperation("report.render", {}, ctx(human, web))) as { markdown: string }).markdown;
    expect(md1).toContain("# Informe de pentest - Web");
    expect(md1).toContain("Cobertura de pruebas (OWASP WSTG)");
    expect(md1).toContain("| ATHN · Autenticación | **Vulnerable** | credenciales por defecto |");

    const infra = ws.create({ language: "es", clientName: "ACME", name: "Infra", mode: "infra" }, human);
    const md2 = ((await executeOperation("report.render", {}, ctx(human, infra))) as { markdown: string }).markdown;
    expect(md2).toContain("# Informe de pentest - Infra");
    expect(md2).not.toContain("Cobertura de pruebas (OWASP WSTG)");
  });

  it("retest: the result of each inherited finding", async () => {
    const orig = ws.create({ language: "es", clientName: "ACME", name: "Pentest 2025", mode: "web" }, human);
    await finding(orig, "SQLi en login", "critical", "reported");
    await finding(orig, "XSS reflejado", "medium", "reported");
    const r = (await executeOperation("engagement.retest", { sourceEngagementId: orig.info.id }, ctx(human, orig))) as { id: string };
    const retest = ws.get(r.id);
    const [a, b] = retest.query({ kind: "finding" });
    await executeOperation("finding.set_status", { id: a!.id, status: "fixed" }, ctx(human, retest));
    await executeOperation("finding.set_status", { id: b!.id, status: "not_verifiable" }, ctx(human, retest));
    const md = ((await executeOperation("report.render", {}, ctx(human, retest))) as { markdown: string }).markdown;
    expect(md).toContain("# Informe de retest");
    expect(md).toContain("De 2 hallazgos verificados: **1 corregidos**");
    expect(md).toContain("1 no verificables");
    expect(md).toContain("**Comparación con el original:** 1 resueltos");
  });
});

describe("DOCX", () => {
  it("exports the deliverable as a Word document with a cover and the findings", async () => {
    const eng = ws.create({ language: "es", clientName: "ACME", name: "Pentest web", mode: "web" }, human);
    await finding(eng, "Credenciales por defecto", "high");
    ws.setBranding({ companyName: "Seguridad SA", primaryColor: "#5b4bd6" });
    const r = (await executeOperation("report.render", { format: "docx" }, ctx(human, eng))) as { file: string; docxBase64: string };
    const bytes = Buffer.from(r.docxBase64, "base64");
    expect(bytes.subarray(0, 2).toString()).toBe("PK");
    const xml = strFromU8(unzipSync(new Uint8Array(bytes))["word/document.xml"]!);
    expect(xml).toContain("Informe de pentest - Pentest web");
    expect(xml).toMatch(/Elaborado por<\/w:t>[\s\S]*Seguridad SA/);
    expect(xml).toContain("Credenciales por defecto");
    expect(r.file.endsWith(".docx")).toBe(true);
  });
});
