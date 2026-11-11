import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Actor } from "@penteos/schema";
import { strToU8, zipSync } from "fflate";
import { afterEach, beforeEach, expect, it } from "vitest";
import { type Engagement, executeOperation, type OperationContext, renderReport, ToolRegistry, ToolRunner, Workspace } from "../src/index.js";

/** A previous assessment done elsewhere as this one's baseline: fixed, still open, new. */
const human: Actor = { type: "human", id: "01JA00000000000000000000H1" };
const agent: Actor = { type: "agent", id: "01JA000000000000000000MSTR" };
let dir: string;
let ws: Workspace;
let eng: Engagement;
const ctx = (actor: Actor = agent): OperationContext =>
  ({ workspace: ws, caller: { actor, policy: actor.type === "human" ? { type: "human" } : { type: "agent", autonomy: "autonomous", maxRisk: "active" } }, defaultEngagementId: eng.info.id, engagement: () => eng, runner: () => new ToolRunner(eng, new ToolRegistry(join(dir, "tools"))) }) as unknown as OperationContext;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "penteos-baseline-"));
  ws = new Workspace(join(dir, "data"));
  eng = ws.create({ language: "es", clientName: "Cliente S.R.L.", name: "Web", mode: "web" }, human);
  eng.addScopeRule({ effect: "include", target: { type: "url", value: "https://app.cliente.test" } }, human);
  eng.ingest({ format: "penteos.ingest/v0", source: { parser: "test", tool: "test" }, rawIds: [], observedAt: new Date().toISOString(), items: [{ op: "upsert", kind: "webapp", key: { origin: "https://app.cliente.test" }, confidence: 1 }] } as never, human);
});
afterEach(() => {
  ws.close();
  rmSync(dir, { recursive: true, force: true });
});

it("reads a previous Word report from inputs/, and only from there for the agent", async () => {
  mkdirSync(join(eng.dir, "inputs"), { recursive: true });
  const xml = `<w:document><w:body><w:p><w:r><w:t>M1 Enumeración de usuarios en el login</w:t></w:r></w:p><w:p><w:r><w:t>A4 Path traversal en /api/onboarding/{id} &amp; más</w:t></w:r></w:p></w:body></w:document>`;
  writeFileSync(join(eng.dir, "inputs", "octubre.docx"), zipSync({ "word/document.xml": strToU8(xml) }));
  const r = (await executeOperation("baseline.read_document", { file: "octubre.docx" }, ctx())) as { text: string; method: string };
  expect(r.method).toBe("docx");
  expect(r.text).toContain("A4 Path traversal en /api/onboarding/{id} & más");
  await expect(executeOperation("baseline.read_document", { file: "../../../etc/passwd" }, ctx())).rejects.toMatchObject({ code: "NOT_FOUND" });
});

it("each previous finding gets a status; the round does not close without; the report compares", async () => {
  await executeOperation("baseline.set", { source: "Pentest de octubre (equipo interno)", date: "2026-10", findings: [
    { ref: "M1", title: "Enumeración de usuarios en el login", severity: "medium" },
    { ref: "A1", title: "n8n expuesto con CVE de RCE", severity: "high", asset: "automation.cliente.test" },
  ] }, ctx());
  const app = eng.query({ kind: "webapp" })[0]!;
  const f = (await executeOperation("finding.create", { title: "El login revela si un correo tiene cuenta", severity: "low", instances: [{ entityId: app.id }] }, ctx(human))) as { id: string };
  eng.editEntity(f.id, { status: "approved" }, human);
  const g = (await executeOperation("finding.create", { title: "Redirección abierta en redirectUrl", severity: "medium", instances: [{ entityId: app.id }] }, ctx(human))) as { id: string };
  eng.editEntity(g.id, { status: "approved" }, human);
  const paths = [{ title: "a", why: "b", needs: "nothing" }, { title: "c", why: "d", needs: "nothing" }];
  await expect(executeOperation("plan.propose_paths", { status: "Fin.", paths }, ctx())).rejects.toMatchObject({ message: expect.stringMatching(/2 finding\(s\) of the previous assessment have no status: M1/) });
  await expect(executeOperation("baseline.link", { ref: "M1", status: "still_open" }, ctx())).rejects.toMatchObject({ code: "VALIDATION_ERROR" });
  await executeOperation("baseline.link", { ref: "M1", status: "still_open", findingId: f.id }, ctx());
  await executeOperation("baseline.link", { ref: "A1", status: "not_retested", note: "automation.cliente.test quedó fuera del alcance de esta ronda" }, ctx());
  await expect(executeOperation("plan.propose_paths", { status: "Fin.", paths }, ctx())).resolves.toMatchObject({ status: "shown" });
  const md = renderReport(eng);
  expect(md).toContain("Comparación con la evaluación anterior");
  expect(md).toContain("**Corregidos:** 0 · **Siguen abiertos:** 1 · **No re-verificados:** 1");
  expect(md).toMatch(/\| M1 \| Enumeración de usuarios en el login \| Media \| Sigue abierto \| «El login revela si un correo tiene cuenta» \|/);
  expect(md).toContain("1 hallazgo nuevo en esta evaluación");
  expect(md).toContain("- Redirección abierta en redirectUrl (Media)");
});
