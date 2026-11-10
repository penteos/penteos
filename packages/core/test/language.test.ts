import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Actor } from "@penteos/schema";
import { afterEach, expect, it } from "vitest";
import { executeOperation, getPlan, languageRules, setPhase, type OperationContext, renderReport, Workspace } from "../src/index.js";

/** The deliverable follows the project's language; the interface and the Maestro follow each operator's. */

const human: Actor = { type: "human", id: "01JA0000000000000000000HMN" };
const dir = mkdtempSync(join(tmpdir(), "penteos-lang-"));
afterEach(() => rmSync(dir, { recursive: true, force: true }));

it("renders the report frame and the phases in the project's language", () => {
  const ws = new Workspace(join(dir, "a"));
  const en = ws.create({ clientName: "ACME", name: "Web", mode: "web", language: "en" }, human);
  const es = ws.create({ clientName: "ACME", name: "Web ES", mode: "web", language: "es" }, human);

  const reportEn = renderReport(en);
  expect(reportEn).toContain("# Penetration test report - Web");
  expect(reportEn).toContain("Executive summary");
  expect(reportEn).not.toMatch(/Resumen ejecutivo|Alcance|Hallazgos/);
  expect(getPlan(en).phases[0]!.title).toBe("Reconnaissance");

  const reportEs = renderReport(es);
  expect(reportEs).toContain("Resumen ejecutivo");
  expect(getPlan(es).phases[0]!.title).toBe("Reconocimiento");
  ws.close();
});

it("keeps each operator's language and tells agents which language to use for what", async () => {
  const ws = new Workspace(join(dir, "b"));
  const e = ws.create({ clientName: "ACME", name: "Web", mode: "web" }, human);
  const ctx: OperationContext = { workspace: ws, caller: { actor: human, policy: { type: "human" } }, defaultEngagementId: e.info.id, engagement: () => e, runner: () => { throw new Error("no runner"); } };
  // English until the operator chooses, whatever the system's language.
  expect(await executeOperation("workspace.prefs", {}, ctx)).toMatchObject({ language: "en", languageSet: false });
  expect(e.info.language).toBe("en");
  await executeOperation("operator.set_language", { language: "es" }, ctx);
  expect(await executeOperation("workspace.prefs", {}, ctx)).toMatchObject({ language: "es", languageSet: true });

  const rules = languageRules("en", "es");
  expect(rules).toContain("Talk to the operator in English");
  expect(rules).toContain("deliverable in Spanish");
  expect(rules).toContain("no voseo");
  expect(languageRules(null, "en")).not.toContain("Talk to the operator");
  ws.close();
});

it("shows the standard phases in each reader's language, and follows a deliverable switched mid-project", async () => {
  const ws = new Workspace(join(dir, "c"));
  const e = ws.create({ clientName: "ACME", name: "Web", mode: "web", language: "en" }, human);
  const ctx: OperationContext = { workspace: ws, caller: { actor: human, policy: { type: "human" } }, defaultEngagementId: e.info.id, engagement: () => e, runner: () => { throw new Error("no runner"); } };
  const agent: OperationContext = { ...ctx, caller: { actor: { type: "agent", id: "maestro" }, policy: { type: "agent", autonomy: "autonomous", maxRisk: "passive" } } };
  type P = { phases: Array<{ id: string; title: string }> };
  // Moving a phase stores the plan (in the deliverable's language at that moment).
  setPhase(e, "mapping", human);
  await executeOperation("operator.set_language", { language: "es" }, ctx);
  // The operator reads Spanish; the Maestro keeps the deliverable's English.
  expect(((await executeOperation("plan.get", {}, ctx)) as P).phases[0]!.title).toBe("Reconocimiento");
  expect(((await executeOperation("plan.get", {}, agent)) as P).phases[0]!.title).toBe("Reconnaissance");
  // The deliverable switches to Spanish: the stored plan's standard phases follow it.
  await executeOperation("engagement.update", { language: "es" }, ctx);
  expect(getPlan(e).phases[0]!.title).toBe("Reconocimiento");
  ws.close();
});
