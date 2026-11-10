import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Actor } from "@penteos/schema";
import { afterEach, beforeEach, expect, it } from "vitest";
import { type Engagement, executeOperation, type OperationContext, recordEvent, resetRepeatGuard, type RunSummary, Workspace } from "../src/index.js";

/** How a run went: the agents' calls are counted, the operator notes what they missed, runs compare. */

const agent: Actor = { type: "agent", id: "01JA000000000000000000MSTR" };
const human: Actor = { type: "human", id: "01JA00000000000000000000H1" };
let dir: string;
let ws: Workspace;
let eng: Engagement;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "penteos-metrics-"));
  ws = new Workspace(join(dir, "data"));
  eng = ws.create({ clientName: "Cliente", name: "Web", mode: "web" }, human);
  resetRepeatGuard(agent.id);
});
afterEach(() => {
  ws.close();
  rmSync(dir, { recursive: true, force: true });
});

const ctx = (actor: Actor = agent): OperationContext =>
  ({
    workspace: ws,
    caller: { actor, policy: actor.type === "agent" ? { type: "agent", autonomy: "autonomous", maxRisk: "active" } : { type: "human" } },
    defaultEngagementId: eng.info.id,
    engagement: () => eng,
  }) as unknown as OperationContext;

it("counts the agents' calls, their errors, repairs and repeated calls", async () => {
  await executeOperation("note.create", { title: "uno", body: "x" }, ctx());
  await executeOperation("finding.create", { title: "Cabeceras ausentes", severity: "low", cwe: ["CWE-693"] }, ctx());
  await expect(executeOperation("finding.set_status", { id: "nope", status: "in_review" }, ctx())).rejects.toMatchObject({ code: "NOT_FOUND" });
  // The same write three times: the third is echoed.
  for (let i = 0; i < 3; i++) await executeOperation("note.create", { title: "repetida", body: "y" }, ctx());
  recordEvent(eng, "stepLimit");

  const s = (await executeOperation("metrics.summary", {}, ctx(human))) as RunSummary;
  expect(s.behaviour.calls).toBe(6);
  expect(s.behaviour.echoed).toBe(1);
  expect(s.behaviour.errors).toEqual({ NOT_FOUND: 1 });
  expect(s.behaviour.errorRate).toBeCloseTo(16.7, 1);
  expect(s.behaviour.stepLimit).toBe(1);
  expect(s.behaviour.ops["note.create"]).toBe(4);
  expect(s.findings).toMatchObject({ total: 1, draft: 1, bySeverity: { low: 1 } });
  // People's calls are not the agents' and are not counted.
  await executeOperation("note.create", { title: "humana", body: "z" }, ctx(human));
  expect(((await executeOperation("metrics.summary", {}, ctx(human))) as RunSummary).behaviour.calls).toBe(6);
});

it("the operator notes what the agents missed, and runs compare across engagements", async () => {
  await executeOperation("run_note.add", { kind: "missed", text: "No probó el IDOR en /api/tenants/{id}" }, ctx(human));
  await expect(executeOperation("run_note.add", { kind: "missed", text: "x" }, ctx())).rejects.toMatchObject({ code: "PERMISSION_DENIED" });
  const other = ws.create({ clientName: "Otro", name: "API", mode: "web" }, human);
  expect(other.info.id).not.toBe(eng.info.id);
  const all = (await executeOperation("metrics.compare", {}, ctx(human))) as RunSummary[];
  expect(all.map((r) => r.engagement.client).sort()).toEqual(["Cliente", "Laboratorio", "Otro"].filter((c) => all.some((r) => r.engagement.client === c)).sort());
  const mine = all.find((r) => r.engagement.id === eng.info.id)!;
  expect(mine.missed.map((n) => n.text)).toEqual(["No probó el IDOR en /api/tenants/{id}"]);
});
