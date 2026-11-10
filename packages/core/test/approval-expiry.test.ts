import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, expect, it } from "vitest";
import { type Caller, type ChangeEvent, type Engagement, executeOperation, type OperationContext, ToolRegistry, ToolRunner, Workspace } from "../src/index.js";

/** A request that lapses unanswered is not silently dropped: whoever asked hears about it. */

const HUMAN: Caller = { actor: { type: "human", id: "01JA0000000000000000000HMN" }, policy: { type: "human" } };
const MAESTRO: Caller = { actor: { type: "agent", id: "01JA000000000000000000MSTR" }, policy: { type: "agent", autonomy: "autonomous", maxRisk: "active" } };

let dir: string;
let ws: Workspace;
let eng: Engagement;
let runner: ToolRunner;
let events: ChangeEvent[];
const ctx = (caller: Caller): OperationContext => ({ workspace: ws, caller, defaultEngagementId: eng.info.id, engagement: () => eng, runner: () => runner });

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "penteos-expiry-"));
  ws = new Workspace(join(dir, "data"));
  eng = ws.create({ clientName: "Lab", name: "Expiry", mode: "web" }, HUMAN.actor);
  runner = new ToolRunner(eng, new ToolRegistry(join(dir, "tools")));
  eng.addScopeRule({ effect: "include", target: { type: "domain", value: "app.test" } }, HUMAN.actor);
  events = [];
  eng.events.on("change", (e: ChangeEvent) => events.push(e));
});

afterEach(() => {
  ws.close();
  rmSync(dir, { recursive: true, force: true });
});

it("waits eight hours, then tells whoever asked and keeps what it was", async () => {
  const p = (await executeOperation("scope.propose_rule", { rule: { effect: "include", target: { type: "domain", value: "www.app.test" } }, reason: "el sitio redirige a www" }, ctx(MAESTRO))) as { approvalId: string };
  const a = runner.listApprovals().find((x) => x.id === p.approvalId)!;
  expect(Date.parse(a.expiresAt) - Date.parse(a.createdAt)).toBeGreaterThanOrEqual(8 * 60 * 60 * 1000);

  // Time passes with no answer.
  a.expiresAt = new Date(Date.now() - 1000).toISOString();
  expect(runner.listApprovals().some((x) => x.id === p.approvalId)).toBe(false);
  expect(events.find((e) => e.type === "approval.expired")).toMatchObject({ id: p.approvalId, requestedBy: MAESTRO.actor });
  expect(runner.approvalStatus([p.approvalId])[p.approvalId]).toMatchObject({ state: "expired", summary: expect.stringContaining("www.app.test") });
});

it("survives a restart: what was pending still is, and what was decided still says how", async () => {
  const a = (await executeOperation("scope.propose_rule", { rule: { effect: "include", target: { type: "domain", value: "www.app.test" } }, reason: "redirige a www" }, ctx(MAESTRO))) as { approvalId: string };
  const b = (await executeOperation("scope.propose_rule", { rule: { effect: "include", target: { type: "domain", value: "api.app.test" } }, reason: "la API" }, ctx(MAESTRO))) as { approvalId: string };
  await executeOperation("approval.approve", { approvalId: a.approvalId }, ctx(HUMAN));

  // Penteos restarts: a new workspace and runner over the same data.
  const id = eng.info.id;
  ws.close();
  ws = new Workspace(join(dir, "data"));
  eng = ws.get(id);
  runner = new ToolRunner(eng, new ToolRegistry(join(dir, "tools")));

  expect(runner.approvalStatus([a.approvalId, b.approvalId])).toMatchObject({
    [a.approvalId]: { state: "approved" },
    [b.approvalId]: { state: "pending" },
  });
  // And the pending one can still be decided, with its effect.
  await executeOperation("approval.approve", { approvalId: b.approvalId }, ctx(HUMAN));
  expect(eng.scopeRules().some((r) => r.target.type === "domain" && r.target.value === "api.app.test")).toBe(true);
});
