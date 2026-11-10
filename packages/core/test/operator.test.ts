import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { type Caller, type ChangeEvent, type Engagement, executeOperation, type OperationContext, setPhase, ToolRegistry, ToolRunner, Workspace } from "../src/index.js";

const HUMAN: Caller = { actor: { type: "human", id: "01JA0000000000000000000HMN" }, policy: { type: "human" } };
const MAESTRO: Caller = { actor: { type: "agent", id: "01JA000000000000000000MSTR" }, policy: { type: "agent", autonomy: "autonomous", maxRisk: "active" } };

let dir: string;
let ws: Workspace;
let eng: Engagement;
let runner: ToolRunner;
let events: ChangeEvent[];

const ctx = (caller: Caller): OperationContext => ({ workspace: ws, caller, defaultEngagementId: eng.info.id, engagement: () => eng, runner: () => runner });

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "penteos-operator-"));
  ws = new Workspace(join(dir, "data"));
  eng = ws.create({ language: "es", clientName: "Lab", name: "Web", mode: "web" }, HUMAN.actor);
  runner = new ToolRunner(eng, new ToolRegistry(join(dir, "tools")));
  eng.addScopeRule({ effect: "include", target: { type: "domain", value: "app.lab" } }, HUMAN.actor);
  events = [];
  eng.events.on("change", (e: ChangeEvent) => events.push(e));
});

afterEach(() => {
  ws.close();
  rmSync(dir, { recursive: true, force: true });
});

describe("questions on the board", () => {
  it("an agent asks once, the operator answers on the card, the agent hears it", async () => {
    const t = (await executeOperation("task.create", { title: "Credenciales", assignee: "operator", question: "¿Uso admin/password o me pasás otras?" }, ctx(MAESTRO))) as { id: string };
    expect(eng.get(t.id)!.attributes.question).toMatch(/admin\/password/);
    await expect(executeOperation("task.answer", { id: t.id, answer: "Usá esas" }, ctx(MAESTRO))).rejects.toMatchObject({ code: "PERMISSION_DENIED" });
    await executeOperation("task.answer", { id: t.id, answer: "Usá las de por defecto" }, ctx(HUMAN));
    const task = eng.get(t.id)!.attributes;
    expect(task.status).toBe("done");
    expect(task.answer).toMatchObject({ text: "Usá las de por defecto", by: HUMAN.actor });
    expect(events.find((e) => e.type === "task.answered")).toMatchObject({ taskId: t.id, answer: "Usá las de por defecto", askedBy: MAESTRO.actor });
  });
});

describe("rules of engagement", () => {
  it("name saved secrets only, reach the brief, and only humans set them", async () => {
    await expect(executeOperation("rules.set", { accounts: [{ label: "admin", username: "admin", secret: "nope" }] }, ctx(HUMAN))).rejects.toMatchObject({ code: "UNKNOWN_SECRET" });
    await executeOperation("secret.save", { name: "cuenta_admin", kind: "password", value: "s3cr3t" }, ctx(HUMAN));
    await executeOperation("rules.set", { accounts: [{ label: "admin de la app", username: "admin", secret: "cuenta_admin", role: "admin" }], allowed: "nivel bajo y medio", avoid: "no resetear la base" }, ctx(HUMAN));
    await expect(executeOperation("rules.set", { accounts: [] }, ctx(MAESTRO))).rejects.toMatchObject({ code: "PERMISSION_DENIED" });
    const brief = (await executeOperation("engagement.brief", {}, ctx(MAESTRO))) as { rules: { accounts: Array<{ use: string; username: string }>; avoid: string } };
    expect(brief.rules.accounts[0]).toMatchObject({ username: "admin", use: "{{secret:cuenta_admin}}" });
    expect(brief.rules.avoid).toBe("no resetear la base");
    expect(JSON.stringify(brief)).not.toContain("s3cr3t");
  });
});

describe("coverage", () => {
  it("the matrix shows every application, and closing the analysis with gaps warns the operator", async () => {
    eng.ingest({ format: "penteos.ingest/v0", source: { parser: "test@0.1", tool: "test" }, rawIds: [], observedAt: new Date().toISOString(), items: [{ op: "upsert", kind: "webapp", key: { origin: "https://app.lab" }, confidence: 1 }] } as never, HUMAN.actor);
    const app = eng.query({ kind: "webapp" })[0]!;
    await executeOperation("webapp.set_coverage", { webappId: app.id, category: "ATHN", status: "tested" }, ctx(MAESTRO));
    const m = (await executeOperation("coverage.matrix", {}, ctx(HUMAN))) as { apps: Array<{ origin: string; coverage: Array<{ id: string; status: string }> }> };
    expect(m.apps).toHaveLength(1);
    expect(m.apps[0]!.coverage.find((c) => c.id === "ATHN")!.status).toBe("tested");
    expect(m.apps[0]!.coverage.find((c) => c.id === "INPV")!.status).toBe("untested");

    setPhase(eng, "analysis", HUMAN.actor);
    const r = (await executeOperation("phase.request", { to: "exploitation", summary: "Listo" }, ctx(MAESTRO))) as { note?: string };
    expect(r.note).toMatch(/11 de 12 categorías sin cubrir/);
    expect(runner.listApprovals()[0]!.warnings[0]).toMatch(/https:\/\/app\.lab: 11 de 12 categorías sin cubrir/);
  });
});

describe("approvals", () => {
  it("say who decided, so the agent knows a human just acted", async () => {
    const a = runner.proposeScopeRule({ effect: "include", target: { type: "domain", value: "api.lab" } }, "lo necesito", MAESTRO.actor);
    await executeOperation("approval.approve", { approvalId: a.id }, ctx(HUMAN));
    expect(events.find((e) => e.type === "approval.resolved")).toMatchObject({ id: a.id, approved: true, decidedBy: HUMAN.actor });
  });
});

describe("ingest", () => {
  it("accepts a parser named without a version (what agents tend to write)", async () => {
    const r = (await executeOperation("ingest.submit_batch", { batch: { format: "penteos.ingest/v0", source: { parser: "agent:recon", tool: "recon" }, rawIds: [], observedAt: new Date().toISOString(), items: [{ op: "upsert", kind: "domain", key: { fqdn: "app.lab" }, confidence: 1 }] } }, ctx(MAESTRO))) as { created: Record<string, number> };
    expect(r.created.domain).toBe(1);
  });
});

describe("board", () => {
  it("a human deletes a task (kept in the audit); an agent cannot", async () => {
    const t = (await executeOperation("task.create", { title: "Probar IDOR" }, ctx(MAESTRO))) as { id: string };
    await expect(executeOperation("task.delete", { id: t.id }, ctx(MAESTRO))).rejects.toMatchObject({ code: "PERMISSION_DENIED" });
    await executeOperation("task.delete", { id: t.id }, ctx(HUMAN));
    expect(eng.get(t.id)).toBeUndefined();
    expect(((await executeOperation("task.list", {}, ctx(HUMAN))) as unknown[]).length).toBe(0);
    expect(eng.auditEvents({ limit: 5 }).some((a) => a.action === "task.delete")).toBe(true);
  });
});
