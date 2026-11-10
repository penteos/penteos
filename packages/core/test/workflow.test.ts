import { chmodSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Actor } from "@penteos/schema";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { type Engagement, executeOperation, type OperationContext, ToolRegistry, ToolRunner, Workspace } from "../src/index.js";

const human: Actor = { type: "human", id: "01JA0000000000000000000HMN" };
const agent: Actor = { type: "agent", id: "01JA000000000000000000MSTR" };

let dir: string;
let ws: Workspace;
let eng: Engagement;
let runner: ToolRunner;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "penteos-workflow-"));
  ws = new Workspace(join(dir, "data"));
  eng = ws.create({ clientName: "Lab", name: "DVWA", mode: "web", maxRisk: "exploitation" }, human);
  eng.addScopeRule({ effect: "include", target: { type: "ip", value: "127.0.0.1" }, ports: "4280" }, human);
  runner = new ToolRunner(eng, new ToolRegistry(join(dir, "tools")));
  // A probe that prints its arguments, so we can see what really reached the process.
  const tool = join(dir, "probe");
  writeFileSync(tool, '#!/bin/sh\necho "args: $*"\n');
  chmodSync(tool, 0o755);
  runner.registry.save({ name: "probe", description: "probe", binaries: [tool], risk: "active", targets: { flags: ["-u"] } });
});

afterEach(async () => {
  for (const r of eng.runs(50)) if (r.status === "running") await runner.waitForRun(r.id, 5);
  ws.close();
  rmSync(dir, { recursive: true, force: true });
});

const ctx = (actor: Actor, maxRisk: "active" | "intrusive" | "exploitation" = "active"): OperationContext => ({
  workspace: ws,
  caller: { actor, policy: actor.type === "agent" ? { type: "agent", autonomy: "autonomous", maxRisk } : { type: "human" } },
  defaultEngagementId: eng.info.id,
  engagement: () => eng,
  runner: () => runner,
});

const exec = (actor: Actor, risk: string, extra: string[] = []) =>
  executeOperation("run.exec", { argv: ["probe", "-u", "http://127.0.0.1:4280/", ...extra], targets: [], risk }, ctx(actor)) as Promise<Record<string, string>>;

describe("approvals", () => {
  it("does not create a second card for the same request, and lets the agent withdraw it", async () => {
    const a = await exec(agent, "intrusive");
    const b = await exec(agent, "intrusive");
    expect(a.status).toBe("pending_approval");
    expect(b).toMatchObject({ approvalId: a.approvalId, note: expect.stringContaining("already asked") });
    expect(runner.listApprovals()).toHaveLength(1);

    await executeOperation("approval.withdraw", { approvalId: a.approvalId, reason: "ya no hace falta" }, ctx(agent));
    expect(runner.listApprovals()).toHaveLength(0);
    expect(runner.approvalStatus([a.approvalId!])[a.approvalId!]!.state).toBe("withdrawn");
  });

  it("'allow during the session' covers the same tool and targets, but not more risk", async () => {
    const a = await exec(agent, "intrusive");
    await executeOperation("approval.approve", { approvalId: a.approvalId, forSession: true }, ctx(human));
    // Same tool and target, same risk: runs without asking.
    expect((await exec(agent, "intrusive", ["-v"])).status).toBe("running");
    // More risk: asks again. (Exploitation is also gated by the phase.)
    await expect(exec(agent, "exploitation")).rejects.toMatchObject({ code: "PHASE" });
    await executeOperation("approval.revoke_grant", { id: runner.grants()[0]!.id }, ctx(human));
    expect((await exec(agent, "intrusive", ["-x"])).status).toBe("pending_approval");
  });

  it("warns when a command uses files of this machine", async () => {
    const a = await exec(agent, "intrusive", ["-b", "/tmp/jar.txt"]);
    expect(runner.listApprovals().find((x) => x.id === a.approvalId)!.localFiles).toContain("/tmp/jar.txt");
  });
});

describe("phases", () => {
  it("starts in recon, blocks agent exploitation until a human approves the phase change", async () => {
    const plan = (await executeOperation("plan.get", {}, ctx(agent))) as { current: string; phases: Array<{ id: string }> };
    expect(plan.current).toBe("recon");
    expect(plan.phases.map((p) => p.id)).toEqual(["recon", "mapping", "analysis", "exploitation", "reporting"]);

    await executeOperation("plan.set_phase_plan", { phase: "recon", plan: "- nmap del puerto\n- httpx" }, ctx(agent));
    await expect(exec(agent, "exploitation")).rejects.toMatchObject({ code: "PHASE" });

    const req = (await executeOperation("phase.request", { to: "exploitation", summary: "Login con credenciales por defecto confirmado." }, ctx(agent))) as { approvalId: string };
    await executeOperation("approval.approve", { approvalId: req.approvalId }, ctx(human));
    const after = (await executeOperation("plan.get", {}, ctx(agent))) as { current: string; phases: Array<{ id: string; status: string; summary?: string }> };
    expect(after.current).toBe("exploitation");
    expect(after.phases.find((p) => p.id === "recon")).toMatchObject({ status: "done", summary: expect.stringContaining("credenciales") });

    // Now it is the risk ceiling that decides (this agent's is "active"): it asks, not denies.
    expect((await exec(agent, "exploitation")).status).toBe("pending_approval");
  });

  it("does not re-open a phase pass that is pending or already granted", async () => {
    await executeOperation("plan.set_phase_plan", { phase: "recon", plan: "- recon" }, ctx(agent));
    const first = (await executeOperation("phase.request", { to: "mapping", summary: "Reconocimiento cerrado." }, ctx(agent))) as { status: string; approvalId: string };
    expect(first.status).toBe("pending_approval");
    // Asking again while it waits hands back the same request, not a duplicate.
    const again = (await executeOperation("phase.request", { to: "mapping", summary: "otra vez" }, ctx(agent))) as { status: string; approvalId: string };
    expect(again.status).toBe("already_pending");
    expect(again.approvalId).toBe(first.approvalId);

    await executeOperation("approval.approve", { approvalId: first.approvalId }, ctx(human));
    expect(((await executeOperation("plan.get", {}, ctx(agent))) as { current: string }).current).toBe("mapping");
    // Asking to move to the phase it is already in is a no-op, not a new card.
    const done = (await executeOperation("phase.request", { to: "mapping", summary: "ya estoy" }, ctx(agent))) as { status: string; approvalId?: string };
    expect(done.status).toBe("already_in_phase");
    expect(done.approvalId).toBeUndefined();
  });

  it("free mode has no phases and gates nothing", async () => {
    await executeOperation("engagement.update", { mode: "custom" }, ctx(human));
    expect(((await executeOperation("plan.get", {}, ctx(agent))) as { phases: unknown[] }).phases).toEqual([]);
    expect((await exec(agent, "exploitation")).status).toBe("pending_approval");
  });
});

describe("secrets", () => {
  it("are used by reference: the process gets the value, everything else shows the reference", async () => {
    await executeOperation("secret.save", { name: "dvwa_session", kind: "cookie", value: "PHPSESSID=abc123secret", note: "admin" }, ctx(agent));
    expect(JSON.stringify(await executeOperation("secret.list", {}, ctx(agent)))).not.toContain("abc123secret");

    const r = (await executeOperation("run.exec", { argv: ["probe", "-u", "http://127.0.0.1:4280/", "-H", "Cookie: {{secret:dvwa_session}}"], targets: [], risk: "active", wait: 5 }, ctx(agent))) as {
      output: { content: string };
    };
    // The process received the value; the agent reads it back redacted.
    expect(JSON.stringify(r)).not.toContain("abc123secret");
    expect(JSON.stringify(r)).toContain("{{secret:dvwa_session}}");
    expect(eng.runs(1)[0]!.command).toContain("{{secret:dvwa_session}}");
    const raw = eng.readRaw(eng.runs(1)[0]!.rawIds[0]!).toString();
    expect(raw).toContain("abc123secret");

    await expect(executeOperation("run.exec", { argv: ["probe", "-u", "http://127.0.0.1:4280/", "{{secret:nope}}"], targets: [], risk: "active" }, ctx(agent))).rejects.toMatchObject({ code: "UNKNOWN_SECRET" });
    await expect(executeOperation("secret.reveal", { name: "dvwa_session" }, ctx(agent))).rejects.toMatchObject({ code: "PERMISSION_DENIED" });
    expect(await executeOperation("secret.reveal", { name: "dvwa_session" }, ctx(human))).toMatchObject({ value: "PHPSESSID=abc123secret" });
  });
});

describe("vault", () => {
  it("keeps secret values encrypted in the engagement database", async () => {
    await executeOperation("secret.save", { name: "db_pass", kind: "password", value: "Sup3rS3cret!" }, ctx(human));
    const Database = (await import("../src/store/sqlite.js")).default;
    const db = new Database(join(eng.dir, "engagement.db"), { readonly: true });
    const stored = (db.prepare("select value from secrets where name = 'db_pass'").get() as { value: string }).value;
    db.close();
    expect(stored.startsWith("v1:")).toBe(true);
    expect(stored).not.toContain("Sup3rS3cret");
    expect(eng.secretValue("db_pass")).toBe("Sup3rS3cret!");
    expect(eng.redact("password=Sup3rS3cret!")).toBe("password={{secret:db_pass}}");
  });
});

describe("notes and tasks", () => {
  it("links mentions and moves tasks across the board", async () => {
    const app = eng.createEntity("webapp", { origin: "http://127.0.0.1:4280" }, human);
    const note = (await executeOperation("note.create", { title: "Login", body: `El login de [@dvwa](penteos:entity/${app.id}) usa token CSRF.` }, ctx(agent))) as { attributes: { mentions: unknown[] } };
    expect(note.attributes.mentions).toEqual([{ kind: "webapp", id: app.id }]);

    const t = (await executeOperation("task.create", { title: "Probar IDOR en /api/orders", priority: "high", assignee: "maestro" }, ctx(human))) as { id: string; attributes: Record<string, unknown> };
    expect(t.attributes).toMatchObject({ status: "todo", priority: "high", assignee: { type: "agent" } });
    await executeOperation("task.update", { id: t.id, status: "in_progress" }, ctx(agent));
    await executeOperation("task.update", { id: t.id, assignee: "nobody" }, ctx(human));
    const [task] = (await executeOperation("task.list", { status: "in_progress" }, ctx(agent))) as Array<{ attributes: Record<string, unknown> }>;
    expect(task!.attributes.status).toBe("in_progress");
    expect(task!.attributes.assignee ?? null).toBeNull();
  });
});

describe("memory", () => {
  it("remembers attempts per entity, flags them when the entity changes, and can be invalidated", async () => {
    const app = eng.createEntity("webapp", { origin: "http://127.0.0.1:4280" }, human);
    const m = (await executeOperation("memory.write", { memoryType: "attempt", content: "sqlmap en /login: bloqueado por WAF tras 15 requests", entityIds: [app.id] }, ctx(agent))) as { id: string };
    let [found] = (await executeOperation("memory.query", { entityId: app.id }, ctx(agent))) as Array<{ id: string; reverify: boolean; attributes: { trusted: boolean } }>;
    expect(found).toMatchObject({ id: m.id, reverify: false, attributes: { trusted: true } });

    await new Promise((r) => setTimeout(r, 5));
    eng.editEntity(app.id, { title: "DVWA v2" }, human); // the application changed
    [found] = (await executeOperation("memory.query", { entityId: app.id }, ctx(agent))) as Array<{ id: string; reverify: boolean; attributes: { trusted: boolean } }>;
    expect(found!.reverify).toBe(true);

    const brief = (await executeOperation("engagement.brief", {}, ctx(agent))) as { memory: Array<{ content: string }> };
    expect(brief.memory[0]!.content).toContain("WAF");

    await executeOperation("memory.update", { id: m.id, invalidate: "el WAF se desactivó" }, ctx(human));
    expect(await executeOperation("memory.query", { entityId: app.id }, ctx(agent))).toEqual([]);
  });
});
