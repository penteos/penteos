import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { type Engagement, executeOperation, type OperationContext, type Role, ToolRunner, Workspace } from "../src/index.js";

let dir: string;
let ws: Workspace;
let eng: Engagement;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "penteos-team-"));
  ws = new Workspace(dir);
  eng = ws.create({ clientName: "Cliente", name: "Web", mode: "web" }, { type: "human", id: "01JA0000000000000000000HMN" });
  eng.addScopeRule({ effect: "include", target: { type: "domain", value: "app.cliente.example" } }, { type: "human", id: "01JA0000000000000000000HMN" });
});

afterEach(() => {
  ws.close();
  rmSync(dir, { recursive: true, force: true });
});

function as(role: Role): OperationContext {
  const runner = new ToolRunner(eng);
  return {
    workspace: ws,
    caller: { actor: { type: "human", id: "01JA0000000000000000000ABC" }, policy: { type: "human" }, role, name: role },
    defaultEngagementId: eng.info.id,
    engagement: () => eng,
    runner: () => runner,
  };
}

describe("operators", () => {
  it("stores only a hash of the token, which is shown once", () => {
    const { operator, token } = ws.addOperator("Ana", "operator");
    expect(token).toMatch(/^pnt_/);
    expect(ws.operatorByToken(token)).toMatchObject({ id: operator.id, name: "Ana", role: "operator" });
    expect(ws.operatorByToken("pnt_wrong")).toBeUndefined();
    ws.setOperatorDisabled(operator.id, true);
    expect(ws.operatorByToken(token)).toBeUndefined();
  });
});

describe("role permissions", () => {
  const rule = { rule: { effect: "include", target: { type: "domain", value: "api.cliente.example" } } };

  it("observers only read", async () => {
    await expect(executeOperation("engagement.get", {}, as("observer"))).resolves.toBeDefined();
    await expect(executeOperation("finding.create", { title: "x", severity: "low" }, as("observer"))).rejects.toMatchObject({
      code: "PERMISSION_DENIED",
      message: expect.stringContaining("reviewer"),
    });
  });

  it("reviewers write findings and reports but do not touch targets", async () => {
    await expect(executeOperation("finding.create", { title: "x", severity: "low" }, as("reviewer"))).resolves.toBeDefined();
    await expect(executeOperation("run.exec", { argv: ["echo", "hola"], targets: [], risk: "passive" }, as("reviewer"))).rejects.toMatchObject({ code: "PERMISSION_DENIED" });
  });

  it("operators run tools and can stop work, but not change scope or resume", async () => {
    await expect(executeOperation("run.exec", { argv: ["echo", "hola"], targets: [], risk: "passive", wait: 5 }, as("operator"))).resolves.toMatchObject({ status: "finished" });
    await expect(executeOperation("scope.add_rule", rule, as("operator"))).rejects.toMatchObject({ code: "PERMISSION_DENIED" });
    await expect(executeOperation("engagement.stop_work", { reason: "pedido del cliente" }, as("operator"))).resolves.toMatchObject({ stopWork: true });
    await expect(executeOperation("engagement.resume_work", {}, as("operator"))).rejects.toMatchObject({ code: "PERMISSION_DENIED" });
  });

  it("never leaves the team without an active lead", async () => {
    const { operator } = ws.addOperator("Única", "lead");
    const self: OperationContext = { ...as("lead"), caller: { actor: { type: "human", id: operator.id }, policy: { type: "human" }, role: "lead" } };
    await expect(executeOperation("team.set_disabled", { id: operator.id, disabled: true }, self)).rejects.toMatchObject({ message: "you cannot disable yourself" });
    await expect(executeOperation("team.set_disabled", { id: operator.id, disabled: true }, as("lead"))).rejects.toMatchObject({ message: "this is the last active lead" });
  });

  it("leads manage scope and the team", async () => {
    await expect(executeOperation("scope.add_rule", rule, as("lead"))).resolves.toBeDefined();
    const added = (await executeOperation("team.add", { name: "Bruno", role: "reviewer" }, as("lead"))) as { token: string };
    expect(ws.operatorByToken(added.token)?.role).toBe("reviewer");
    await expect(executeOperation("team.add", { name: "bruno", role: "lead" }, as("lead"))).rejects.toMatchObject({ code: "CONFLICT" });
  });
});
