import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Actor } from "@penteos/schema";
import { afterEach, expect, it } from "vitest";
import { executeOperation, type OperationContext, Workspace } from "../src/index.js";

const human: Actor = { type: "human", id: "01JA0000000000000000000HMN" };
const dir = mkdtempSync(join(tmpdir(), "penteos-prefs-"));
afterEach(() => rmSync(dir, { recursive: true, force: true }));

it("asks for onboarding on a fresh workspace, remembers where each operator left off, and changes the mode", async () => {
  const ws = new Workspace(join(dir, "data"));
  expect(ws.prefs().onboarded).toBe(false);

  const a = ws.create({ clientName: "ACME", name: "Web", mode: "web" }, human);
  const b = ws.create({ clientName: "ACME", name: "Infra", mode: "infra" }, human);
  // Onboarding is done when the operator finishes it, not inferred from what exists.
  expect(ws.prefs().onboarded).toBe(false);

  ws.rememberOpened(human.id, a.info.id);
  ws.rememberOpened("01JA000000000000000000OPR2", b.info.id);
  expect(ws.lastOpened(human.id)).toBe(a.info.id);
  expect(ws.lastOpened("01JA000000000000000000OPR2")).toBe(b.info.id);
  expect(ws.lastOpened("nobody")).toBeUndefined();

  const ctx: OperationContext = { workspace: ws, caller: { actor: human, policy: { type: "human" } }, defaultEngagementId: a.info.id, engagement: (id) => ws.get(id ?? a.info.id), runner: () => { throw new Error("no runner"); } };
  await executeOperation("workspace.set_prefs", { onboarded: true, workStyle: "team" }, ctx);
  expect(await executeOperation("workspace.prefs", {}, ctx)).toEqual({ onboarded: true, workStyle: "team", language: "en", languageSet: false });
  await executeOperation("engagement.update", { mode: "infra" }, ctx);
  expect(ws.list().find((e) => e.id === a.info.id)?.mode).toBe("infra");
  ws.close();
});
