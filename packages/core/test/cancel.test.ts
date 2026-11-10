import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, expect, it } from "vitest";
import { type Caller, type Engagement, executeOperation, type OperationContext, ToolRegistry, ToolRunner, Workspace } from "../src/index.js";

/** "Cancel" always does something, and a cancelled run says so. */

const HUMAN: Caller = { actor: { type: "human", id: "01JA0000000000000000000HMN" }, policy: { type: "human" } };

let dir: string;
let ws: Workspace;
let eng: Engagement;
let runner: ToolRunner;
const ctx = (): OperationContext => ({ workspace: ws, caller: HUMAN, defaultEngagementId: eng.info.id, engagement: () => eng, runner: () => runner });

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "penteos-cancel-"));
  ws = new Workspace(join(dir, "data"));
  eng = ws.create({ clientName: "Lab", name: "Cancel", mode: "web" }, HUMAN.actor);
  runner = new ToolRunner(eng, new ToolRegistry(join(dir, "tools")));
});

afterEach(() => {
  ws.close();
  rmSync(dir, { recursive: true, force: true });
});

it("stops a process that ignores SIGINT, and the run ends as cancelled", async () => {
  const r = (await executeOperation("run.exec", { argv: ["sh", "-c", "trap '' INT; sleep 30"], targets: [], risk: "passive" }, ctx())) as { runId: string };
  await new Promise((ok) => setTimeout(ok, 300));
  expect(await executeOperation("run.cancel", { runId: r.runId }, ctx())).toEqual({ cancelled: true });
  const run = await runner.waitForRun(r.runId, 10);
  expect(run!.status).toBe("cancelled");
}, 15000);

it("closes a run left running with no process (a restart, a request in flight)", async () => {
  const run = eng.startRun({ actor: HUMAN.actor, origin: "runner", tool: "http", command: "GET https://lab.test/", targets: [], risk: "passive", policy: { result: "allowed" }, runner: "local" } as never);
  expect(await executeOperation("run.cancel", { runId: run.id }, ctx())).toEqual({ cancelled: true });
  expect(eng.getRun(run.id)!.status).toBe("cancelled");
  // A result that arrives late does not overwrite it, and cancelling again says there was nothing to do.
  eng.finishRun(run.id, { status: "finished" });
  expect(eng.getRun(run.id)!.status).toBe("cancelled");
  expect(await executeOperation("run.cancel", { runId: run.id }, ctx())).toEqual({ cancelled: false });
});
