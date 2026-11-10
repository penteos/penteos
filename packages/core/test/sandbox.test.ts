import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { createServer, type Server } from "node:http";
import { homedir, tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { type Caller, type Engagement, executeOperation, offlineSandbox, type OperationContext, ToolRegistry, ToolRunner, Workspace } from "../src/index.js";

/**
 * Local analysis with no approval, because it cannot reach anything: an agent's command without
 * targets runs offline (no network, not even loopback) and can only write to the project.
 */

const MAESTRO: Caller = { actor: { type: "agent", id: "01JA000000000000000000MSTR" }, policy: { type: "agent", autonomy: "autonomous", maxRisk: "active" } };

let dir: string;
let ws: Workspace;
let eng: Engagement;
let runner: ToolRunner;
let server: Server;
let port: number;
const ctx = (): OperationContext => ({ workspace: ws, caller: MAESTRO, defaultEngagementId: eng.info.id, engagement: () => eng, runner: () => runner });

beforeEach(async () => {
  dir = mkdtempSync(join(tmpdir(), "penteos-sandbox-"));
  ws = new Workspace(join(dir, "data"));
  eng = ws.create({ clientName: "Lab", name: "Sandbox", mode: "web" }, MAESTRO.actor);
  runner = new ToolRunner(eng, new ToolRegistry(join(dir, "tools")));
  server = createServer((_req, res) => res.end("reached"));
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", () => r()));
  port = (server.address() as { port: number }).port;
});

afterEach(async () => {
  await new Promise((r) => server.close(r));
  ws.close();
  rmSync(dir, { recursive: true, force: true });
});

const run = async (script: string) => {
  const r = (await executeOperation("run.exec", { argv: ["python3", "-c", script], targets: [], risk: "passive", wait: 20 }, ctx())) as { status: string; output?: unknown; runId?: string };
  return r;
};
const text = (o: unknown) => String((o as { content?: string })?.content ?? o ?? "");

describe.skipIf(!offlineSandbox())("an agent's command with no targets", () => {
  it("runs at once, with no approval, and is marked offline", async () => {
    const r = await run("print('analysis ok')");
    expect(r.status).toBe("finished");
    expect(text(r.output)).toContain("analysis ok");
    expect(eng.getRun(r.runId!)!.policy.reason).toMatch(/offline sandbox/);
  });

  it("cannot reach the network, not even a server on this same machine", async () => {
    const r = await run(`import socket\ntry:\n  socket.create_connection(("127.0.0.1", ${port}), timeout=3); print("CONNECTED")\nexcept Exception as e:\n  print("BLOCKED", type(e).__name__)`);
    expect(text(r.output)).toContain("BLOCKED");
    expect(text(r.output)).not.toContain("CONNECTED");
  });

  it("writes only inside the project's work folder", async () => {
    const outside = join(homedir(), `penteos-sandbox-probe-${process.pid}`);
    const r = await run(`import os\nopen("inside.txt","w").write("ok"); print("INSIDE", os.path.exists("inside.txt"))\ntry:\n  open(${JSON.stringify(outside)},"w").write("x"); print("OUTSIDE-WROTE")\nexcept Exception as e:\n  print("OUTSIDE-BLOCKED")`);
    expect(text(r.output)).toContain("INSIDE True");
    expect(text(r.output)).toContain("OUTSIDE-BLOCKED");
    expect(existsSync(outside)).toBe(false);
  });
});

it("a command that declares targets still goes through scope as before", async () => {
  await expect(executeOperation("run.exec", { argv: ["curl", "https://not-in-scope.test/"], targets: ["https://not-in-scope.test/"], risk: "passive" }, ctx())).rejects.toMatchObject({ code: "OUT_OF_SCOPE" });
});
