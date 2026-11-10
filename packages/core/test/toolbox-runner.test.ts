import { createHash } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { createServer, type Server } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Actor } from "@penteos/schema";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { type ToolCatalogEntry as CatalogEntry, type Engagement, executeOperation, type OperationContext, Toolbox, ToolRegistry, ToolRunner, Workspace } from "../src/index.js";

const human: Actor = { type: "human", id: "01JA0000000000000000000HMN" };
const agent: Actor = { type: "agent", id: "01JA000000000000000000MSTR" };

let dir: string;
let ws: Workspace;
let eng: Engagement;
let runner: ToolRunner;
let server: Server;
let served: Uint8Array;

/** A tool the catalog offers (as a plain file: format "raw"), and the bytes the server sends for it. */
const tool = new TextEncoder().encode('#!/bin/sh\nif [ "$1" = "-version" ]; then echo "probe2 version 1.0.0"; else echo "probe2 ran: $*"; fi\n');
const entry = (url: string, data = tool): CatalogEntry => ({
  name: "probe2",
  version: "1.0.0",
  via: "release",
  homepage: "https://example.test",
  license: "MIT",
  binary: "probe2",
  assets: { "linux-x64": { url, sha256: createHash("sha256").update(data).digest("hex"), size: data.length, format: "raw", bin: "probe2" } },
});

beforeEach(async () => {
  dir = mkdtempSync(join(tmpdir(), "penteos-toolbox-runner-"));
  served = tool;
  server = createServer((_q, s) => s.end(served));
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const url = `http://127.0.0.1:${(server.address() as { port: number }).port}/probe2`;
  ws = new Workspace(join(dir, "data"));
  eng = ws.create({ clientName: "Lab", name: "Caja", mode: "web" }, human);
  eng.addScopeRule({ effect: "include", target: { type: "ip", value: "127.0.0.1" } }, human);
  const box = new Toolbox(join(dir, "toolbox"), { catalog: [entry(url)], platform: "linux-x64", allowHttp: true, retryDelayMs: 5 });
  runner = new ToolRunner(eng, new ToolRegistry(join(dir, "tools"), box));
  // A tool Penteos knows (a manifest) that is not on this machine: only the catalog has it.
  runner.registry.save({ name: "probe2", description: "probe2", binaries: ["probe2-not-on-path"], risk: "passive", identity: { args: ["-version"], pattern: "probe2 version" }, targets: { flags: ["-u"] } });
});

afterEach(async () => {
  for (const r of eng.runs(50)) if (r.status === "running") await runner.waitForRun(r.id, 5);
  await new Promise((r) => server.close(r));
  ws.close();
  rmSync(dir, { recursive: true, force: true });
});

const ctx = (actor: Actor): OperationContext => ({
  workspace: ws,
  caller: { actor, policy: actor.type === "agent" ? { type: "agent", autonomy: "autonomous", maxRisk: "active" } : { type: "human" } },
  defaultEngagementId: eng.info.id,
  engagement: () => eng,
  runner: () => runner,
});

describe("tools from the verified catalog, end to end", () => {
  it("missing → the agent is told to propose it and move on → one card → installed without root → it runs", async () => {
    const status = (await runner.registry.status(true)).find((t) => t.name === "probe2")!;
    expect(status).toMatchObject({ installed: false, install: { method: "catalog", version: "1.0.0" }, catalog: { version: "1.0.0" } });

    // The agent tries it: a clear refusal saying what to do, not a shell command to run.
    const refused = (await executeOperation("run.exec", { argv: ["probe2", "-u", "http://127.0.0.1/"], targets: [], risk: "passive" }, ctx(agent)).catch((e) => e)) as { code: string; message: string };
    expect(refused.code).toBe("TOOL_NOT_INSTALLED");
    expect(refused.message).toMatch(/tool_propose_install.*keep working/s);

    // Proposing twice gives the same card.
    const a = (await executeOperation("tool.propose_install", { tool: "probe2", reason: "falta para el análisis" }, ctx(agent))) as { approvalId: string; summary: string };
    const b = (await executeOperation("tool.propose_install", { tool: "probe2", reason: "otra vez" }, ctx(agent))) as { approvalId: string };
    expect(b.approvalId).toBe(a.approvalId);
    expect(a.summary).toMatch(/verified, no root/);

    const installed: string[] = [];
    eng.events.on("change", (e: { type: string; tool?: string }) => e.type === "tool.installed" && installed.push(e.tool!));
    await executeOperation("approval.approve", { approvalId: a.approvalId }, ctx(human));
    const runId = eng.runs(10).find((r) => r.tool === "penteos-toolbox")?.id;
    expect(runId).toBeTruthy();
    const run = (await runner.waitForRun(runId!, 10))!;
    expect(run.status).toBe("finished");
    expect(run.summary).toMatchObject({ installed: { tool: "probe2", version: "1.0.0" } });
    expect(installed).toEqual(["probe2"]);

    const after = (await runner.registry.status(true)).find((t) => t.name === "probe2")!;
    expect(after).toMatchObject({ installed: true, managed: true, version: "1.0.0" });

    const ran = (await executeOperation("run.exec", { argv: ["probe2", "-u", "http://127.0.0.1/"], targets: [], risk: "passive" }, ctx(agent))) as { runId: string };
    const done = (await runner.waitForRun(ran.runId, 10))!;
    expect(eng.readRaw(done.rawIds[0]!).toString()).toContain("probe2 ran: -u http://127.0.0.1/");

    const box = (await executeOperation("tool.toolbox", {}, ctx(human))) as { tools: Array<{ name: string; installed?: { lastUsedAt?: string } }> };
    expect(box.tools[0]).toMatchObject({ name: "probe2", installed: { lastUsedAt: expect.any(String) } });
  });

  it("a failed install says why in the run, and leaves nothing behind", async () => {
    served = Uint8Array.from(tool, (b, i) => (i === 20 ? b ^ 1 : b));
    const r = runner.install("probe2", human);
    expect(r.status).toBe("started");
    const run = (await runner.waitForRun((r as { run: { id: string } }).run.id, 10))!;
    expect(run.status).toBe("failed");
    expect(run.summary).toMatchObject({ code: "HASH_MISMATCH" });
    expect(runner.registry.toolbox!.installed()).toEqual([]);
  });
});
