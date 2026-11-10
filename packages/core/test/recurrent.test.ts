import { chmodSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { type Actor, INGEST_FORMAT, type IngestItem } from "@penteos/schema";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { type Engagement, executeOperation, type OperationContext, runDueSchedules, type SnapshotDiff, ToolRegistry, ToolRunner, Workspace } from "../src/index.js";

const human: Actor = { type: "human", id: "01JA0000000000000000000HMN" };
const agent: Actor = { type: "agent", id: "01JA000000000000000000MSTR" };

let dir: string;
let ws: Workspace;
let eng: Engagement;
const runners = new Map<string, ToolRunner>();

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "penteos-recurrent-"));
  ws = new Workspace(join(dir, "data"));
  eng = ws.create({ clientName: "ACME", name: "Pentest 2025", mode: "web" }, human);
  eng.addScopeRule({ effect: "include", target: { type: "cidr", value: "10.0.0.0/24" } }, human);
});

afterEach(() => {
  runners.clear();
  ws.close();
  rmSync(dir, { recursive: true, force: true });
});

const ctx = (actor: Actor, e = eng): OperationContext => ({
  workspace: ws,
  caller: { actor, policy: actor.type === "agent" ? { type: "agent", autonomy: "autonomous", maxRisk: "active" } : { type: "human" } },
  defaultEngagementId: e.info.id,
  engagement: (id) => (id ? ws.get(id) : e),
  runner: (id) => {
    const key = id ?? e.info.id;
    if (!runners.has(key)) runners.set(key, new ToolRunner(ws.get(key), new ToolRegistry(join(dir, "tools"))));
    return runners.get(key)!;
  },
});

function services(e: Engagement, list: Array<[number, string?, string?]>) {
  const items: IngestItem[] = [{ op: "upsert", kind: "host", key: { ip: "10.0.0.5" }, attributes: { status: "up" }, confidence: 1 }];
  for (const [port, product, version] of list) {
    items.push({
      op: "upsert",
      kind: "service",
      key: { ip: "10.0.0.5", transport: "tcp", port },
      attributes: { state: "open", ...(product ? { product } : {}), ...(version ? { version } : {}) },
      confidence: 1,
    });
  }
  e.ingest({ format: INGEST_FORMAT, source: { parser: "test@0", tool: "test" }, rawIds: [], observedAt: new Date().toISOString(), items }, human);
}

const finding = (e: Engagement, title: string, severity = "high") =>
  executeOperation("finding.create", { title, severity, description: "d", impact: "i", remediation: "r" }, ctx(human, e)) as Promise<{ id: string }>;

describe("photos and differences", () => {
  it("shows what opened, closed, changed version and which findings are new or resolved", async () => {
    services(eng, [[22, "OpenSSH", "8.9"], [80, "nginx", "1.18"]]);
    const old = await finding(eng, "TLS débil");
    await finding(eng, "Listado de directorios", "low");
    await executeOperation("finding.set_status", { id: old.id, status: "reported" }, ctx(human));
    await executeOperation("snapshot.create", { label: "enero" }, ctx(agent));

    eng.ingest({ format: INGEST_FORMAT, source: { parser: "t@0", tool: "t" }, rawIds: [], observedAt: new Date().toISOString(), items: [
      { op: "upsert", kind: "service", key: { ip: "10.0.0.5", transport: "tcp", port: 80 }, attributes: { state: "closed" }, confidence: 1 },
    ] }, human);
    services(eng, [[22, "OpenSSH", "9.6"], [3306, "MySQL"]]);
    await executeOperation("finding.set_status", { id: old.id, status: "fixed" }, ctx(human));
    await finding(eng, "MySQL expuesto a internet", "critical");

    const d = (await executeOperation("snapshot.diff", {}, ctx(agent))) as SnapshotDiff;
    expect(d.from.label).toBe("enero");
    expect(d.services.added).toEqual(["default|10.0.0.5|tcp|3306"]);
    expect(d.services.removed).toEqual(["default|10.0.0.5|tcp|80"]);
    expect(d.services.changed).toEqual([{ key: "default|10.0.0.5|tcp|22", before: "OpenSSH 8.9", after: "OpenSSH 9.6" }]);
    expect(d.findings.new.map((f) => f.title)).toEqual(["MySQL expuesto a internet"]);
    expect(d.findings.resolved.map((f) => f.title)).toEqual(["TLS débil"]);
    expect(d.findings.persisting.map((f) => f.title)).toEqual(["Listado de directorios"]);
  });

  it("asks for a photo when there is nothing to compare with", async () => {
    await expect(executeOperation("snapshot.diff", {}, ctx(human))).rejects.toMatchObject({ code: "VALIDATION_ERROR" });
  });
});

describe("retest", () => {
  it("creates a retest with the same scope and the reported findings to verify, compared with the original", async () => {
    const a = await finding(eng, "SQL injection en /login", "critical");
    const b = await finding(eng, "Cookies sin Secure", "low");
    await finding(eng, "Borrador sin terminar"); // drafts are not part of the deliverable
    for (const f of [a, b]) await executeOperation("finding.set_status", { id: f.id, status: "reported" }, ctx(human));

    await expect(executeOperation("engagement.retest", { sourceEngagementId: eng.info.id }, ctx(agent))).rejects.toMatchObject({ code: "PERMISSION_DENIED" });
    const r = (await executeOperation("engagement.retest", { sourceEngagementId: eng.info.id }, ctx(human))) as { id: string; mode: string; roundMode: string; findingsToVerify: number; previousEngagementId: string };
    expect(r).toMatchObject({ mode: "web", roundMode: "retest", findingsToVerify: 2, previousEngagementId: eng.info.id });

    const retest = ws.get(r.id);
    expect(retest.scopeRules()).toHaveLength(1);
    const copies = retest.query({ kind: "finding" });
    expect(copies.every((f) => f.tags.includes("retest") && f.attributes.status === "reported")).toBe(true);

    const sqli = copies.find((f) => f.attributes.title === "SQL injection en /login")!;
    await executeOperation("finding.set_status", { id: sqli.id, status: "fixed" }, ctx(human, retest));
    const d = (await executeOperation("snapshot.diff", {}, ctx(human, retest))) as SnapshotDiff;
    expect(d.findings.resolved.map((f) => f.title)).toEqual(["SQL injection en /login"]);
    expect(d.findings.persisting.map((f) => f.title)).toEqual(["Cookies sin Secure"]);
    expect(d.findings.new).toEqual([]);
  });
});

describe("scheduled scans", () => {
  it("runs when due, inside the scope, and records what changed", async () => {
    const tool = join(dir, "fakescan");
    writeFileSync(tool, "#!/bin/sh\necho scanned $2\n");
    chmodSync(tool, 0o755);
    ctx(human).runner().registry.save({ name: "fakescan", description: "scan", binaries: [tool], risk: "active", targets: { flags: ["-t"] } });

    await expect(executeOperation("schedule.create", { label: "x", argv: ["fakescan"], targets: [], risk: "active", everyHours: 24 }, ctx(agent))).rejects.toMatchObject({ code: "PERMISSION_DENIED" });
    const s = (await executeOperation("schedule.create", { label: "semanal", argv: ["fakescan", "-t", "10.0.0.5"], targets: [], risk: "active", everyHours: 168 }, ctx(human))) as { id: string; nextAt: string };
    const out = await executeOperation("schedule.create", { label: "fuera", argv: ["fakescan", "-t", "8.8.8.8"], targets: [], risk: "active", everyHours: 24, startNow: true }, ctx(human));
    expect(out).toBeTruthy();

    // Only the out-of-scope one is due now: it is blocked like any other run.
    let done = await runDueSchedules(eng, ctx(human).runner(), { waitSeconds: 5 });
    expect(done.map((d) => [d.label, d.last?.status.startsWith("bloqueado")])).toEqual([["fuera", true]]);

    // A week later the weekly one runs, takes the first photo, and is pushed a week ahead.
    done = await runDueSchedules(eng, ctx(human).runner(), { waitSeconds: 5, now: new Date(Date.parse(s.nextAt) + 1000) });
    const weekly = done.find((d) => d.label === "semanal")!;
    expect(weekly.last).toMatchObject({ status: "finished", headline: "primera foto" });
    const list = (await executeOperation("schedule.list", {}, ctx(agent))) as Array<{ id: string; nextAt: string }>;
    expect(Date.parse(list.find((x) => x.id === s.id)!.nextAt)).toBeGreaterThan(Date.parse(s.nextAt));
    expect(((await executeOperation("snapshot.list", {}, ctx(agent))) as { snapshots: unknown[] }).snapshots).toHaveLength(1);
  });
});
