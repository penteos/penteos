import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Actor } from "@penteos/schema";
import { afterEach, beforeEach, expect, it } from "vitest";
import { type Engagement, executeOperation, type OperationContext, ToolRegistry, ToolRunner, Workspace } from "../src/index.js";
import { BUILTIN_MANIFESTS } from "../src/tools/builtin-manifests.js";
import { parseWithManifest, validateManifest } from "../src/tools/manifest.js";

/** What a real run showed: a failed edit poisoning a finding, evidence without output, NXDOMAIN in the graph. */

const agent: Actor = { type: "agent", id: "01JA000000000000000000MSTR" };
const human: Actor = { type: "human", id: "01JA00000000000000000000H1" };
let dir: string;
let ws: Workspace;
let eng: Engagement;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "penteos-integrity-"));
  ws = new Workspace(join(dir, "data"));
  eng = ws.create({ clientName: "Lab", name: "Web", mode: "web" }, human);
});
afterEach(() => {
  runner = undefined;
  ws.close();
  rmSync(dir, { recursive: true, force: true });
});

const ctx = (actor: Actor = agent): OperationContext =>
  ({
    workspace: ws,
    caller: { actor, policy: { type: "agent", autonomy: "autonomous", maxRisk: "active" } },
    defaultEngagementId: eng.info.id,
    engagement: () => eng,
    runner: () => (runner ??= new ToolRunner(eng, new ToolRegistry(join(dir, "tools")))),
  }) as unknown as OperationContext;
let runner: ToolRunner | undefined;

async function finding(): Promise<{ id: string; endpoint: string }> {
  eng.ingest({ format: "penteos.ingest/v0", source: { parser: "test", tool: "test" }, rawIds: [], observedAt: new Date().toISOString(), items: [
    { op: "upsert", kind: "webapp", key: { origin: "https://app.lab" }, confidence: 1 },
  ] } as never, human);
  const app = eng.query({ kind: "webapp" })[0]!;
  const f = (await executeOperation("finding.create", { title: "Sin límite de intentos", severity: "medium", instances: [{ entityId: app.id, location: "/login" }] }, ctx())) as { id: string };
  return { id: f.id, endpoint: app.id };
}

it("an edit that does not validate leaves nothing behind", async () => {
  const { id } = await finding();
  expect(() => eng.editEntity(id, { instances: [{ entityId: "x", location: "/y" }] }, human)).toThrow(/invalid finding/);
  // The finding still takes edits: the bad one did not stay half-written.
  await executeOperation("finding.set_status", { id, status: "in_review" }, ctx());
  expect(eng.get(id)!.attributes.status).toBe("in_review");
});

it("agents edit findings only through their own operations, never approving one", async () => {
  const { id } = await finding();
  await expect(executeOperation("entity.edit", { id, fields: { status: "approved" } }, ctx())).rejects.toMatchObject({ code: "PERMISSION_DENIED" });
  expect(eng.get(id)!.attributes.status).toBe("draft");
  await executeOperation("entity.edit", { id, fields: { title: "Editado por una persona" } }, ctx(human));
  expect(eng.get(id)!.attributes.title).toBe("Editado por una persona");
});

it("finding.set_instances takes the creation shape, keeps what stays and never leaves none", async () => {
  const { id, endpoint } = await finding();
  const before = (eng.get(id)!.attributes.instances as Array<{ id: string }>)[0]!.id;
  await executeOperation("finding.set_instances", { id, instances: [{ entityId: endpoint, location: "/login" }, { entityId: endpoint, location: "/forgot-password" }] }, ctx());
  const now = eng.get(id)!.attributes.instances as Array<{ id: string; location: string }>;
  expect(now.map((i) => i.location)).toEqual(["/login", "/forgot-password"]);
  expect(now[0]!.id).toBe(before);
  await expect(executeOperation("finding.set_instances", { id, instances: [] }, ctx())).rejects.toMatchObject({ code: "VALIDATION_ERROR" });
});

it("evidence must point to an output that exists", async () => {
  await expect(executeOperation("evidence.from_raw", { rawId: `sha256:${"a".repeat(64)}`, caption: "x" }, ctx())).rejects.toMatchObject({ code: "NOT_FOUND" });
  const ref = eng.putRaw("HTTP/1.1 200 OK", { type: "http_exchange", mime: "text/plain" });
  const ev = (await executeOperation("evidence.from_raw", { rawId: ref, caption: "respuesta" }, ctx())) as { kind: string };
  expect(ev.kind).toBe("evidence");
});

it("dnsx: names that do not exist never reach the graph", () => {
  const dnsx = validateManifest(BUILTIN_MANIFESTS.find((m) => (m as { name: string }).name === "dnsx"));
  const out = [
    JSON.stringify({ host: "app.lab", status_code: "NOERROR", a: ["10.0.0.5"] }),
    JSON.stringify({ host: "nope.lab", status_code: "NXDOMAIN" }),
  ].join("\n");
  const r = parseWithManifest(dnsx, out, { rawIds: [] });
  const domains = r.batch.items.filter((i) => i.op === "upsert" && i.kind === "domain").map((i) => (i as unknown as { key: { fqdn: string } }).key.fqdn);
  expect(domains).toEqual(["app.lab"]);
});

it("the agent asks to approve findings; the operator approves the ticked ones and the rest stay in review", async () => {
  const a = await finding();
  const b = (await executeOperation("finding.create", { title: "Cabeceras ausentes", severity: "low" }, ctx())) as { id: string };
  await executeOperation("finding.set_status", { id: a.id, status: "in_review" }, ctx());
  const asked = (await executeOperation("finding.request_approval", { ids: [a.id, b.id], reason: "Listos para el informe" }, ctx())) as { status: string; approvalId: string };
  expect(asked.status).toBe("pending_approval");
  const card = runner!.listApprovals().find((x) => x.id === asked.approvalId)!;
  expect(card.request).toMatchObject({ kind: "findings", findings: [{ id: a.id, severity: "medium" }, { id: b.id, severity: "low" }] });
  // An agent cannot decide it.
  await expect(executeOperation("approval.approve", { approvalId: asked.approvalId }, ctx())).rejects.toMatchObject({ code: "PERMISSION_DENIED" });
  const r = (await executeOperation("approval.approve", { approvalId: asked.approvalId, only: [a.id] }, ctx(human))) as { status: string; approved: string[]; left: string[] };
  expect(r).toMatchObject({ status: "findings_approved", approved: [a.id], left: [b.id] });
  expect(eng.get(a.id)!.attributes).toMatchObject({ status: "approved", reviewer: { id: human.id } });
  expect(eng.get(b.id)!.attributes.status).toBe("draft");
});

it("nuclei runs gently unless told otherwise", async () => {
  const { withDefaults } = await import("../src/tools/manifest.js");
  const nuclei = validateManifest(BUILTIN_MANIFESTS.find((m) => (m as { name: string }).name === "nuclei"));
  expect(withDefaults(nuclei, ["-u", "https://a.lab"])).toEqual(["-u", "https://a.lab", "-rl", "20", "-c", "10"]);
  expect(withDefaults(nuclei, ["-u", "https://a.lab", "-rl", "100"])).toEqual(["-u", "https://a.lab", "-rl", "100", "-c", "10"]);
});
