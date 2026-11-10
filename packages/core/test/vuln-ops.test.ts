import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { Actor } from "@penteos/schema";
import { afterEach, beforeEach, expect, it } from "vitest";
import { type Engagement, executeOperation, type OperationContext, ToolRegistry, ToolRunner, Workspace } from "../src/index.js";
import { __setVulnProviders } from "../src/ops/catalog/vuln.js";
import type { Enricher, Finder } from "../src/vuln/types.js";

/** tech_scan derives technologies from the graph; vuln_lookup matches, ranks and records them. */

const human: Actor = { type: "human", id: "01JA00000000000000000000H1" };
let dir: string;
let ws: Workspace;
let eng: Engagement;

beforeEach(() => {
  dir = mkdtempSync(join(tmpdir(), "penteos-vulnops-"));
  ws = new Workspace(join(dir, "data"));
  eng = ws.create({ clientName: "Lab", name: "Vuln", mode: "web" }, human);
});
afterEach(() => {
  __setVulnProviders(undefined);
  runner = undefined;
  ws.close();
  rmSync(dir, { recursive: true, force: true });
});

let runner: ToolRunner | undefined;
const ctx = (): OperationContext =>
  ({ workspace: ws, caller: { actor: human, policy: { type: "human" } }, defaultEngagementId: eng.info.id, engagement: () => eng, runner: () => (runner ??= new ToolRunner(eng, new ToolRegistry(join(dir, "tools")))) }) as unknown as OperationContext;

function seedWebapp(): void {
  eng.ingest({ format: "penteos.ingest/v0", source: { parser: "test", tool: "test" }, rawIds: [], observedAt: new Date().toISOString(), items: [
    { op: "upsert", kind: "webapp", key: { origin: "https://bloka.test" }, attributes: { origin: "https://bloka.test", technologies: [{ name: "WordPress", version: "6.1", confidence: 0.9 }, { name: "elementor", version: "3.2.0", confidence: 0.8 }] }, confidence: 1 },
  ] } as never, human);
}

it("tech_scan creates one technology per detected product", async () => {
  seedWebapp();
  const r = (await executeOperation("tech.scan", {}, ctx())) as { found: number; technologies: number };
  expect(r.found).toBe(2);
  const list = (await executeOperation("tech.list", {}, ctx())) as { technologies: Array<{ product: string; version: string | null }> };
  expect(list.technologies.map((t) => t.product).sort()).toEqual(["WordPress", "elementor"]);
});

it("vuln_lookup ranks matches and records the top ones as observations on the webapp", async () => {
  seedWebapp();
  // Add the ecosystem so the (fake) finder is asked.
  await executeOperation("tech.add", { where: "https://bloka.test", product: "elementor", version: "3.2.0", ecosystem: "WordPress" }, ctx());
  const finder: Finder = {
    name: "wordfence",
    available: () => true,
    find: async (q) => (q.product === "elementor" ? [
      { id: "CVE-2024-2222", title: "Elementor XSS", cvss: { version: "3.1", score: 8.8 }, source: "wordfence" },
      { id: "CVE-2024-3333", title: "Menor", cvss: { version: "3.1", score: 4.1 }, source: "wordfence" },
    ] : []),
  };
  const kev: Enricher = { name: "kev", enrich: async (ids) => new Map(ids.includes("CVE-2024-2222") ? [["CVE-2024-2222", { kev: true }]] : []) };
  __setVulnProviders(() => ({ finders: [finder], enrichers: [kev] }));

  const r = (await executeOperation("vuln.lookup", {}, ctx())) as { status: string; results: Array<{ product: string; found: number; top: Array<{ id: string; severity: string; kev?: boolean }> }> };
  expect(r.status).toBe("done");
  const ele = r.results.find((x) => x.product === "elementor")!;
  expect(ele.found).toBe(2);
  expect(ele.top[0]!.id).toBe("CVE-2024-2222");
  expect(ele.top[0]!.kev).toBe(true);

  const obs = eng.query({ kind: "observation", limit: 50 }).filter((o) => String(o.attributes.sourceRule) === "vuln:known");
  expect(obs.length).toBe(2);
  const high = obs.find((o) => String(o.attributes.title).includes("CVE-2024-2222"))!;
  expect(high.attributes.severityHint).toBe("high");
  // The observation hangs on the affected web app, not on a dangling technology.
  expect((high.attributes.affects as Array<{ kind: string }>)[0]!.kind).toBe("webapp");
});

it("vuln_lookup with no technologies and no product says so instead of failing", async () => {
  __setVulnProviders(() => ({ finders: [], enrichers: [] }));
  const r = (await executeOperation("vuln.lookup", {}, ctx())) as { status: string };
  expect(r.status).toBe("no_technologies");
});

it("vuln_lookup sets aside a patched match instead of recording it as noise", async () => {
  await executeOperation("tech.add", { where: "https://bloka.test", product: "elementor", version: "3.9.0", ecosystem: "WordPress" }, ctx());
  const finder: Finder = {
    name: "wordfence",
    available: () => true,
    find: async () => [
      { id: "CVE-2024-4444", title: "Vieja, ya parcheada", affected: "fixed in 3.5.0", cvss: { version: "3.1", vector: "AV:N", score: 8 }, source: "wordfence" },
      { id: "CVE-2024-5555", title: "Vigente", cvss: { version: "3.1", vector: "AV:N", score: 7.5 }, source: "wordfence" },
    ],
  };
  __setVulnProviders(() => ({ finders: [finder], enrichers: [] }));
  const r = (await executeOperation("vuln.lookup", {}, ctx())) as { results: Array<{ product: string; recorded: number; setAside?: Array<{ id: string; reason: string }> }> };
  const ele = r.results.find((x) => x.product === "elementor")!;
  expect(ele.recorded).toBe(1);
  expect(ele.setAside?.map((s) => s.id)).toEqual(["CVE-2024-4444"]);
  const obs = eng.query({ kind: "observation", limit: 50 }).filter((o) => String(o.attributes.sourceRule) === "vuln:known");
  expect(obs.map((o) => String(o.attributes.location))).toEqual(["CVE-2024-5555"]);
});

it("vuln_confirm rejects something that is not a CVE id", async () => {
  await expect(executeOperation("vuln.confirm", { cve: "not-a-cve", origin: "https://bloka.test" }, ctx())).rejects.toMatchObject({ code: "VALIDATION_ERROR" });
});

it("vuln_confirm rejects a drafted template that is not a nuclei template", async () => {
  await expect(executeOperation("vuln.confirm", { cve: "CVE-2024-2222", origin: "https://bloka.test", template: "just some free text, not a template at all" }, ctx())).rejects.toMatchObject({ code: "VALIDATION_ERROR" });
});

it("vuln_confirm reports an existing nuclei confirmation without launching a run", async () => {
  seedWebapp();
  eng.ingest({ format: "penteos.ingest/v0", source: { parser: "test", tool: "test" }, rawIds: [], observedAt: new Date().toISOString(), items: [
    { op: "observe", title: "Elementor RCE", sourceRule: "nuclei:cve-2024-2222", affects: [{ kind: "webapp", key: { origin: "https://bloka.test" } }], severityHint: "critical", location: "https://bloka.test/x" },
  ] } as never, human);
  const r = (await executeOperation("vuln.confirm", { cve: "CVE-2024-2222", origin: "https://bloka.test" }, ctx())) as { status: string; by?: string; observation?: string };
  expect(r.status).toBe("confirmed");
  expect(r.by).toBe("nuclei");
  expect(r.observation).toBeTruthy();
});
