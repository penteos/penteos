import { cpSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { listOutputs, outputDir } from "./outputs.js";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { type Actor, fieldsSchema, INGEST_FORMAT, PluginManifest, renderValue } from "@penteos/schema";
import type { OperationContext } from "../ops/registry.js";
import { Workspace } from "../workspace.js";
import { PluginData } from "./data.js";
import { declarativeActivator } from "./declarative.js";
import { codeActivator } from "./code.js";
import { PluginHost } from "./host.js";
import { PluginRuntime, type StepTrace } from "./runtime.js";
import { PluginSettings } from "./settings.js";
import { PluginTypeRegistry } from "./types.js";

/**
 * A plugin draft, tried for real but in a box: a throwaway data folder
 * with its own host, its own type registry, a lab project with the fixtures asked for, and a fake
 * internet that only answers with the recorded responses given. Nothing leaves the machine,
 * nothing touches the real projects or the real catalog, and everything is deleted afterwards.
 */

export interface RecordedResponse {
  method?: string;
  /** A prefix of the URL ("https://api.example.com/v1/host/"), or a pattern with * wildcards. */
  url: string;
  status?: number;
  body?: unknown;
  headers?: Record<string, string>;
}

export interface SandboxFixtures {
  hosts?: string[];
  domains?: string[];
  webapps?: string[];
  findings?: Array<{ title: string; severity: string; description?: string }>;
}

/** What the result must show for the test to pass (the acceptance criteria, set before building). */
export interface TestExpectations {
  /** Paths in the result that must hold a value ("registrar", "dates.expires", "items[0].ip"). */
  fields?: string[];
  /** Texts the result must contain (anywhere in it). */
  contains?: string[];
  /** Texts it must not contain ("error", "undefined"). */
  absent?: string[];
  /** The test is about a failure path: it passes when the operation fails with a clear message. */
  fails?: boolean;
}

export interface DraftTestInput {
  operation: string;
  /** Against the real services (only the hosts the plugin declares, through Penteos), not recorded answers. */
  live?: boolean;
  expect?: TestExpectations;
  /** May reference the fixtures: "{{fixtures.hosts[0].id}}". */
  input?: Record<string, unknown>;
  /** Setting values; secret ones not given get a fake value. */
  settings?: Record<string, unknown>;
  responses?: RecordedResponse[];
  fixtures?: SandboxFixtures;
}

export interface DraftTestReport {
  ok: boolean;
  operation: string;
  durationMs: number;
  result?: unknown;
  error?: string;
  /** The manifest did not validate: nothing ran. */
  issues?: string[];
  steps: StepTrace[];
  requests: Array<{ method: string; url: string; matched: boolean; status?: number; body?: string }>;
  wrote: {
    entities: Array<{ kind: string; naturalKey: string; attributes: Record<string, unknown> }>;
    annotations: Array<{ entity: string; kind: string; data: Record<string, unknown> }>;
    findings: Array<{ title: string; severity: unknown }>;
  };
  notices: string[];
  fixtures: Record<string, unknown>;
  live: boolean;
  /** Each acceptance criterion and whether the result met it. */
  expectations: Array<{ check: string; ok: boolean }>;
  /** Recorded answers that did not come from a probe of the real service. */
  invented: number;
  /** Files it made (a report, a CSV…), with the start of the text ones to check them. */
  files: Array<{ name: string; size: number; type: string; preview?: string }>;
}

export const SANDBOX_LIMITS = { responses: 50, responseBytes: 512 * 1024, fixtures: 50 } as const;

const tester: Actor = { type: "human", id: "01J00000000000000SANDB0X00" };

function matches(rule: RecordedResponse, method: string, url: string): boolean {
  if (rule.method && rule.method.toUpperCase() !== method) return false;
  if (rule.url.includes("*")) {
    const re = new RegExp(`^${rule.url.split("*").map((p) => p.replace(/[.+?^${}()|[\]\\]/g, "\\$&")).join(".*")}$`);
    return re.test(url);
  }
  return url.startsWith(rule.url);
}

/**
 * `sourceDir`: the plugin's folder, for a code plugin (its files are copied into the sandbox; its
 * code runs isolated as it would installed, with the same fake internet behind the core).
 */
export async function testDraft(
  manifestRaw: unknown,
  test: DraftTestInput,
  options: {
    sourceDir?: string;
    /** Live tests: the real fetch (default: the global one). */
    liveFetch?: typeof fetch;
    /** Live tests: the operator's values for its settings (secrets included; they never leave the core). */
    settings?: Record<string, unknown>;
  } = {},
): Promise<DraftTestReport> {
  const started = Date.now();
  const report: DraftTestReport = { ok: false, operation: test.operation, durationMs: 0, steps: [], requests: [], wrote: { entities: [], annotations: [], findings: [] }, notices: [], fixtures: {}, files: [], live: Boolean(test.live), expectations: [], invented: 0 };
  const parsed = PluginManifest.safeParse(manifestRaw);
  if (!parsed.success) {
    report.issues = parsed.error.issues.map((i) => `${i.path.join(".") || "(manifest)"}: ${i.message}`);
    report.error = "the manifest does not validate: fix it with plugin_draft_write first";
    report.durationMs = Date.now() - started;
    return report;
  }
  const manifest = parsed.data;
  const op = (manifest.contributes.operations ?? []).find((o) => o.name === test.operation);
  if (!op) {
    report.error = `no operation "${test.operation}" (has: ${(manifest.contributes.operations ?? []).map((o) => o.name).join(", ") || "none"})`;
    report.durationMs = Date.now() - started;
    return report;
  }
  const responses = (test.responses ?? []).slice(0, SANDBOX_LIMITS.responses);
  report.invented = responses.filter((r) => !(r as { fromProbe?: string }).fromProbe).length;
  if (test.live && responses.length) report.notices.push("live test: the recorded responses were ignored");
  for (const r of responses) {
    if (JSON.stringify(r.body ?? "").length > SANDBOX_LIMITS.responseBytes) throw new Error(`a recorded response is larger than ${SANDBOX_LIMITS.responseBytes} bytes`);
  }

  const dir = mkdtempSync(join(tmpdir(), "penteos-plugin-sandbox-"));
  let ws: Workspace | undefined;
  // A code plugin's process ends with the sandbox, whatever happened.
  let stopCode = () => {};
  try {
    const types = new PluginTypeRegistry();
    ws = new Workspace(join(dir, "ws"), { pluginTypes: types });
    const workspace = ws;
    const data = new PluginData({ dataDir: dir, globalVault: () => workspace.vault(), types });
    const settings = new PluginSettings(dir, () => workspace.vault());
    // The fake internet: recorded responses only; anything else is reported, never sent.
    // Live: the real internet, recorded; the core still allows only the plugin's own hosts.
    const realFetch = options.liveFetch ?? fetch;
    const liveFetch = (async (input: string | URL | Request, init: RequestInit = {}) => {
      const url = String(input);
      const method = String(init.method ?? "GET").toUpperCase();
      const body = typeof init.body === "string" ? init.body.slice(0, 2000) : undefined;
      try {
        const res = await realFetch(input, init);
        report.requests.push({ method, url, matched: true, status: res.status, ...(body ? { body } : {}) });
        return res;
      } catch (e) {
        report.requests.push({ method, url, matched: false, ...(body ? { body } : {}) });
        throw e;
      }
    }) as typeof fetch;
    const fakeFetch = (async (input: string | URL | Request, init: RequestInit = {}) => {
      const url = String(input);
      const method = String(init.method ?? "GET").toUpperCase();
      const rule = responses.find((r) => matches(r, method, url));
      const body = typeof init.body === "string" ? init.body.slice(0, 2000) : undefined;
      report.requests.push({ method, url, matched: Boolean(rule), ...(rule ? { status: rule.status ?? 200 } : {}), ...(body ? { body } : {}) });
      if (!rule) throw new Error(`no recorded response for ${method} ${url} (add one to "responses")`);
      const text = typeof rule.body === "string" ? rule.body : JSON.stringify(rule.body ?? null);
      return new Response(rule.status === 204 || rule.status === 304 ? null : text, {
        status: rule.status ?? 200,
        headers: { "content-type": typeof rule.body === "string" ? "text/plain" : "application/json", ...(rule.headers ?? {}) },
      });
    }) as typeof fetch;
    const runtime = new PluginRuntime({ data, settings, workspace, fetch: test.live ? liveFetch : fakeFetch, register: false, onStep: (s) => report.steps.push(s) });
    const host = new PluginHost({
      dataDir: dir,
      activators: {
        declarative: declarativeActivator(data, runtime),
        code: codeActivator(data, runtime, { hostDir: join(dir, "plugin-host"), contain: true, onLog: (_id, text) => report.notices.push(`log: ${text}`) }),
      },
      activationBudgetMs: 10_000,
    });
    runtime.bind(host);
    data.bind(host);
    stopCode = () => runtime.detachCode(manifest.id)?.stop();
    const target = join(dir, "plugins", manifest.id);
    if (manifest.level === "code") {
      if (!options.sourceDir) throw new Error("a code plugin is tested from its folder");
      cpSync(options.sourceDir, target, { recursive: true, filter: (src) => !lstatSync(src).isSymbolicLink() && !/[\\/](\.git|node_modules)([\\/]|$)/.test(src) && !src.endsWith(`${"/"}meta.json`) });
    }
    mkdirSync(target, { recursive: true });
    writeFileSync(join(target, "plugin.json"), JSON.stringify(manifestRaw));
    await host.load();
    // Node code is tested isolated: the fake internet must be the only one it can reach. Python runs
    // only free, so a Python test can reach the network if its code goes around penteos.http.
    await host.approve(manifest.id, { reviewedCode: true, trust: manifest.runtime === "python" ? "free" : "isolated" });
    if (manifest.runtime === "python") report.notices.push("python: runs contained by the system in the sandbox (no network, files read-only but its folder); its penteos.http calls get the recorded responses");
    const info = host.get(manifest.id);
    if (info?.status !== "active") {
      report.error = `the plugin did not activate: ${info?.reason?.code ?? info?.status}${info?.reason?.detail ? ` (${info.reason.detail})` : ""}`;
      return report;
    }
    // Settings: what was given, and a fake value for each secret left out.
    const fields = manifest.contributes.settings ?? [];
    const values: Record<string, unknown> = { ...(test.live ? (options.settings ?? {}) : {}), ...(test.settings ?? {}) };
    const missing = fields.filter((f) => f.secret && values[f.name] === undefined);
    if (test.live && missing.length) {
      report.error = `a live test needs the operator's ${missing.map((f) => f.name).join(", ")}: ask for it with plugin_draft_request_setting (never ask for keys in the chat), or test with recorded answers until they give it`;
      return report;
    }
    for (const f of missing) values[f.name] = `test-${f.name}-0000`;
    if (fields.length) settings.update(manifest.id, fields, values);

    const eng = workspace.create({ clientName: "Lab", name: "Plugin sandbox", mode: "web", plugins: [manifest.id] }, tester);
    eng.events.on("change", (e) => {
      if (e.type === "plugin.notify") report.notices.push(`${e.level}: ${e.title}${e.body ? ` - ${e.body}` : ""}`);
    });
    // Fixtures in the lab project.
    const fx = test.fixtures ?? {};
    const count = (fx.hosts?.length ?? 0) + (fx.domains?.length ?? 0) + (fx.webapps?.length ?? 0) + (fx.findings?.length ?? 0);
    if (count > SANDBOX_LIMITS.fixtures) throw new Error(`at most ${SANDBOX_LIMITS.fixtures} fixtures`);
    const items = [
      ...(fx.hosts ?? []).map((ip) => ({ op: "upsert" as const, kind: "host" as const, key: { ip }, attributes: { status: "up" } })),
      ...(fx.domains ?? []).map((fqdn) => ({ op: "upsert" as const, kind: "domain" as const, key: { fqdn } })),
      ...(fx.webapps ?? []).map((origin) => ({ op: "upsert" as const, kind: "webapp" as const, key: { origin } })),
    ];
    if (items.length) eng.ingest({ format: INGEST_FORMAT, source: { parser: "sandbox@1" }, rawIds: [], observedAt: new Date().toISOString(), items }, tester);
    const byKind = (kind: "host" | "domain" | "webapp", field: string) => eng.query({ kind, limit: 500 }).map((e) => ({ id: e.id, [field]: e.attributes[field] }));
    const findings = (fx.findings ?? []).map((f) => {
      const created = eng.createEntity("finding", { title: f.title, severity: f.severity, ...(f.description ? { description: f.description } : {}) }, tester);
      return { id: created.id, title: f.title };
    });
    report.fixtures = { hosts: byKind("host", "ip"), domains: byKind("domain", "fqdn"), webapps: byKind("webapp", "origin"), findings };
    const before = new Set(eng.query({ limit: 100_000 }).map((e) => e.id));

    const ctx = {
      workspace,
      caller: { actor: tester, policy: { type: "human" } },
      defaultEngagementId: eng.info.id,
      engagement: () => eng,
      runner: () => {
        throw new Error("plugins do not use the runner");
      },
      plugins: host,
      pluginData: data,
      pluginRuntime: runtime,
      pluginSettings: settings,
    } as unknown as OperationContext;
    const input = renderValue(test.input ?? {}, { fixtures: report.fixtures }) as Record<string, unknown>;
    const parsedInput = fieldsSchema(op.input).safeParse(input);
    if (!parsedInput.success) {
      report.error = `invalid input: ${parsedInput.error.issues.map((i) => `${i.path.join(".")}: ${i.message}`).join("; ")}`;
      return report;
    }
    let ran = false;
    try {
      report.result = await runtime.run(manifest.id, op, parsedInput.data as Record<string, unknown>, ctx);
      ran = true;
    } catch (e) {
      report.error = e instanceof Error ? e.message : String(e);
    }
    report.expectations = checkExpectations(test.expect, ran, report.result, report.error);
    report.ok = report.expectations.every((x) => x.ok) && (ran || Boolean(test.expect?.fails));
    // What it wrote: its own entities, its annotations, the findings it drafted.
    for (const e of eng.query({ limit: 100_000 })) {
      const ext = eng.annotationOf(e.id, manifest.id);
      if (ext) report.wrote.annotations.push({ entity: e.naturalKey, kind: e.kind, data: ext });
      if (before.has(e.id)) continue;
      if (e.kind === "finding") report.wrote.findings.push({ title: String(e.attributes.title), severity: e.attributes.severity });
      else report.wrote.entities.push({ kind: e.kind, naturalKey: e.naturalKey, attributes: e.attributes });
    }
    report.wrote.entities = report.wrote.entities.slice(0, 50);
    const out = outputDir(eng.dir, manifest.id);
    for (const f of listOutputs(out, 20).files) {
      const text = /^(text\/|application\/(json|xml|yaml))/.test(f.type);
      report.files.push({ ...f, ...(text ? { preview: readFileSync(join(out, ...f.name.split("/"))).subarray(0, 1500).toString("utf8") } : {}) });
    }
    return report;
  } finally {
    report.durationMs = Date.now() - started;
    try {
      stopCode();
      ws?.close();
    } catch {
      /* closing a throwaway workspace */
    }
    rmSync(dir, { recursive: true, force: true });
  }
}

/** Reads `a.b[0].c` from a value. */
function at(value: unknown, path: string): unknown {
  let cur: unknown = value;
  for (const m of path.matchAll(/([^.[\]]+)|\[(\d+)\]/g)) {
    if (cur === null || cur === undefined) return undefined;
    cur = (cur as Record<string | number, unknown>)[(m[1] ?? Number(m[2])) as never];
  }
  return cur;
}

const filled = (v: unknown) => v !== undefined && v !== null && v !== "" && !(Array.isArray(v) && v.length === 0) && !(typeof v === "object" && !Array.isArray(v) && Object.keys(v as object).length === 0);

/** The acceptance criteria against what happened. */
export function checkExpectations(expect: TestExpectations | undefined, ran: boolean, result: unknown, error: string | undefined): Array<{ check: string; ok: boolean }> {
  const out: Array<{ check: string; ok: boolean }> = [];
  if (!expect) return out;
  if (expect.fails) {
    out.push({ check: "fails with a clear message", ok: !ran && Boolean(error && error.length > 12 && !/undefined|null|\[object Object\]|TypeError|Cannot read/i.test(error)) });
    return out;
  }
  const text = JSON.stringify(result ?? null).toLowerCase();
  for (const f of expect.fields ?? []) out.push({ check: `result.${f} has a value`, ok: ran && filled(at(result, f)) });
  for (const c of expect.contains ?? []) out.push({ check: `contains "${c}"`, ok: ran && text.includes(c.toLowerCase()) });
  for (const c of expect.absent ?? []) out.push({ check: `does not contain "${c}"`, ok: ran && !text.includes(c.toLowerCase()) });
  return out;
}
