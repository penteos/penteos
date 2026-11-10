import { createHash } from "node:crypto";
import { cpSync, existsSync, lstatSync, mkdirSync, readdirSync, readFileSync, renameSync, rmSync, statSync, writeFileSync } from "node:fs";
import { dirname, join, relative, sep } from "node:path";
import { type Actor, manifestHosts, PluginManifest } from "@penteos/schema";
import type { Engagement } from "../engagement.js";
import type { PluginProposal } from "../tools/runner.js";
import type { PluginHost } from "./host.js";
import type { DraftTestReport } from "./sandbox.js";
import { outputName } from "./outputs.js";
import { unifiedDiff } from "./textdiff.js";
import { Prober } from "./probe.js";

/** What a code draft may hold: text files the Maestro writes (no dependencies to install). */
export const DRAFT_FILE_LIMITS = { files: 40, fileBytes: 256 * 1024, totalBytes: 2 * 1024 * 1024, diffBytes: 60 * 1024 } as const;
const RESERVED = new Set(["plugin.json", "meta.json"]);

/** Every file of a plugin folder but its manifest and the draft's own notes (no links, no installed dependencies). */
function codeFiles(dir: string): string[] {
  const out: string[] = [];
  if (!existsSync(dir)) return out;
  const walk = (d: string) => {
    for (const e of readdirSync(d, { withFileTypes: true })) {
      if (e.name === "node_modules" || e.name === ".git" || e.name === "__pycache__" || e.name.endsWith(".tmp")) continue;
      const path = join(d, e.name);
      if (e.isDirectory()) walk(path);
      else if (e.isFile()) {
        const rel = relative(dir, path).split(sep).join("/");
        if (!RESERVED.has(rel)) out.push(rel);
      }
    }
  };
  walk(dir);
  return out.sort();
}

/**
 * The plugins the Maestro builds, while they are drafts: kept in
 * `<dataDir>/plugin-drafts/<id>/`, outside the plugins folder, so a draft is never loaded. A draft
 * is always `maestro.*`, declarative, authored by the Maestro; it can be proposed only once its
 * current version passed a sandbox test, and the operator's approval installs exactly that version.
 */

export const DRAFT_ID_RE = /^maestro\.[a-z0-9][a-z0-9-]{0,40}$/;

export interface DraftMeta {
  createdAt: string;
  updatedAt: string;
  updatedBy: Actor;
  lastTest?: { hash: string; ok: boolean; at: string; operation: string; steps: number; requests: number; error?: string; live?: boolean };
  /** The last test against the real services that passed: what went in and what came out. */
  lastLive?: { hash: string; at: string; operation: string; input: Record<string, unknown>; sample: string; requests: string[]; checks: string[] };
  proposed?: { hash: string; approvalId: string; at: string };
  /** Settings the Maestro asked the operator for (a key, an account). */
  needs?: Array<{ setting: string; reason: string; at: string }>;
}

export interface DraftView {
  id: string;
  name: string;
  version: string;
  level: "declarative" | "code";
  /** A code draft's files (besides plugin.json). */
  files: Array<{ path: string; size: number }>;
  hash: string;
  valid: boolean;
  issues: string[];
  warnings: string[];
  summary: { permissions: string[]; sendsTo: string[]; operations: string[]; menus: number; events: string[]; entityTypes: string[]; providers: string[] };
  meta: DraftMeta;
  /** The last test was of this exact version and passed. */
  tested: boolean;
  installed?: { version?: string; status: string };
}

function cmpVersion(a: string, b: string): number {
  const p = (v: string) => v.split(/[.-]/).slice(0, 3).map(Number);
  const [x, y] = [p(a), p(b)];
  for (let i = 0; i < 3; i++) if ((x[i] ?? 0) !== (y[i] ?? 0)) return (x[i] ?? 0) - (y[i] ?? 0);
  return 0;
}

export class PluginDrafts {
  readonly dir: string;
  /** What the Maestro saw of real services while building (replayable in tests). */
  readonly prober: Prober;
  /** The real internet for probes and live tests (a fake one in tests). */
  readonly fetch: typeof fetch;

  constructor(
    dataDir: string,
    private readonly host?: PluginHost,
    fetchImpl?: typeof fetch,
  ) {
    this.dir = join(dataDir, "plugin-drafts");
    this.fetch = fetchImpl ?? ((...a: Parameters<typeof fetch>) => fetch(...a));
    this.prober = new Prober(this.fetch);
  }

  private folder(id: string): string {
    if (!DRAFT_ID_RE.test(id)) throw new Error(`a Maestro plugin id looks like maestro.<name> (got ${id})`);
    return join(this.dir, id);
  }

  /**
   * Saves a draft. The Maestro's draft is always maestro.* and authored by it - fixed here whatever
   * the input says (and said back in warnings). It is declarative, or code with its files: `files`
   * adds or replaces files ({ "main.mjs": "…" }), `remove` deletes some. The raw JSON is kept even
   * when it does not validate, so it can be fixed step by step.
   */
  write(raw: unknown, by: Actor, files: Record<string, string> = {}, remove: string[] = []): DraftView {
    if (!raw || typeof raw !== "object" || Array.isArray(raw)) throw new Error("the manifest is a JSON object");
    const m = { ...(raw as Record<string, unknown>) };
    const notes: string[] = [];
    const rawId = typeof m.id === "string" ? m.id.toLowerCase() : "";
    let id = rawId;
    if (!DRAFT_ID_RE.test(id)) {
      const tail = (rawId.split(".").pop() || String(m.name ?? "plugin")).toLowerCase().replace(/[^a-z0-9-]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 40) || "plugin";
      id = `maestro.${tail}`;
      notes.push(`id set to ${id} (plugins built by the Maestro live under maestro.*)`);
    }
    m.id = id;
    m.author = { type: "maestro", name: "Maestro" };
    const code = m.level === "code";
    if (!code) {
      if (m.level !== undefined && m.level !== "declarative") notes.push(`level "${String(m.level)}" is not one: declarative or code`);
      m.level = "declarative";
      delete m.main;
      delete m.runtime;
    } else m.main ??= m.runtime === "python" ? "main.py" : "main.mjs";
    m.apiVersion ??= 1;
    m.version ??= "0.1.0";
    const folder = this.folder(id);
    // The files first: a bad one refuses the whole write, nothing half-saved.
    const writes = Object.entries(files).map(([name, content]) => {
      let path: string;
      try {
        path = outputName(name);
      } catch (e) {
        throw new Error(`file ${name}: ${(e as Error).message}`);
      }
      if (RESERVED.has(path)) throw new Error(`file ${path}: the manifest goes in "manifest", not in files`);
      if (path.split("/").includes("node_modules")) throw new Error(`file ${path}: dependencies are not written by hand; use Node's or Python's own modules`);
      if (typeof content !== "string") throw new Error(`file ${path}: its content is text`);
      if (Buffer.byteLength(content) > DRAFT_FILE_LIMITS.fileBytes) throw new Error(`file ${path} is larger than ${DRAFT_FILE_LIMITS.fileBytes / 1024} KB`);
      return { path, content };
    });
    if ((writes.length || remove.length) && !code) throw new Error("files are for code plugins (level: code)");
    mkdirSync(folder, { recursive: true });
    for (const name of remove) rmSync(join(folder, outputName(name)), { force: true });
    for (const w of writes) {
      mkdirSync(dirname(join(folder, w.path)), { recursive: true });
      writeFileSync(join(folder, w.path), w.content);
    }
    // A declarative draft has no files (one that was code before loses them).
    if (!code) for (const f of codeFiles(folder)) rmSync(join(folder, f), { force: true });
    const present = codeFiles(folder);
    if (present.length > DRAFT_FILE_LIMITS.files) throw new Error(`a draft holds at most ${DRAFT_FILE_LIMITS.files} files`);
    if (present.reduce((n, f) => n + statSync(join(folder, f)).size, 0) > DRAFT_FILE_LIMITS.totalBytes) throw new Error(`a draft's files add up to more than ${DRAFT_FILE_LIMITS.totalBytes / 1048576} MB`);
    const now = new Date().toISOString();
    const previous = this.readMeta(id);
    const tmp = join(folder, "plugin.json.tmp");
    writeFileSync(tmp, `${JSON.stringify(m, null, 2)}\n`);
    renameSync(tmp, join(folder, "plugin.json"));
    this.writeMeta(id, { ...(previous ?? { createdAt: now }), createdAt: previous?.createdAt ?? now, updatedAt: now, updatedBy: by });
    const view = this.view(id)!;
    return { ...view, warnings: [...notes, ...view.warnings] };
  }

  list(): DraftView[] {
    if (!existsSync(this.dir)) return [];
    return readdirSync(this.dir)
      .filter((d) => DRAFT_ID_RE.test(d) && existsSync(join(this.dir, d, "plugin.json")))
      .map((d) => this.view(d)!)
      .sort((a, b) => b.meta.updatedAt.localeCompare(a.meta.updatedAt));
  }

  manifest(id: string): unknown {
    const file = join(this.folder(id), "plugin.json");
    if (!existsSync(file)) throw new Error(`no draft ${id}`);
    return JSON.parse(readFileSync(file, "utf8"));
  }

  /** The fingerprint of the manifest and every file: what is tested is exactly what is proposed and installed. */
  hash(id: string): string {
    const folder = this.folder(id);
    const h = createHash("sha256").update(readFileSync(join(folder, "plugin.json")));
    for (const f of codeFiles(folder)) h.update(`\0${f}\0`).update(readFileSync(join(folder, f)));
    return h.digest("hex");
  }

  /** The folder a code draft is tested from. */
  sourceDir(id: string): string {
    return this.folder(id);
  }

  /** A draft's files with their text (each cut at 64 KB), for the Maestro to read its code back. */
  files(id: string): Array<{ path: string; size: number; text: string }> {
    const folder = this.folder(id);
    return codeFiles(folder).map((path) => {
      const bytes = readFileSync(join(folder, path));
      return { path, size: bytes.length, text: bytes.subarray(0, 64 * 1024).toString("utf8") };
    });
  }

  view(id: string): DraftView | undefined {
    const file = join(this.folder(id), "plugin.json");
    if (!existsSync(file)) return undefined;
    let raw: unknown;
    try {
      raw = JSON.parse(readFileSync(file, "utf8"));
    } catch (e) {
      raw = undefined;
      void e;
    }
    const parsed = PluginManifest.safeParse(raw);
    const r = (raw ?? {}) as Record<string, unknown>;
    const hash = this.hash(id);
    const meta = this.readMeta(id) ?? { createdAt: "", updatedAt: "", updatedBy: { type: "system", id: "unknown" } };
    const installed = this.host?.get(id);
    const warnings: string[] = [];
    let summary: DraftView["summary"] = { permissions: [], sendsTo: [], operations: [], menus: 0, events: [], entityTypes: [], providers: [] };
    if (parsed.success) {
      const c = parsed.data.contributes;
      summary = {
        permissions: parsed.data.permissions,
        sendsTo: manifestHosts(c, parsed.data.permissions),
        operations: (c.operations ?? []).map((o) => `${o.name}${o.actors.includes("agent") ? " (also your tool)" : ""}`),
        menus: (c.menus ?? []).length,
        events: (c.events ?? []).map((e) => `${e.on} → ${e.operation}`),
        entityTypes: (c.entityTypes ?? []).map((t) => `${id}:${t.name}`),
        providers: (c.providers ?? []).map((p) => p.id),
      };
      if (parsed.data.permissions.includes("target")) warnings.push("the target permission is not available to declarative plugins yet");
      if (!(c.operations ?? []).length && !(c.providers ?? []).length) warnings.push("it has no operations or providers: it would do nothing");
      if (installed?.version && cmpVersion(parsed.data.version, installed.version) <= 0) warnings.push(`version ${parsed.data.version} is not above the installed ${installed.version}: raise it before proposing`);
    }
    const files = codeFiles(this.folder(id)).map((path) => ({ path, size: statSync(join(this.folder(id), path)).size }));
    const issues = parsed.success ? [] : raw === undefined ? ["plugin.json is not valid JSON"] : parsed.error.issues.map((i) => `${i.path.join(".") || "(manifest)"}: ${i.message}`);
    if (parsed.success && parsed.data.level === "code" && parsed.data.main && !files.some((f) => f.path === parsed.data.main)) issues.push(`main: there is no file ${parsed.data.main} (write it with files)`);
    return {
      id,
      name: typeof r.name === "string" ? r.name : id,
      version: typeof r.version === "string" ? r.version : "?",
      level: r.level === "code" ? "code" : "declarative",
      files,
      hash,
      valid: parsed.success && issues.length === 0,
      issues,
      warnings,
      summary,
      meta,
      tested: Boolean(meta.lastTest?.ok && meta.lastTest.hash === hash),
      ...(installed ? { installed: { ...(installed.version ? { version: installed.version } : {}), status: installed.status } } : {}),
    };
  }

  recordTest(id: string, hash: string, report: DraftTestReport, input: Record<string, unknown> = {}): void {
    const meta = this.readMeta(id);
    if (!meta) return;
    meta.lastTest = { hash, ok: report.ok, at: new Date().toISOString(), operation: report.operation, steps: report.steps.length, requests: report.requests.length, ...(report.error ? { error: report.error.slice(0, 500) } : {}), live: report.live };
    if (report.live && report.ok) {
      meta.lastLive = {
        hash,
        at: meta.lastTest.at,
        operation: report.operation,
        input,
        sample: (report.error ?? JSON.stringify(report.result ?? null, null, 1)).slice(0, 1200),
        requests: report.requests.slice(0, 10).map((r) => `${r.method} ${r.url} → ${r.status ?? "failed"}`),
        checks: report.expectations.map((x) => x.check),
      };
    }
    this.writeMeta(id, meta);
  }

  /** What the operator's approval card shows; refuses a draft that is not ready. */
  proposal(id: string): PluginProposal {
    const v = this.view(id);
    if (!v) throw new Error(`no draft ${id}`);
    if (!v.valid) throw new Error(`the draft does not validate: ${v.issues.slice(0, 5).join("; ")}`);
    if (v.meta.needs?.length) throw new Error(`it still waits for the operator's ${v.meta.needs.map((n) => n.setting).join(", ")}: once they give it, test it live`);
    if (!v.tested) throw new Error(v.meta.lastTest && v.meta.lastTest.hash === v.hash ? `its last test failed (${v.meta.lastTest.error ?? "see plugin_draft_test"}): fix it and test again` : "test this exact version with plugin_draft_test before proposing it");
    const blocking = v.warnings.filter((w) => /raise it before proposing|not available/.test(w));
    if (blocking.length) throw new Error(blocking.join("; "));
    const meta = v.meta;
    // A plugin that talks to the internet is proposed only once it worked against the real service.
    if (v.summary.sendsTo.length && meta.lastLive?.hash !== v.hash) {
      throw new Error(
        meta.needs?.length
          ? `it still waits for the operator's ${meta.needs.map((n) => n.setting).join(", ")}: once they give it, test it live`
          : "test this exact version against the real service first (plugin_draft_test with live: true, the operator's own example as input, and expect with what the result must show)",
      );
    }
    const m = PluginManifest.parse(this.manifest(id));
    const c = m.contributes;
    return {
      pluginId: id,
      name: m.name,
      version: m.version,
      ...(m.description ? { description: m.description } : {}),
      hash: v.hash,
      ...(v.installed ? { update: { ...(v.installed.version ? { from: v.installed.version } : {}) } } : {}),
      permissions: m.permissions,
      sendsTo: v.summary.sendsTo,
      operations: (c.operations ?? []).map((o) => ({ name: o.name, title: o.title, agent: o.actors.includes("agent") })),
      menus: (c.menus ?? []).length,
      events: v.summary.events,
      entityTypes: v.summary.entityTypes,
      providers: v.summary.providers,
      test: { operation: v.meta.lastTest!.operation, at: v.meta.lastTest!.at, steps: v.meta.lastTest!.steps, requests: v.meta.lastTest!.requests },
      ...(m.level === "code" ? { code: this.codeProposal(id, m.runtime, m.main ?? "") } : {}),
      ...(meta.lastLive?.hash === v.hash ? { live: { operation: meta.lastLive.operation, input: meta.lastLive.input, sample: meta.lastLive.sample, requests: meta.lastLive.requests, checks: meta.lastLive.checks } } : {}),
    };
  }

  /** A code draft's files for the operator to review, and what changed against the installed version. */
  private codeProposal(id: string, runtime: "node" | "python", main: string): NonNullable<PluginProposal["code"]> {
    const files = this.files(id);
    const installedDir = this.host?.get(id) ? join(this.host.pluginsDir, this.host.get(id)!.folder) : undefined;
    let diff: string | undefined;
    if (installedDir && existsSync(installedDir)) {
      const before = new Map(codeFiles(installedDir).map((f) => [f, readFileSync(join(installedDir, f), "utf8")]));
      before.set("plugin.json", readFileSync(join(installedDir, "plugin.json"), "utf8"));
      const after = new Map(files.map((f) => [f.path, f.text]));
      after.set("plugin.json", readFileSync(join(this.folder(id), "plugin.json"), "utf8"));
      const parts = [...new Set([...before.keys(), ...after.keys()])].sort().map((p) => unifiedDiff(p, before.get(p), after.get(p)));
      diff = parts.join("");
      if (diff.length > DRAFT_FILE_LIMITS.diffBytes) diff = `${diff.slice(0, DRAFT_FILE_LIMITS.diffBytes)}\n[…]\n`;
    }
    return {
      runtime,
      main,
      files: files.map((f) => ({ path: f.path, size: f.size, lines: f.text.split("\n").length })),
      ...(diff !== undefined ? { diff } : {}),
    };
  }

  /** The Maestro asks the operator for a setting of the draft (a key, an account): it must be declared. */
  requestSetting(id: string, setting: string, reason: string): { setting: string; label: string; secret: boolean } {
    const m = PluginManifest.safeParse(this.manifest(id));
    const fields = m.success ? (m.data.contributes.settings ?? []) : [];
    const f = fields.find((x) => x.name === setting);
    if (!f) throw new Error(`the draft has no setting "${setting}": declare it in contributes.settings first (secret: true for a key)`);
    const meta = this.readMeta(id);
    if (meta) {
      meta.needs = [...(meta.needs ?? []).filter((n) => n.setting !== setting), { setting, reason: reason.slice(0, 500), at: new Date().toISOString() }];
      this.writeMeta(id, meta);
    }
    const label = typeof f.label === "string" ? f.label : (f.label?.es ?? f.label?.en ?? setting);
    return { setting, label, secret: Boolean(f.secret) };
  }

  /** The operator gave a setting: the request is closed. */
  settingGiven(id: string, settings: string[]): void {
    const meta = this.readMeta(id);
    if (!meta?.needs) return;
    meta.needs = meta.needs.filter((n) => !settings.includes(n.setting));
    this.writeMeta(id, meta);
  }

  /** A draft's declared settings (to fill them before it is installed). */
  settingFields(id: string) {
    const m = PluginManifest.safeParse(this.manifest(id));
    return m.success ? (m.data.contributes.settings ?? []) : [];
  }

  markProposed(id: string, hash: string, approvalId: string): void {
    const meta = this.readMeta(id);
    if (!meta) return;
    meta.proposed = { hash, approvalId, at: new Date().toISOString() };
    this.writeMeta(id, meta);
  }

  /**
   * The operator approved: installs exactly the version that was proposed (a draft edited since is
   * refused), approves it in the host and enables it in this project only.
   */
  async install(proposal: PluginProposal, engagement: Engagement, by: Actor, options: { trust?: "free" | "isolated" } = {}): Promise<{ status: "plugin_installed"; pluginId: string; version: string }> {
    if (!this.host) throw new Error("no plugin host");
    const id = proposal.pluginId;
    if (this.hash(id) !== proposal.hash) throw new Error("the draft changed after it was proposed: the Maestro has to test and propose it again");
    const target = join(this.host.pluginsDir, id);
    const staging = join(this.host.pluginsDir, `.installing-${id}-${Date.now()}`);
    mkdirSync(staging, { recursive: true });
    cpSync(join(this.folder(id), "plugin.json"), join(staging, "plugin.json"));
    for (const f of codeFiles(this.folder(id))) {
      mkdirSync(dirname(join(staging, f)), { recursive: true });
      cpSync(join(this.folder(id), f), join(staging, f));
    }
    rmSync(target, { recursive: true, force: true });
    renameSync(staging, target);
    await this.host.rescan();
    // Code: the operator saw it in the proposal and chose how it runs (isolated unless they freed it;
    // Python only runs free).
    const runtime = proposal.code?.runtime;
    await this.host.approve(id, proposal.code ? { reviewedCode: true, trust: runtime === "python" ? "free" : (options.trust ?? "isolated") } : {});
    const info = this.host.get(id);
    if (info?.status !== "active") throw new Error(`installed but it did not activate: ${info?.reason?.code ?? info?.status}`);
    const current = engagement.info;
    if (!current.plugins.includes(id)) {
      engagement.setInfo({ ...current, plugins: [...current.plugins, id] }, by, "plugin.enable_project");
      engagement.emit({ type: "engagement.updated" });
    }
    engagement.audit(by, "plugin.install_maestro", { plugin: id }, { version: proposal.version, hash: proposal.hash, ...(proposal.code ? { code: true, trust: this.host.get(id)?.trust } : {}) });
    return { status: "plugin_installed", pluginId: id, version: proposal.version };
  }

  /** A new version of an installed Maestro plugin starts from what is installed. */
  fromInstalled(id: string, by: Actor): DraftView {
    if (!this.host) throw new Error("no plugin host");
    const manifest = this.host.manifest(id);
    if (!manifest) throw new Error(`${id} is not installed`);
    if (!DRAFT_ID_RE.test(id)) throw new Error("only plugins built by the Maestro (maestro.*) can be edited as drafts; make a new one instead");
    const dir = join(this.host.pluginsDir, this.host.get(id)!.folder);
    const files = Object.fromEntries(codeFiles(dir).filter((f) => !lstatSync(join(dir, f)).isSymbolicLink()).map((f) => [f, readFileSync(join(dir, f), "utf8")]));
    return this.write(JSON.parse(readFileSync(join(dir, "plugin.json"), "utf8")), by, files);
  }

  remove(id: string): void {
    rmSync(this.folder(id), { recursive: true, force: true });
  }

  private readMeta(id: string): DraftMeta | undefined {
    const file = join(this.folder(id), "meta.json");
    if (!existsSync(file)) return undefined;
    try {
      return JSON.parse(readFileSync(file, "utf8")) as DraftMeta;
    } catch {
      return undefined;
    }
  }

  private writeMeta(id: string, meta: DraftMeta): void {
    writeFileSync(join(this.folder(id), "meta.json"), JSON.stringify(meta, null, 2));
  }
}
