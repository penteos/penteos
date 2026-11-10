import { createHash } from "node:crypto";
import { appendFileSync, existsSync, lstatSync, mkdirSync, readdirSync, readFileSync, renameSync, rmSync, statSync, writeFileSync } from "node:fs";
import { join, relative } from "node:path";
import { engineSatisfies, PLUGIN_REASONS, PluginManifest, type PluginReasonCode, type PluginText, SUPPORTED_PLUGIN_API_VERSIONS } from "@penteos/schema";

/**
 * The plugin host: the safety net every plugin runs inside.
 *
 * - A plugin folder is never trusted on sight: it loads only once approved, and only while its
 *   files hash to what was approved.
 * - Plugins activate one at a time with a time budget, behind a crash marker: if the app dies
 *   while activating one, the next start knows which one and disables it.
 * - Two starts in a row that never complete put the next one in safe mode (no plugin activates).
 * - At run time every call into a plugin goes through guard(): too many errors, timeouts or
 *   crashes in a window and the plugin disables itself, with the reason kept for the operator.
 * - The app always starts: nothing here throws out of load().
 *
 * Layout: `<dataDir>/plugins/<folder>/plugin.json` holds plugins and nothing else; the host's own
 * files (state, crash marker, logs) live in `<dataDir>/plugin-host/` so they never touch a hash.
 */

/** The Penteos version plugins check their `engine` range against. */
export const PENTEOS_VERSION = "0.1.0";

export type PluginStatus = "active" | "disabled" | "pending" | "invalid" | "incompatible" | "modified" | "slow" | "safe_mode";

export interface PluginReason {
  code: PluginReasonCode;
  /** Technical detail (a schema path, an error message); the sentence comes from the code. */
  detail?: string;
  at: string;
  /** Set by the host on its own, not by the operator. */
  auto: boolean;
}

export interface PluginInfo {
  id: string;
  name: string;
  folder: string;
  status: PluginStatus;
  version?: string;
  level?: "declarative" | "code";
  /** The plugin's own words: one text, or Spanish and English. */
  description?: PluginText;
  author?: { type: "human" | "maestro"; name?: string };
  permissions: string[];
  /** Code plugins: free or isolated. */
  trust?: PluginTrust;
  reason?: PluginReason;
  /** Failures inside the breaker window. */
  health: { errors: number; timeouts: number; crashes: number };
}

export interface PluginNotice {
  id: string;
  name: string;
  code: PluginReasonCode;
  detail?: string;
  at: string;
}

export interface PluginNotices {
  safeMode: boolean;
  /** Safe mode was turned on by the host after starts that never completed. */
  autoSafeMode: boolean;
  /** The host state was unreadable and started over (every plugin needs approval again). */
  stateReset: boolean;
  items: PluginNotice[];
}

/** How a code plugin runs: free (a normal process, watched) or isolated (Node's permissions, no network of its own). */
export type PluginTrust = "free" | "isolated";

export interface LoadedPlugin {
  id: string;
  dir: string;
  manifest: PluginManifest;
  /** Set by the host from what the operator chose (free unless they isolated it). */
  trust?: PluginTrust;
}

/** What turns a valid plugin into running contributions; one per level, provided by later phases. */
export interface PluginActivator {
  activate(plugin: LoadedPlugin): void | Promise<void>;
  deactivate?(id: string): void | Promise<void>;
}

export interface PluginLoadProgress {
  done: number;
  total: number;
  current?: string;
  active: number;
  disabled: number;
  safeMode: boolean;
}

export interface PluginHostOptions {
  dataDir: string;
  safeMode?: boolean;
  activators?: Partial<Record<"declarative" | "code", PluginActivator>>;
  /** Time a plugin has to activate before it is marked slow (ms). */
  activationBudgetMs?: number;
  now?: () => number;
}

/** The breaker: this many failures of one kind inside the window disable the plugin. */
export const BREAKER = { windowMs: 10 * 60_000, errors: 5, timeouts: 3, crashes: 3 } as const;
/** Starts in a row that never completed before the next one goes to safe mode. */
export const FAILED_BOOTS_FOR_SAFE_MODE = 2;
/** A plugin folder larger than this is refused (it is a package, not a data store). */
// Room for a plugin that brings its dependencies (node_modules, a Python package folder).
const MAX_PACKAGE = { files: 20_000, bytes: 300 * 1024 * 1024 };
const MAX_LOG_BYTES = 256 * 1024;
const MAX_NOTICES = 50;

interface PluginRecord {
  enabled: boolean;
  trust?: PluginTrust;
  hash?: string;
  name?: string;
  reason?: PluginReason;
  errors: number[];
  timeouts: number[];
  crashes: number[];
}

interface HostState {
  version: 1;
  plugins: Record<string, PluginRecord>;
  failedBoots: number;
  notices: PluginNotice[];
}

const freshState = (): HostState => ({ version: 1, plugins: {}, failedBoots: 0, notices: [] });

interface Discovered {
  folder: string;
  dir: string;
  plugin?: LoadedPlugin;
  hash?: string;
  error?: { status: "invalid" | "incompatible"; code: PluginReasonCode; detail: string; id?: string; name?: string };
}

class PluginTimeout extends Error {}

function withTimeout<T>(work: Promise<T>, ms: number): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => reject(new PluginTimeout(`no answer after ${ms} ms`)), ms);
    work.then(
      (v) => {
        clearTimeout(timer);
        resolve(v);
      },
      (e: unknown) => {
        clearTimeout(timer);
        reject(e);
      },
    );
  });
}

const message = (e: unknown) => (e instanceof Error ? e.message : String(e)).slice(0, 500);

/** The error a call into an unavailable plugin gets (the plugin is off, failing or unknown). */
export class PluginUnavailableError extends Error {
  readonly code = "PLUGIN_UNAVAILABLE";
  constructor(
    readonly pluginId: string,
    readonly status: PluginStatus | "unknown",
  ) {
    super(`plugin ${pluginId} is not available (${status})`);
  }
}

export class PluginHost {
  readonly pluginsDir: string;
  private readonly hostDir: string;
  private readonly statePath: string;
  private readonly markerPath: string;
  private readonly activators: Partial<Record<"declarative" | "code", PluginActivator>>;
  private readonly budgetMs: number;
  private readonly now: () => number;
  private state: HostState = freshState();
  private readonly infos = new Map<string, PluginInfo>();
  private readonly loaded = new Map<string, Discovered>();
  private readonly listeners = new Set<() => void>();
  private safe: boolean;
  private autoSafe = false;
  private stateReset = false;

  /** Where the host keeps its own files (state, logs, the code runner). */
  get hostDirectory(): string {
    return this.hostDir;
  }

  constructor(options: PluginHostOptions) {
    this.pluginsDir = join(options.dataDir, "plugins");
    this.hostDir = join(options.dataDir, "plugin-host");
    this.statePath = join(this.hostDir, "state.json");
    this.markerPath = join(this.hostDir, "activating.json");
    this.activators = options.activators ?? {};
    this.budgetMs = options.activationBudgetMs ?? 2000;
    this.now = options.now ?? Date.now;
    this.safe = Boolean(options.safeMode);
  }

  get safeMode(): boolean {
    return this.safe;
  }

  /** Called whenever a plugin changes status (the interface refreshes on it). */
  onChange(listener: () => void): () => void {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  // -------------------------------------------------------------------------------------------
  // Start
  // -------------------------------------------------------------------------------------------

  /** Discovers, validates and activates the plugins. Never throws: the app always starts. */
  async load(onProgress?: (p: PluginLoadProgress) => void): Promise<PluginInfo[]> {
    try {
      mkdirSync(this.pluginsDir, { recursive: true });
      mkdirSync(join(this.hostDir, "logs"), { recursive: true });
      this.state = this.readState();
      // Starts that never completed: this one goes in safe mode.
      if (!this.safe && this.state.failedBoots >= FAILED_BOOTS_FOR_SAFE_MODE) {
        this.safe = true;
        this.autoSafe = true;
      }
      this.state.failedBoots++;
      this.save();
      this.blameCrash();
      const found = this.discover();
      const total = found.length;
      let done = 0;
      const progress = (current?: string) =>
        onProgress?.({
          done,
          total,
          ...(current ? { current } : {}),
          active: [...this.infos.values()].filter((i) => i.status === "active").length,
          disabled: [...this.infos.values()].filter((i) => i.status !== "active" && i.status !== "slow").length,
          safeMode: this.safe,
        });
      progress();
      for (const d of found) {
        const name = d.plugin?.manifest.name ?? d.error?.name ?? d.folder;
        progress(name);
        try {
          await this.settle(d);
        } catch (e) {
          // A host bug must not stop the start either: this plugin stays out, the rest go on.
          this.log(d.plugin?.id ?? d.folder, "error", `host error: ${message(e)}`);
        }
        done++;
        progress();
      }
    } catch (e) {
      this.log("host", "error", `plugin host failed to load: ${message(e)}`);
    }
    this.changed();
    return this.list();
  }

  /**
   * Looks at the plugins folder again without restarting (a plugin copied in, updated or removed).
   * Running plugins whose files did not change are left alone; one whose files changed or whose
   * folder is gone is turned off first. Not a start: the safe-mode count is not touched.
   */
  async rescan(): Promise<PluginInfo[]> {
    const before = new Map(this.infos);
    const beforeHash = new Map([...this.loaded].map(([id, d]) => [id, d.hash]));
    const beforeLevel = new Map([...this.loaded].map(([id, d]) => [id, d.plugin?.manifest.level]));
    const running = (id: string) => ["active", "slow"].includes(before.get(id)?.status ?? "");
    try {
      const found = this.discover();
      const seen = new Set(found.map((d) => d.plugin?.id).filter(Boolean) as string[]);
      for (const [id] of before) {
        if (seen.has(id) || !running(id)) continue;
        // Its folder was removed while it ran: stop it (its data stays).
        try {
          const level = beforeLevel.get(id);
          await (level ? this.activators[level] : undefined)?.deactivate?.(id);
        } catch (e) {
          this.log(id, "warn", `deactivate failed: ${message(e)}`);
        }
        this.log(id, "info", "its folder was removed: stopped");
      }
      for (const d of found) {
        const id = d.plugin?.id;
        if (id && running(id) && beforeHash.get(id) === d.hash) {
          this.infos.set(id, before.get(id)!);
          continue;
        }
        if (id && running(id)) {
          try {
            const level = beforeLevel.get(id);
            await (level ? this.activators[level] : undefined)?.deactivate?.(id);
          } catch (e) {
            this.log(id, "warn", `deactivate failed: ${message(e)}`);
          }
        }
        try {
          await this.settle(d);
        } catch (e) {
          this.log(d.plugin?.id ?? d.folder, "error", `host error: ${message(e)}`);
        }
      }
    } catch (e) {
      this.log("host", "error", `rescan failed: ${message(e)}`);
    }
    this.changed();
    return this.list();
  }

  /** The app came up: the start counted as good, so the safe-mode countdown starts over. */
  bootCompleted(): void {
    this.state.failedBoots = 0;
    this.save();
  }

  // -------------------------------------------------------------------------------------------
  // What the operator sees and does
  // -------------------------------------------------------------------------------------------

  list(): PluginInfo[] {
    return [...this.infos.values()].sort((a, b) => a.name.localeCompare(b.name));
  }

  get(id: string): PluginInfo | undefined {
    return this.infos.get(id);
  }

  notices(): PluginNotices {
    return { safeMode: this.safe, autoSafeMode: this.autoSafe, stateReset: this.stateReset, items: [...this.state.notices] };
  }

  dismissNotices(): void {
    this.state.notices = [];
    this.autoSafe = false;
    this.stateReset = false;
    this.save();
    this.changed();
  }

  /** Approves a plugin as it is now (its files are hashed) and activates it. */
  async approve(id: string, options: { reviewedCode?: boolean; trust?: PluginTrust } = {}): Promise<PluginInfo> {
    const d = this.loaded.get(id);
    if (!d?.plugin || !d.hash) throw new Error(`plugin ${id} cannot be approved: it is not valid`);
    // Code runs on this machine: it is approved only by someone who says they read it.
    if (d.plugin.manifest.level === "code" && !options.reviewedCode) throw new Error(`${id} runs code of its own: approve it after reviewing its code (reviewedCode)`);
    this.state.plugins[id] = { enabled: true, hash: d.hash, name: d.plugin.manifest.name, trust: options.trust ?? this.state.plugins[id]?.trust ?? "free", errors: [], timeouts: [], crashes: [] };
    this.save();
    this.log(id, "info", `approved (hash ${d.hash.slice(0, 12)})`);
    await this.settle(d);
    this.changed();
    return this.infos.get(id)!;
  }

  /** Free or isolated: the plugin starts again under the new one. */
  async setTrust(id: string, trust: PluginTrust): Promise<PluginInfo> {
    const d = this.loaded.get(id);
    const record = this.state.plugins[id];
    if (!d?.plugin || !record) throw new Error(`plugin ${id} is not installed and approved`);
    if (d.plugin.manifest.runtime === "python" && trust === "isolated") throw new Error("a Python plugin runs only free");
    record.trust = trust;
    this.save();
    this.log(id, "info", `trust: ${trust}`);
    const info = this.infos.get(id);
    if (info && (info.status === "active" || info.status === "slow")) {
      try {
        await this.activators[d.plugin.manifest.level]?.deactivate?.(id);
      } catch (e) {
        this.log(id, "warn", `deactivate failed: ${message(e)}`);
      }
    }
    await this.settle(d);
    this.changed();
    return this.infos.get(id)!;
  }

  /** Turns a plugin back on: its failure history starts over. */
  async enable(id: string): Promise<PluginInfo> {
    const d = this.loaded.get(id);
    const record = this.state.plugins[id];
    if (!d?.plugin || !record) throw new Error(`plugin ${id} cannot be enabled: it is not installed or not valid`);
    if (record.hash !== d.hash) throw new Error(`plugin ${id} changed since it was approved: approve it again`);
    record.enabled = true;
    delete record.reason;
    record.errors = [];
    record.timeouts = [];
    record.crashes = [];
    this.save();
    this.log(id, "info", "enabled by the operator");
    await this.settle(d);
    this.changed();
    return this.infos.get(id)!;
  }

  async disable(id: string): Promise<PluginInfo> {
    const record = this.state.plugins[id];
    if (!record || !this.infos.has(id)) throw new Error(`plugin ${id} is not installed`);
    await this.turnOff(id, { code: "DISABLED_BY_USER", at: this.iso(), auto: false });
    return this.infos.get(id)!;
  }

  /** The manifest of an installed, valid plugin (whatever its status). */
  manifest(id: string): PluginManifest | undefined {
    return this.loaded.get(id)?.plugin?.manifest;
  }

  /**
   * Turns a running plugin off on the core's own initiative (its database failed to migrate, say),
   * with the reason the operator will read at the next notice. Idempotent.
   */
  async suspend(id: string, code: PluginReasonCode, detail?: string): Promise<void> {
    const info = this.infos.get(id);
    if (!info || info.status === "disabled") return;
    await this.turnOff(id, { code, ...(detail ? { detail: detail.slice(0, 500) } : {}), at: this.iso(), auto: true });
  }

  /**
   * Removes a plugin's package. Its data stays: entities of its types remain in the graph (dormant),
   * its databases stay on disk; installing it again picks them up. Purging data is separate.
   */
  async uninstall(id: string): Promise<{ folder: string }> {
    const info = this.infos.get(id);
    if (!info) throw new Error(`plugin ${id} is not installed`);
    // Invalid plugins can be uninstalled too (that is how a broken one goes away for good).
    const dir = join(this.pluginsDir, info.folder);
    const level = this.loaded.get(id)?.plugin?.manifest.level;
    if (info.status === "active" || info.status === "slow") {
      try {
        await (level ? this.activators[level] : undefined)?.deactivate?.(id);
      } catch (e) {
        this.log(id, "warn", `deactivate failed: ${message(e)}`);
      }
    }
    rmSync(dir, { recursive: true, force: true });
    delete this.state.plugins[id];
    this.state.notices = this.state.notices.filter((n) => n.id !== id);
    this.save();
    this.loaded.delete(id);
    this.infos.delete(id);
    this.log(id, "info", `uninstalled (folder ${info.folder} removed; its data was kept)`);
    this.changed();
    return { folder: info.folder };
  }

  /** The last lines of a plugin's log. */
  logOf(id: string, lines = 100): string[] {
    const path = this.logPath(id);
    if (!existsSync(path)) return [];
    return readFileSync(path, "utf8").split("\n").filter(Boolean).slice(-lines);
  }

  // -------------------------------------------------------------------------------------------
  // Run time
  // -------------------------------------------------------------------------------------------

  /**
   * Every call into a plugin goes through here: it refuses an unavailable plugin, bounds the time,
   * and counts failures toward the breaker. The caller gets the plugin's error back unchanged.
   */
  async guard<T>(id: string, work: () => T | Promise<T>, timeoutMs = 30_000): Promise<T> {
    const info = this.infos.get(id);
    if (!info || info.status !== "active") throw new PluginUnavailableError(id, info?.status ?? "unknown");
    try {
      return await withTimeout(Promise.resolve().then(work), timeoutMs);
    } catch (e) {
      // The caller's mistake (bad input, a missing entity, a plugin's own "fail" rule) is not the
      // plugin failing: it does not count toward the breaker.
      if ((e as { pluginFault?: boolean } | null)?.pluginFault === false) throw e;
      if (e instanceof PluginTimeout || (e as { pluginTimeout?: boolean } | null)?.pluginTimeout) this.recordFailure(id, "timeouts", message(e));
      else this.recordFailure(id, "errors", message(e));
      throw e;
    }
  }

  /** A line in a plugin's log from whoever runs it (what a code plugin logs). */
  note(id: string, text: string): void {
    this.log(id, "info", text.slice(0, 2000));
  }

  /** A plugin's process died or its interface crashed (reported by whoever runs it). */
  recordCrash(id: string, detail: string): void {
    this.recordFailure(id, "crashes", detail);
  }

  // -------------------------------------------------------------------------------------------
  // Inside
  // -------------------------------------------------------------------------------------------

  /** Decides one discovered plugin's status, activating it if it may run. */
  private async settle(d: Discovered): Promise<void> {
    if (d.error) {
      const id = d.error.id ?? `folder:${d.folder}`;
      const was = d.error.id ? this.state.plugins[d.error.id] : undefined;
      this.setInfo(id, {
        name: d.error.name ?? d.folder,
        folder: d.folder,
        status: d.error.status,
        permissions: [],
        reason: { code: d.error.code, detail: d.error.detail, at: this.iso(), auto: true },
      });
      this.log(id, "warn", `${d.error.code}: ${d.error.detail}`);
      // It used to run: say why it no longer does - once, it stays off until fixed and enabled.
      if (was?.enabled) {
        was.enabled = false;
        was.reason = { code: d.error.code, detail: d.error.detail, at: this.iso(), auto: true };
        this.save();
        this.notice(id, d.error.name ?? d.folder, d.error.code, d.error.detail);
      }
      return;
    }
    const plugin = d.plugin!;
    const m = plugin.manifest;
    const base = {
      name: m.name,
      folder: d.folder,
      version: m.version,
      level: m.level,
      ...(m.description ? { description: m.description } : {}),
      author: m.author.name ? { type: m.author.type, name: m.author.name } : { type: m.author.type },
      permissions: [...m.permissions],
    } as Omit<PluginInfo, "id" | "status" | "health">;
    const record = this.state.plugins[m.id];
    if (!record) {
      this.setInfo(m.id, { ...base, status: "pending", reason: { code: "NOT_APPROVED", at: this.iso(), auto: true } });
      return;
    }
    if (record.hash !== d.hash) {
      this.setInfo(m.id, { ...base, status: "modified", reason: { code: "MODIFIED", detail: "its files changed since it was approved", at: this.iso(), auto: true } });
      this.log(m.id, "warn", "files changed since approval; not loaded until approved again");
      if (record.enabled) {
        record.enabled = false;
        record.reason = { code: "MODIFIED", detail: "its files changed since it was approved", at: this.iso(), auto: true };
        this.save();
        this.notice(m.id, m.name, "MODIFIED");
      }
      return;
    }
    if (!record.enabled) {
      this.setInfo(m.id, { ...base, status: "disabled", reason: record.reason ?? { code: "DISABLED_BY_USER", at: this.iso(), auto: false } });
      return;
    }
    if (this.safe) {
      this.setInfo(m.id, { ...base, status: "safe_mode", reason: { code: "SAFE_MODE", at: this.iso(), auto: this.autoSafe } });
      return;
    }
    plugin.trust = record.trust ?? "free";
    base.trust = plugin.trust;
    const activator = this.activators[m.level];
    if (!activator) {
      this.setInfo(m.id, { ...base, status: "incompatible", reason: { code: "LEVEL_UNAVAILABLE", detail: `${m.level} plugins are not supported by this version`, at: this.iso(), auto: true } });
      return;
    }
    await this.activate(plugin, activator, base);
  }

  private async activate(plugin: LoadedPlugin, activator: PluginActivator, base: Omit<PluginInfo, "id" | "status" | "health">): Promise<void> {
    const id = plugin.id;
    // The crash marker: written before, removed after. Still there at the next start = culprit.
    writeFileSync(this.markerPath, JSON.stringify({ id, name: plugin.manifest.name, at: this.iso() }));
    let running: Promise<void>;
    try {
      running = Promise.resolve(activator.activate(plugin));
    } catch (e) {
      running = Promise.reject(e);
    }
    try {
      await withTimeout(running, this.budgetMs);
      this.setInfo(id, { ...base, status: "active" });
      this.log(id, "info", `activated (${plugin.manifest.version})`);
    } catch (e) {
      if (e instanceof PluginTimeout) {
        // Slow, not broken: it keeps activating in the background without holding the start.
        this.setInfo(id, { ...base, status: "slow", reason: { code: "ACTIVATION_TIMEOUT", detail: message(e), at: this.iso(), auto: true } });
        this.recordFailure(id, "timeouts", `activation took longer than ${this.budgetMs} ms`);
        running.then(
          () => {
            if (this.infos.get(id)?.status !== "slow") return;
            this.setInfo(id, { ...base, status: "active" });
            this.log(id, "info", "activated late");
            this.changed();
          },
          (err: unknown) => void this.turnOff(id, { code: "ACTIVATION_FAILED", detail: message(err), at: this.iso(), auto: true }),
        );
      } else {
        this.recordFailure(id, "crashes", message(e), false);
        // An activator may say why in a code of its own (its database could not migrate).
        const own = (e as { reasonCode?: unknown })?.reasonCode;
        const code: PluginReasonCode = typeof own === "string" && (PLUGIN_REASONS as readonly string[]).includes(own) ? (own as PluginReasonCode) : "ACTIVATION_FAILED";
        await this.turnOff(id, { code, detail: message(e), at: this.iso(), auto: true });
      }
    } finally {
      rmSync(this.markerPath, { force: true });
    }
  }

  /** Counts a failure; past the breaker threshold the plugin disables itself. */
  private recordFailure(id: string, kind: "errors" | "timeouts" | "crashes", detail: string, trip = true): void {
    const record = this.state.plugins[id];
    if (!record) return;
    const now = this.now();
    record[kind] = [...record[kind].filter((t) => now - t < BREAKER.windowMs), now];
    this.save();
    this.log(id, kind === "errors" ? "warn" : "error", `${kind.slice(0, -1)}: ${detail}`);
    const info = this.infos.get(id);
    if (info) this.setInfo(id, { ...info, health: this.health(record) });
    if (trip && record[kind].length >= BREAKER[kind]) {
      const code: PluginReasonCode = kind === "errors" ? "TOO_MANY_ERRORS" : kind === "timeouts" ? "TOO_MANY_TIMEOUTS" : "TOO_MANY_CRASHES";
      void this.turnOff(id, { code, detail: `${record[kind].length} in ${BREAKER.windowMs / 60_000} min; last: ${detail}`, at: this.iso(), auto: true });
    }
  }

  private async turnOff(id: string, reason: PluginReason): Promise<void> {
    const record = this.state.plugins[id];
    const info = this.infos.get(id);
    if (record) {
      record.enabled = false;
      record.reason = reason;
      this.save();
    }
    if (info) this.setInfo(id, { ...info, status: "disabled", reason });
    const level = this.loaded.get(id)?.plugin?.manifest.level;
    const activator = level ? this.activators[level] : undefined;
    try {
      await activator?.deactivate?.(id);
    } catch (e) {
      this.log(id, "warn", `deactivate failed: ${message(e)}`);
    }
    this.log(id, reason.auto ? "error" : "info", `disabled: ${reason.code}${reason.detail ? ` (${reason.detail})` : ""}`);
    if (reason.auto) this.notice(id, info?.name ?? record?.name ?? id, reason.code, reason.detail);
    this.changed();
  }

  /** A marker left by the previous start: that plugin was activating when the app stopped. */
  private blameCrash(): void {
    if (!existsSync(this.markerPath)) return;
    let marker: { id?: string; name?: string; at?: string } = {};
    try {
      marker = JSON.parse(readFileSync(this.markerPath, "utf8")) as typeof marker;
    } catch {
      /* unreadable marker: nothing to blame */
    }
    rmSync(this.markerPath, { force: true });
    const id = marker.id;
    const record = id ? this.state.plugins[id] : undefined;
    if (!id || !record) return;
    // The sentence comes from the code; the detail only adds when it happened.
    const reason: PluginReason = { code: "CRASH_ON_ACTIVATE", ...(marker.at ? { detail: marker.at } : {}), at: this.iso(), auto: true };
    record.enabled = false;
    record.reason = reason;
    record.crashes = [...record.crashes, this.now()];
    this.save();
    this.log(id, "error", `disabled: CRASH_ON_ACTIVATE`);
    this.notice(id, marker.name ?? record.name ?? id, "CRASH_ON_ACTIVATE", reason.detail);
  }

  private discover(): Discovered[] {
    this.loaded.clear();
    this.infos.clear();
    const folders = readdirSync(this.pluginsDir, { withFileTypes: true })
      .filter((e) => e.isDirectory() && !e.name.startsWith("."))
      .map((e) => e.name)
      .sort();
    const seen = new Set<string>();
    const out: Discovered[] = [];
    for (const folder of folders) {
      const dir = join(this.pluginsDir, folder);
      const d = this.inspect(folder, dir);
      const id = d.plugin?.id;
      if (id && seen.has(id)) {
        out.push({ folder, dir, error: { status: "invalid", code: "DUPLICATE_ID", detail: `another folder already holds ${id}`, name: d.plugin!.manifest.name } });
        continue;
      }
      if (id) {
        seen.add(id);
        this.loaded.set(id, d);
      }
      out.push(d);
    }
    return out;
  }

  private inspect(folder: string, dir: string): Discovered {
    const manifestPath = join(dir, "plugin.json");
    if (!existsSync(manifestPath)) return { folder, dir, error: { status: "invalid", code: "INVALID_MANIFEST", detail: "plugin.json is missing" } };
    let raw: unknown;
    try {
      raw = JSON.parse(readFileSync(manifestPath, "utf8"));
    } catch (e) {
      return { folder, dir, error: { status: "invalid", code: "INVALID_JSON", detail: message(e) } };
    }
    const hint = raw && typeof raw === "object" ? (raw as { id?: unknown; name?: unknown }) : {};
    const name = typeof hint.name === "string" ? hint.name.slice(0, 80) : undefined;
    const parsed = PluginManifest.safeParse(raw);
    if (!parsed.success) {
      const issue = parsed.error.issues[0];
      const detail = issue ? `${issue.path.join(".") || "(root)"}: ${issue.message}` : "invalid manifest";
      return { folder, dir, error: { status: "invalid", code: "INVALID_MANIFEST", detail, ...(name ? { name } : {}) } };
    }
    const manifest = parsed.data;
    const ids = { id: manifest.id, name: manifest.name };
    if (!SUPPORTED_PLUGIN_API_VERSIONS.includes(manifest.apiVersion)) {
      return { folder, dir, error: { status: "incompatible", code: "INCOMPATIBLE_API", detail: `apiVersion ${manifest.apiVersion}; supported: ${SUPPORTED_PLUGIN_API_VERSIONS.join(", ")}`, ...ids } };
    }
    if (!engineSatisfies(manifest.engine, PENTEOS_VERSION)) {
      return { folder, dir, error: { status: "incompatible", code: "INCOMPATIBLE_ENGINE", detail: `needs Penteos ${manifest.engine}; this is ${PENTEOS_VERSION}`, ...ids } };
    }
    let hash: string;
    try {
      hash = this.hashPackage(dir);
    } catch (e) {
      return { folder, dir, error: { status: "invalid", code: "INVALID_PACKAGE", detail: message(e), ...ids } };
    }
    return { folder, dir, hash, plugin: { id: manifest.id, dir, manifest } };
  }

  /** One hash over every file (path + content). Links are refused: they could point outside. */
  private hashPackage(dir: string): string {
    const files: string[] = [];
    let bytes = 0;
    const walk = (at: string) => {
      for (const name of readdirSync(at).sort()) {
        const path = join(at, name);
        const st = lstatSync(path);
        if (st.isSymbolicLink()) throw new Error(`links are not allowed: ${relative(dir, path)}`);
        // Bytecode caches are not part of a plugin (Python is told never to read them from here).
        if (st.isDirectory() && name === "__pycache__") continue;
        if (st.isDirectory()) walk(path);
        else if (st.isFile()) {
          files.push(path);
          bytes += st.size;
          if (files.length > MAX_PACKAGE.files) throw new Error(`more than ${MAX_PACKAGE.files} files`);
          if (bytes > MAX_PACKAGE.bytes) throw new Error(`larger than ${MAX_PACKAGE.bytes / 1024 / 1024} MB`);
        }
      }
    };
    walk(dir);
    const h = createHash("sha256");
    for (const path of files) {
      h.update(relative(dir, path).split("\\").join("/"));
      h.update("\0");
      h.update(readFileSync(path));
      h.update("\0");
    }
    return h.digest("hex");
  }

  private readState(): HostState {
    if (!existsSync(this.statePath)) return freshState();
    try {
      const s = JSON.parse(readFileSync(this.statePath, "utf8")) as HostState;
      if (s?.version !== 1 || typeof s.plugins !== "object" || !Array.isArray(s.notices)) throw new Error("unexpected shape");
      for (const r of Object.values(s.plugins)) {
        r.errors ??= [];
        r.timeouts ??= [];
        r.crashes ??= [];
      }
      s.failedBoots = Number.isFinite(s.failedBoots) ? s.failedBoots : 0;
      return s;
    } catch (e) {
      // Unreadable state: keep a copy and start over. Every plugin needs approval again - the
      // safe default, since what was approved can no longer be known.
      try {
        renameSync(this.statePath, `${this.statePath}.corrupt-${this.now()}`);
      } catch {
        /* keep going */
      }
      this.stateReset = true;
      this.log("host", "error", `state unreadable, started over: ${message(e)}`);
      return freshState();
    }
  }

  private save(): void {
    try {
      mkdirSync(this.hostDir, { recursive: true });
      const tmp = `${this.statePath}.tmp`;
      writeFileSync(tmp, JSON.stringify(this.state, null, 2));
      renameSync(tmp, this.statePath);
    } catch (e) {
      // Losing state is bad but must not take the app down.
      this.log("host", "error", `could not save state: ${message(e)}`);
    }
  }

  private notice(id: string, name: string, code: PluginReasonCode, detail?: string): void {
    this.state.notices = [...this.state.notices.filter((n) => !(n.id === id && n.code === code)), { id, name, code, ...(detail ? { detail } : {}), at: this.iso() }].slice(-MAX_NOTICES);
    this.save();
  }

  private setInfo(id: string, info: Omit<PluginInfo, "id" | "health"> & { health?: PluginInfo["health"] }): void {
    const record = this.state.plugins[id];
    this.infos.set(id, { ...info, id, health: info.health ?? (record ? this.health(record) : { errors: 0, timeouts: 0, crashes: 0 }) });
  }

  private health(record: PluginRecord): PluginInfo["health"] {
    const now = this.now();
    const inWindow = (list: number[]) => list.filter((t) => now - t < BREAKER.windowMs).length;
    return { errors: inWindow(record.errors), timeouts: inWindow(record.timeouts), crashes: inWindow(record.crashes) };
  }

  private logPath(id: string): string {
    return join(this.hostDir, "logs", `${id.replace(/[^a-zA-Z0-9._-]/g, "_")}.log`);
  }

  private log(id: string, level: "info" | "warn" | "error", text: string): void {
    try {
      const path = this.logPath(id);
      mkdirSync(join(this.hostDir, "logs"), { recursive: true });
      appendFileSync(path, `${new Date(this.now()).toISOString()} ${level} ${text.replace(/\n/g, " ")}\n`);
      if (statSync(path).size > MAX_LOG_BYTES) {
        const lines = readFileSync(path, "utf8").split("\n");
        writeFileSync(path, lines.slice(Math.floor(lines.length / 2)).join("\n"));
      }
    } catch {
      /* logging never breaks anything */
    }
  }

  private iso(): string {
    return new Date(this.now()).toISOString();
  }

  private changed(): void {
    for (const l of this.listeners) {
      try {
        l();
      } catch {
        /* a listener's problem is not the host's */
      }
    }
  }
}
