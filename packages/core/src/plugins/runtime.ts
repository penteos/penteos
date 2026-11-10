import {
  type Actor,
  type EachStep,
  fieldsSchema,
  type FieldSpec,
  HTTP_LIMITS,
  netAllows,
  type PluginEvent,
  type PluginManifest,
  type PluginOperation,
  pluginOperationName,
  type PluginStep,
  renderValue,
  type RenderOptions,
  SecretValue,
  TemplateError,
  textOf,
  truthy,
  WRITE_STEPS,
  type PluginFindingTemplate,
  type PluginParser,
  REPORT_SECTION_IDS,
  SEVERITY_LEVELS,
  PLUGIN_EVENTS,
  type PluginProxyHook,
  PluginStepSchema,
  ENTITY_KINDS,
  EVENT_LIMITS,
  manifestHosts,
  httpsHostOf,
} from "@penteos/schema";
import { existsSync, mkdirSync, readFileSync, realpathSync, statSync } from "node:fs";
import { extname, resolve, sep } from "node:path";
import { reportToDocx } from "../docx.js";
import { restore } from "../privacy/vault.js";
import { Branding, type ExtraSection, type ReportSectionId, renderReport } from "../report.js";
import { REPORT_TEXT } from "../report-text.js";
import { z } from "zod";
import type { ChangeEvent, Engagement, Entity } from "../engagement.js";
import { defineOperation, executeOperation, type OperationContext, OperationError, undefineOperation } from "../ops/registry.js";
import type { Workspace } from "../workspace.js";
import type { PluginData } from "./data.js";
import type { LoadedPlugin, PluginHost } from "./host.js";
import type { PluginSettings } from "./settings.js";
import type { CodePluginProcess, Observation } from "./code.js";
import type { EgressEvent } from "./egress.js";
import { detect } from "../privacy/detectors.js";
import type { Where } from "./storage.js";
import { OutputError, outputDir, outputName, readOutput, writeOutput } from "./outputs.js";

/**
 * Runs declarative plugins. A plugin's operations become catalog
 * operations `plugin.<id>.<name>` - so they are forms for people and tools for the Maestro, with
 * the catalog's roles, validation, loop guard and audit - and each call executes its steps here,
 * with the core's own code, inside the host's guard (time limit, breaker).
 *
 * What a plugin can never do, whatever its manifest says (each is checked again at run time):
 *  - talk to a host outside its net: permissions, or over plain http;
 *  - run in a project where it was not enabled, or send data out of a local_only / no_ai project;
 *  - see a secret anywhere but inside the request it is sent with (it is redacted on the way back);
 *  - write to the graph without graph:write, approve a finding, or act on a target;
 *  - run unbounded: steps, requests, loop items, response bytes and time are all capped.
 */

export type PluginAlertKind = "destination" | "client_data";

/** One thing a plugin did that Penteos saw (its card shows them). */
export interface PluginActivity {
  at: string;
  kind: "egress" | "direct" | "process" | "alert";
  severity: "info" | "warn";
  text: string;
  /** For a destination: inside the scope, among its declared hosts, or elsewhere. */
  where?: "target" | "declared" | "elsewhere";
  alert?: PluginAlertKind;
}

export interface PluginRuntimeOptions {
  /** The project the operator has open (for what a free plugin does outside a call). */
  currentEngagementId?: () => string | undefined;
  /** Or bound later with bind() (the host is built with this runtime's activator). */
  host?: PluginHost;
  data: PluginData;
  settings: PluginSettings;
  workspace: Workspace;
  fetch?: typeof fetch;
  /** The context event-triggered calls run in (the server provides it); without it events are ignored. */
  context?: (engagementId: string, actor: Actor) => OperationContext;
  now?: () => number;
  /**
   * false: a sandbox runtime. Its plugins' operations never join the catalog (they are not tools
   * of anyone); they run only through run(). Default true.
   */
  register?: boolean;
  /** Called after each step (a sandbox builds its test report from it). */
  onStep?: (step: StepTrace) => void;
}

/** What one step did, for a test report. */
export interface StepTrace {
  /** "3" or "4.2" (inside a loop). */
  path: string;
  do: string;
  id?: string;
  skipped?: boolean;
  ms: number;
  ok: boolean;
  error?: string;
  /** The step's result, cut short. */
  output?: string;
}

/** Skills: what all plugins together may add to the Maestro's prompt in one project. */
export const SKILL_LIMITS = { total: 24_000 } as const;
/** Proxy hooks: viewing calls at once per plugin, and the most any call may run. */
export const PROXY_LIMITS = { inFlight: 16, hardTimeoutMs: 30_000, bodyBytes: 1024 * 1024 } as const;
const message_ = (e: unknown) => (e instanceof Error ? e.message : String(e));

export const RUN_LIMITS = { steps: 2000, requests: 50, resultBytes: 1024 * 1024, redirects: 3, notifyPerMinute: 10 } as const;

/** The actor a plugin's own writes carry in the graph and the audit chain. */
export const pluginActor = (pluginId: string): Actor => ({ type: "system", id: `plugin:${pluginId}` });

class StepFailure extends Error {
  readonly pluginFault: boolean;
  /** The plugin's own words for the person (a fail step): shown as they are, without "step N". */
  readonly own: boolean;
  constructor(message: string, pluginFault = true, own = false) {
    super(message);
    this.name = "PluginStepError";
    this.pluginFault = pluginFault;
    this.own = own;
  }
}

const message = (e: unknown) => (e instanceof Error ? e.message : String(e));

/** The hosts an operation sends data to (what the operator is told before enabling it). */
function hostsOf(steps: PluginStep[]): string[] {
  const out = new Set<string>();
  const walk = (list: PluginStep[]) => {
    for (const s of list) {
      if (s.do === "http") {
        const h = httpsHostOf(s.url);
        if (h) out.add(h.host);
      }
      if (s.do === "each") walk(s.steps);
    }
  };
  walk(steps);
  return [...out].sort();
}

/**
 * Where an operation can send data. A code operation can reach any host of the plugin's net:
 * permissions (the core enforces that list on every request it makes for it).
 */
function opHosts(manifest: PluginManifest, op: PluginOperation): string[] {
  if (manifest.permissions.includes("net:*")) return ["*"];
  if (op.steps) return hostsOf(op.steps);
  return manifest.permissions.filter((p) => p.startsWith("net:")).map((p) => p.slice(4)).sort();
}

/** Whether an operation can change state; code is assumed to (it is a write for roles and the loop guard). */
function opWrites(op: PluginOperation): boolean {
  return op.steps ? writesState(op.steps) : true;
}

function writesState(steps: PluginStep[]): boolean {
  return steps.some((s) => WRITE_STEPS.has(s.do) || s.do === "http" || (s.do === "each" && writesState(s.steps)));
}

export interface CatalogOperation {
  name: string;
  op: string;
  title: unknown;
  action?: unknown;
  icon?: string;
  description: unknown;
  input: FieldSpec[];
  view?: PluginOperation["view"];
  actors: Array<"human" | "agent">;
  sendsTo: string[];
}

export interface CatalogPlugin {
  id: string;
  name: string;
  version: string;
  author: PluginManifest["author"];
  description?: PluginManifest["description"];
  permissions: string[];
  /** Hosts it sends data to: enabling it in a project lets project data leave to them. */
  sendsTo: string[];
  operations: CatalogOperation[];
  menus: NonNullable<PluginManifest["contributes"]["menus"]>;
  panels: NonNullable<PluginManifest["contributes"]["panels"]>;
  /** Formats it adds to the Deliverable panel. */
  exports: NonNullable<PluginManifest["contributes"]["exports"]>;
  level: PluginManifest["level"];
  trust: "free" | "isolated";
  settings: FieldSpec[];
  providers: Array<{ id: string; label: unknown }>;
  entityTypes: Array<{ kind: string; label: unknown }>;
}

export interface PluginProviderInfo {
  key: string;
  pluginId: string;
  id: string;
  label: string;
  description?: string;
  baseUrl: string;
  models: string[];
  apiKey?: string;
}

export class PluginRuntime {
  private readonly plugins = new Map<string, LoadedPlugin>();
  private readonly fetchImpl: typeof fetch;
  private readonly now: () => number;
  private readonly queues = new Map<string, Promise<void>>();
  private readonly queued = new Map<string, number>();
  private readonly eventTimes = new Map<string, number[]>();
  private readonly notifyTimes = new Map<string, number[]>();
  /** Entities a plugin wrote recently: their change events do not trigger that plugin again. */
  private readonly recentWrites = new Map<string, Map<string, number>>();

  private host: PluginHost | undefined;

  constructor(private readonly options: PluginRuntimeOptions) {
    this.host = options.host;
    this.fetchImpl = options.fetch ?? fetch;
    this.now = options.now ?? Date.now;
    options.workspace.onOpen((engagement) => {
      engagement.events.on("change", (event: ChangeEvent) => this.onChange(engagement, event));
    });
  }

  bind(host: PluginHost): void {
    this.host = host;
  }

  private get hostRef(): PluginHost {
    if (!this.host) throw new OperationError("PLUGIN_UNAVAILABLE", "the plugin host is not ready");
    return this.host;
  }

  // -------------------------------------------------------------------------------------------
  // Registration (called by the declarative activator)
  // -------------------------------------------------------------------------------------------

  register(plugin: LoadedPlugin): void {
    this.unregister(plugin.id);
    const m = plugin.manifest;
    for (const op of this.options.register === false ? [] : (m.contributes.operations ?? [])) {
      const name = pluginOperationName(plugin.id, op.name);
      const hosts = opHosts(m, op);
      const shape = fieldsSchema(op.input).shape;
      defineOperation({
        name,
        title: textOf(op.title, "en"),
        description: `${textOf(op.description, "en")} (Plugin "${m.name}".${hosts.length ? ` Sends data to ${hosts.join(", ")}.` : ""})`,
        kind: opWrites(op) ? "write" : "read",
        actors: op.actors,
        input: z.object({ engagementId: z.string().optional(), ...shape }),
        handler: (input: Record<string, unknown>, ctx: OperationContext) => this.run(plugin.id, op, input, ctx),
      });
    }
    this.plugins.set(plugin.id, plugin);
  }

  unregister(pluginId: string): void {
    const plugin = this.plugins.get(pluginId);
    if (!plugin) return;
    if (this.options.register !== false) for (const op of plugin.manifest.contributes.operations ?? []) undefineOperation(pluginOperationName(pluginId, op.name));
    this.plugins.delete(pluginId);
    this.recentWrites.delete(pluginId);
  }

  isRegistered(pluginId: string): boolean {
    return this.plugins.has(pluginId);
  }

  // -------------------------------------------------------------------------------------------
  // What the interface and the server read
  // -------------------------------------------------------------------------------------------

  /** Every running plugin with what it contributes (the interface localizes the texts). */
  catalog(): CatalogPlugin[] {
    return [...this.plugins.values()]
      .map(({ id, manifest: m }) => {
        const operations = (m.contributes.operations ?? []).map((op) => ({
          name: pluginOperationName(id, op.name),
          op: op.name,
          title: op.title,
          ...(op.action ? { action: op.action } : {}),
          ...(op.icon ? { icon: op.icon } : {}),
          description: op.description,
          input: op.input,
          ...(op.view ? { view: op.view } : {}),
          actors: op.actors,
          sendsTo: opHosts(m, op),
        }));
        return {
          id,
          name: m.name,
          version: m.version,
          author: m.author,
          ...(m.description ? { description: m.description } : {}),
          permissions: m.permissions,
          sendsTo: manifestHosts(m.contributes, m.permissions),
          operations,
          menus: m.contributes.menus ?? [],
          panels: m.contributes.panels ?? [],
          exports: m.contributes.exports ?? [],
          level: m.level,
          trust: this.host?.get(id)?.trust ?? "free",
          settings: m.contributes.settings ?? [],
          providers: (m.contributes.providers ?? []).map((p) => ({ id: p.id, label: p.label })),
          entityTypes: (m.contributes.entityTypes ?? []).map((t) => ({ kind: `${id}:${t.name}`, label: t.label })),
        };
      })
      .sort((a, b) => a.name.localeCompare(b.name));
  }

  /** Finding templates of running plugins, for the library. */
  templates(): Array<PluginFindingTemplate & { plugin: string }> {
    return [...this.plugins.values()].flatMap(({ id, manifest }) => (manifest.contributes.findingTemplates ?? []).map((t) => ({ ...t, plugin: id })));
  }

  /** AI providers of running plugins, with their key resolved (the server builds sessions from these). */
  providers(lang: "es" | "en" = "en"): PluginProviderInfo[] {
    const out: PluginProviderInfo[] = [];
    for (const { id, manifest: m } of this.plugins.values()) {
      const settingsFields = m.contributes.settings ?? [];
      const scope = this.options.settings.scope(id, settingsFields);
      for (const p of m.contributes.providers ?? []) {
        const key = p.apiKey ? scope[p.apiKey] : undefined;
        out.push({
          key: `plugin:${id}:${p.id}`,
          pluginId: id,
          id: p.id,
          label: textOf(p.label, lang),
          ...(p.description ? { description: textOf(p.description, lang) } : {}),
          baseUrl: p.baseUrl,
          models: p.models,
          ...(key instanceof SecretValue ? { apiKey: key.value } : {}),
        });
      }
    }
    return out;
  }

  /** Whether a plugin may run in a project: running, and enabled there by the operator. */
  usableIn(pluginId: string, engagement: Engagement): { ok: true } | { ok: false; reason: string } {
    const info = this.hostRef.get(pluginId);
    if (!info || info.status !== "active" || !this.plugins.has(pluginId)) return { ok: false, reason: `the plugin ${pluginId} is not active (${info?.status ?? "not installed"})` };
    if (!engagement.info.plugins.includes(pluginId)) return { ok: false, reason: `the plugin ${info.name} is not enabled in this project: the operator enables it in Plugins` };
    return { ok: true };
  }

  // -------------------------------------------------------------------------------------------
  // Running an operation
  // -------------------------------------------------------------------------------------------

  async run(pluginId: string, op: PluginOperation, input: Record<string, unknown>, ctx: OperationContext): Promise<unknown> {
    const plugin = this.plugins.get(pluginId);
    if (!plugin) throw new OperationError("PLUGIN_UNAVAILABLE", `the plugin ${pluginId} is not active`);
    const { engagementId, ...fields } = input;
    const engagement = ctx.engagement(engagementId as string | undefined);
    const usable = this.usableIn(pluginId, engagement);
    if (!usable.ok) throw new OperationError("PLUGIN_UNAVAILABLE", usable.reason);
    const hosts = opHosts(plugin.manifest, op);
    const policy = engagement.info.dataPolicy;
    if (hosts.length > 0 && (policy === "local_only" || policy === "no_ai")) {
      throw new OperationError("PERMISSION_DENIED", `this project keeps its data on this machine (data policy ${policy}): ${plugin.manifest.name} would send it to ${hosts.join(", ")}`);
    }
    const exec = new Execution(this, plugin, op, engagement, ctx, fields);
    try {
      if (op.handler) {
        // Code: its process runs the handler; each thing it asks of the core is one step, run
        // here with the same checks as a declarative plugin's. The process enforces the time limit.
        const proc = this.code.get(pluginId);
        if (!proc) throw new OperationError("PLUGIN_UNAVAILABLE", `the plugin ${pluginId} has no running code`);
        const handler = op.handler;
        this.busyIn.set(pluginId, engagement.info.id);
        let output: string | undefined;
        if (proc.isolation === "free") {
          output = outputDir(engagement.dir, pluginId);
          mkdirSync(output, { recursive: true });
        }
        return await this.hostRef.guard(pluginId, () => exec.runCode((step) => proc.call(handler, fields, engagementScope(engagement), op.timeoutMs, step, output)), op.timeoutMs + 5000);
      }
      return await this.hostRef.guard(pluginId, () => exec.run(), op.timeoutMs);
    } catch (e) {
      exec.abort();
      // A plugin the Maestro built failed for a person: the Maestro hears it, to fix it.
      if (ctx.caller.actor.type === "human" && plugin.manifest.author.type === "maestro") {
        try {
          engagement.emit({ type: "plugin.failed", pluginId, name: plugin.manifest.name, operation: op.name, error: message(e).slice(0, 1500), input: fields, ...(e instanceof StepFailure && e.own ? { own: true } : {}) });
        } catch {
          /* telling never breaks the failure itself */
        }
      }
      if (e instanceof OperationError) throw e;
      const fault = (e as { pluginFault?: boolean }).pluginFault;
      const err = new OperationError(e instanceof StepFailure && fault === false ? "VALIDATION_ERROR" : "INTERNAL", `${plugin.manifest.name}: ${message(e)}`);
      Object.assign(err, { pluginFault: fault !== false });
      throw err;
    }
  }

  /** What plugins enabled in a project teach the Maestro there (skills), at most SKILL_LIMITS.total characters. */
  skillsFor(engagement: Engagement): Array<{ plugin: string; title: string; text: string }> {
    const out: Array<{ plugin: string; title: string; text: string }> = [];
    let used = 0;
    const info = engagement.info;
    for (const pluginId of info.plugins) {
      const plugin = this.plugins.get(pluginId);
      if (!plugin || !this.usableIn(pluginId, engagement).ok) continue;
      for (const skill of plugin.manifest.contributes.skills ?? []) {
        if (skill.modes?.length && !skill.modes.includes(info.mode)) continue;
        if (used + skill.text.length > SKILL_LIMITS.total) continue;
        used += skill.text.length;
        out.push({ plugin: plugin.manifest.name, title: textOf(skill.title, info.language ?? "en"), text: skill.text });
      }
    }
    return out;
  }

  /** The proxy hooks of the plugins enabled in a project, for one direction. */
  proxyHooksFor(engagement: Engagement, on: "request" | "response"): Array<{ pluginId: string; hook: PluginProxyHook }> {
    const out: Array<{ pluginId: string; hook: PluginProxyHook }> = [];
    let enabled: string[];
    try {
      enabled = engagement.info.plugins;
    } catch {
      return out;
    }
    for (const pluginId of enabled) {
      const plugin = this.plugins.get(pluginId);
      if (!plugin || !this.code.has(pluginId) || !this.usableIn(pluginId, engagement).ok) continue;
      for (const hook of plugin.manifest.contributes.proxy ?? []) if (hook.on === on) out.push({ pluginId, hook });
    }
    return out;
  }

  private readonly proxyInFlight = new Map<string, number>();

  /**
   * One proxy hook call. A viewing hook goes aside (at most PROXY_LIMITS.inFlight at once per
   * plugin; past that, messages are skipped, never queued against the traffic). A modifying hook is
   * awaited up to its timeout; then the caller goes on unchanged while the call may still finish.
   * Undefined means "unchanged" in every failure.
   */
  async proxyCall(pluginId: string, hook: PluginProxyHook, engagement: Engagement, message: Record<string, unknown>): Promise<unknown> {
    const plugin = this.plugins.get(pluginId);
    const proc = this.code.get(pluginId);
    const ctx = this.options.context?.(engagement.info.id, pluginActor(pluginId));
    if (!plugin || !proc || !ctx) return undefined;
    const busy = this.proxyInFlight.get(pluginId) ?? 0;
    if (!hook.modify && busy >= PROXY_LIMITS.inFlight) return undefined;
    this.proxyInFlight.set(pluginId, busy + 1);
    const op: PluginOperation = { name: `proxy_${hook.id}`, title: hook.id, description: `proxy hook ${hook.id}`, actors: ["human"], input: [], handler: hook.handler, view: { type: "json" }, timeoutMs: PROXY_LIMITS.hardTimeoutMs } as PluginOperation;
    const exec = new Execution(this, plugin, op, engagement, ctx, {});
    const work = this.hostRef
      .guard(pluginId, () => exec.runCode((step) => proc.call(hook.handler, message, engagementScope(engagement), PROXY_LIMITS.hardTimeoutMs, step)), PROXY_LIMITS.hardTimeoutMs + 2000)
      .catch((e: unknown) => {
        this.hostRef.note(pluginId, `proxy hook ${hook.id}: ${message_(e)}`);
        return undefined;
      })
      .finally(() => this.proxyInFlight.set(pluginId, Math.max(0, (this.proxyInFlight.get(pluginId) ?? 1) - 1)));
    if (!hook.modify) return undefined;
    let timer: NodeJS.Timeout | undefined;
    const late = new Promise<undefined>((resolve) => {
      timer = setTimeout(() => {
        this.hostRef.note(pluginId, `proxy hook ${hook.id}: no answer within ${hook.timeoutMs} ms, the message went on unchanged`);
        resolve(undefined);
      }, hook.timeoutMs);
    });
    try {
      return await Promise.race([work, late]);
    } finally {
      clearTimeout(timer);
    }
  }

  /**
   * The sections plugins enabled in a project add to its official deliverable (reportSections):
   * each one's operation runs with no input and returns markdown. One that fails is left out and
   * reported, never breaking the report; one that returns nothing adds no section.
   */
  async reportSections(engagement: Engagement, ctx: OperationContext): Promise<{ sections: ExtraSection[]; problems: Array<{ plugin: string; section: string; error: string }> }> {
    const sections: ExtraSection[] = [];
    const problems: Array<{ plugin: string; section: string; error: string }> = [];
    const info = engagement.info;
    for (const pluginId of info.plugins) {
      const plugin = this.plugins.get(pluginId);
      if (!plugin || !this.usableIn(pluginId, engagement).ok) continue;
      for (const rs of plugin.manifest.contributes.reportSections ?? []) {
        if (rs.modes?.length && !rs.modes.includes(info.mode)) continue;
        const title = textOf(rs.title, info.language ?? "en");
        const op = (plugin.manifest.contributes.operations ?? []).find((o) => o.name === rs.operation);
        try {
          if (!op) throw new Error(`no operation ${rs.operation}`);
          const out = await this.run(pluginId, op, { engagementId: info.id }, ctx);
          const markdown = typeof out === "string" ? out : out && typeof out === "object" && typeof (out as { markdown?: unknown }).markdown === "string" ? (out as { markdown: string }).markdown : undefined;
          if (markdown === undefined) throw new Error("it returned no markdown (a string, or { markdown })");
          if (!markdown.trim()) continue;
          sections.push({ title, markdown: markdown.slice(0, 200_000), ...(rs.after ? { after: rs.after } : {}) });
        } catch (e) {
          problems.push({ plugin: plugin.manifest.name, section: title, error: message(e) });
        }
      }
    }
    return { sections, problems };
  }

  /**
   * The file formats plugins enabled in a project can import, for a file whose start is `head`.
   * Tried only after the built-in formats.
   */
  parsersFor(engagement: Engagement, filename: string, head: string): Array<{ pluginId: string; version: string; parser: PluginParser }> {
    const out: Array<{ pluginId: string; version: string; parser: PluginParser }> = [];
    const lower = filename.toLowerCase();
    for (const id of engagement.info.plugins) {
      const plugin = this.plugins.get(id);
      if (!plugin || this.hostRef.get(id)?.status !== "active") continue;
      for (const parser of plugin.manifest.contributes.parsers ?? []) {
        if (parser.extensions?.length && !parser.extensions.some((x) => lower.endsWith(x))) continue;
        if (head.includes(parser.detect)) out.push({ pluginId: id, version: plugin.manifest.version, parser });
      }
    }
    return out;
  }

  /** Runs a plugin's parser on a file: its code returns ingest items; the caller validates and ingests them. */
  async runParser(pluginId: string, parser: PluginParser, filename: string, text: string, ctx: OperationContext): Promise<unknown> {
    const op = { name: `parser_${parser.id}`, title: parser.title, description: "", actors: ["human", "agent"], input: [], handler: parser.handler, timeoutMs: 60_000 } as unknown as PluginOperation;
    return this.run(pluginId, op, { filename, text }, ctx);
  }

  // -------------------------------------------------------------------------------------------
  // Watching free plugins: what they reach and start. Never blocks: it tells.
  // -------------------------------------------------------------------------------------------

  private readonly activity = new Map<string, PluginActivity[]>();
  private readonly alerted = new Map<string, number>();
  private readonly busyIn = new Map<string, string>();

  /** The project a plugin is working for now (its call's), or the one the operator has open. */
  private engagementFor(pluginId: string): Engagement | undefined {
    const id = this.busyIn.get(pluginId) ?? this.options.currentEngagementId?.();
    if (!id) return undefined;
    try {
      return this.options.workspace.get(id);
    } catch {
      return undefined;
    }
  }

  /** Recent activity of a plugin (newest last), for its card. */
  activityOf(pluginId: string): PluginActivity[] {
    return [...(this.activity.get(pluginId) ?? [])];
  }

  private record(pluginId: string, a: Omit<PluginActivity, "at">): void {
    const list = this.activity.get(pluginId) ?? [];
    list.push({ at: new Date(this.now()).toISOString(), ...a });
    if (list.length > 300) list.splice(0, list.length - 300);
    this.activity.set(pluginId, list);
  }

  /**
   * One destination a plugin reached. Inside the project's scope or among the hosts it named:
   * activity. Anywhere else: an alert (once per host every 10 minutes), with what it is.
   */
  private destination(pluginId: string, host: string, port: number, how: "proxy" | "direct" | "core", body?: Buffer, inEngagement?: Engagement): void {
    const plugin = this.plugins.get(pluginId);
    const engagement = inEngagement ?? this.engagementFor(pluginId);
    const named = plugin ? plugin.manifest.permissions.some((p) => p.startsWith("net:") && p !== "net:*" && netAllows([p], host)) : false;
    let inScope = false;
    try {
      inScope = engagement ? engagement.inScope(host) : false;
    } catch {
      inScope = false;
    }
    const where = inScope ? "target" : named ? "declared" : "elsewhere";
    this.record(pluginId, { kind: how === "direct" ? "direct" : "egress", severity: where === "elsewhere" ? "warn" : "info", text: `${host}:${port}`, where });
    // Requests made by the core are already in the audit chain (plugin.egress), with what left.
    if (engagement && how !== "core") {
      try {
        engagement.audit(pluginActor(pluginId), "plugin.egress_observed", { plugin: pluginId, host, port }, { how, where });
      } catch {
        /* auditing never stops traffic */
      }
    }
    if (where === "elsewhere") this.alert(pluginId, engagement, "destination", host, `${host}:${port}${how === "direct" ? " (direct, around the proxy)" : ""}`);
    // What leaves in clear: the client's data going to someone outside the scope.
    if (body && !inScope) {
      const found = detect(body.toString("utf8"));
      if (found.length) {
        const kinds = [...new Set(found.map((f) => f.type))].slice(0, 5).join(", ");
        this.alert(pluginId, engagement, "client_data", `${host}#data`, `${kinds} → ${host}`);
      }
    }
  }

  private alert(pluginId: string, engagement: Engagement | undefined, kind: PluginAlertKind, key: string, text: string): void {
    const k = `${pluginId}|${kind}|${key}`;
    const last = this.alerted.get(k);
    if (last !== undefined && this.now() - last < 10 * 60_000) return;
    this.alerted.set(k, this.now());
    this.record(pluginId, { kind: "alert", severity: "warn", text, alert: kind });
    const name = this.plugins.get(pluginId)?.manifest.name ?? pluginId;
    engagement?.emit({ type: "plugin.alert", pluginId, pluginName: name, kind, text });
  }

  /** A request the core made for a plugin (penteos.http, an http step). */
  mediated(pluginId: string, engagement: Engagement, url: URL, body: string | undefined): void {
    this.destination(pluginId, url.hostname, Number(url.port) || (url.protocol === "http:" ? 80 : 443), "core", body ? Buffer.from(body) : undefined, engagement);
  }

  /** What the egress proxy saw. */
  egress(e: EgressEvent): void {
    if (!e.pluginId) return;
    this.destination(e.pluginId, e.host, e.port, "proxy", e.body);
  }

  /** What the watcher saw a free plugin's process do. */
  observe(pluginId: string, o: Observation): void {
    if (o.kind === "connection") this.destination(pluginId, o.ip, o.port, "direct");
    else this.record(pluginId, { kind: "process", severity: "info", text: o.command });
  }

  private readonly code = new Map<string, CodePluginProcess>();

  attachCode(pluginId: string, proc: CodePluginProcess): void {
    this.code.set(pluginId, proc);
  }

  detachCode(pluginId: string): CodePluginProcess | undefined {
    const proc = this.code.get(pluginId);
    this.code.delete(pluginId);
    return proc;
  }

  /** How a running code plugin is isolated (the interface shows it). */
  isolationOf(pluginId: string): "free" | "kernel" | "process" | undefined {
    return this.code.get(pluginId)?.isolation;
  }

  /** Tells the operator something, at most RUN_LIMITS.notifyPerMinute times a minute per plugin. */
  notify(plugin: LoadedPlugin, engagement: Engagement, title: string, body: string | undefined, level: "info" | "warn"): boolean {
    if (!this.allow(this.notifyTimes, plugin.id, RUN_LIMITS.notifyPerMinute)) return false;
    engagement.emit({ type: "plugin.notify", pluginId: plugin.id, pluginName: plugin.manifest.name, title: title.slice(0, 200), ...(body ? { body: body.slice(0, 2000) } : {}), level });
    return true;
  }

  wrote(pluginId: string, entityId: string): void {
    let m = this.recentWrites.get(pluginId);
    if (!m) this.recentWrites.set(pluginId, (m = new Map()));
    m.set(entityId, this.now());
    if (m.size > 500) for (const [k, t] of m) if (this.now() - t > 10_000) m.delete(k);
  }

  trace(step: StepTrace): void {
    this.options.onStep?.(step);
  }

  get http(): typeof fetch {
    return this.fetchImpl;
  }

  get data(): PluginData {
    return this.options.data;
  }

  settingsScope(plugin: LoadedPlugin): Record<string, unknown> {
    return this.options.settings.scope(plugin.id, plugin.manifest.contributes.settings ?? []);
  }

  pluginSecrets(plugin: LoadedPlugin): string[] {
    return this.options.settings.secretValues(plugin.id, plugin.manifest.contributes.settings ?? []);
  }

  // -------------------------------------------------------------------------------------------
  // Events
  // -------------------------------------------------------------------------------------------

  private onChange(engagement: Engagement, event: ChangeEvent): void {
    if (!this.options.context || this.plugins.size === 0) return;
    let name: PluginEvent["on"] | undefined;
    let entity: Entity | undefined;
    // What the event says beyond an entity (an OOB interaction, a verdict…).
    let detail: Record<string, unknown> | undefined;
    if (event.type === "entity.created" || event.type === "entity.updated") {
      const verb = event.type === "entity.created" ? "created" : "updated";
      const candidate = `${event.kind}.${verb}`;
      if (!(PLUGIN_EVENTS as readonly string[]).includes(candidate)) return;
      name = candidate as PluginEvent["on"];
    } else if (event.type === "run.finished") name = "run.finished";
    else if (event.type === "scope.changed") name = "scope.changed";
    else if (event.type === "oob.interaction") {
      name = "oob.interaction";
      detail = { protocol: event.protocol, remote: event.remote, tag: event.tag, purpose: event.purpose };
    } else if (event.type === "verification.done") {
      name = "verification.done";
      detail = { findingId: event.findingId, title: event.title, verdict: event.verdict, summary: event.summary };
    } else if (event.type === "host.unreachable") {
      name = "host.unreachable";
      detail = { host: event.host, failures: event.failures, lastOkAt: event.lastOkAt };
    } else if (event.type === "scope.redirect_outside") {
      name = "scope.redirect_outside";
      detail = { from: event.from, to: event.to, host: event.host };
    } else return;
    let enabled: string[];
    try {
      enabled = engagement.info.plugins;
    } catch {
      return;
    }
    for (const pluginId of enabled) {
      const plugin = this.plugins.get(pluginId);
      if (!plugin) continue;
      const handlers = (plugin.manifest.contributes.events ?? []).filter((h) => h.on === name);
      if (handlers.length === 0) continue;
      if (event.type === "entity.created" || event.type === "entity.updated") {
        // Its own writes never trigger it again (no loops through the graph).
        const at = this.recentWrites.get(pluginId)?.get(event.id);
        if (at !== undefined && this.now() - at < 10_000) continue;
        entity ??= engagement.get(event.id);
        if (entity?.createdBy.type === "system" && entity.createdBy.id === `plugin:${pluginId}` && event.type === "entity.created") continue;
      }
      const payload = {
        type: name,
        ...(entity ? { entity: { id: entity.id, kind: entity.kind, naturalKey: entity.naturalKey, attributes: entity.attributes, outOfScope: entity.outOfScope } } : {}),
        ...(event.type === "run.finished" ? { run: { id: event.id } } : {}),
        ...(detail ? { detail } : {}),
      };
      for (const handler of handlers) this.enqueue(plugin, engagement, handler, payload);
    }
  }

  private enqueue(plugin: LoadedPlugin, engagement: Engagement, handler: PluginEvent, payload: Record<string, unknown>): void {
    const id = plugin.id;
    if ((this.queued.get(id) ?? 0) >= EVENT_LIMITS.queue) return;
    this.queued.set(id, (this.queued.get(id) ?? 0) + 1);
    const work = async () => {
      this.queued.set(id, (this.queued.get(id) ?? 1) - 1);
      if (!this.allow(this.eventTimes, id, EVENT_LIMITS.perMinute)) return;
      const scope = { event: payload, engagement: engagementScope(engagement), settings: this.settingsScope(plugin) };
      try {
        if (handler.when && !truthy(renderValue(handler.when, scope))) return;
        const input = handler.input ? (renderValue(handler.input, scope) as Record<string, unknown>) : {};
        const ctx = this.options.context!(engagement.info.id, pluginActor(id));
        await executeOperation(pluginOperationName(id, handler.operation), { ...input, engagementId: engagement.info.id }, ctx);
      } catch {
        /* counted by the host guard; an event handler never breaks the change that triggered it */
      }
    };
    const prev = this.queues.get(id) ?? Promise.resolve();
    const next = prev.then(work, work);
    this.queues.set(id, next);
  }

  /** Waits for every queued event call (tests, shutdown). */
  async idle(): Promise<void> {
    await Promise.all([...this.queues.values()]);
  }

  private allow(times: Map<string, number[]>, id: string, perMinute: number): boolean {
    const now = this.now();
    const recent = (times.get(id) ?? []).filter((t) => now - t < 60_000);
    if (recent.length >= perMinute) {
      times.set(id, recent);
      return false;
    }
    recent.push(now);
    times.set(id, recent);
    return true;
  }
}

function engagementScope(e: Engagement): Record<string, unknown> {
  const info = e.info;
  return { id: info.id, name: info.name, clientName: info.clientName, mode: info.mode, language: info.language };
}

/** An entity as a plugin reads it; `mine` is its own annotation (plugin ids hold dots, so `ext.<id>` is not a path). */
function entityView(e: Entity | undefined, pluginId?: string): Record<string, unknown> | null {
  if (!e) return null;
  const mine = pluginId ? e.ext?.[pluginId] : undefined;
  return { id: e.id, kind: e.kind, naturalKey: e.naturalKey, attributes: e.attributes, outOfScope: e.outOfScope, tags: e.tags, ...(e.ext ? { ext: e.ext } : {}), ...(mine ? { mine } : {}) };
}

/** One call of one operation: its scope, its counters and its deadline. */
class Execution {
  private readonly scope: Record<string, unknown>;
  private readonly steps: Record<string, unknown> = {};
  private readonly vars: Record<string, unknown> = {};
  private executed = 0;
  private requests = 0;
  private readonly controller = new AbortController();
  private readonly actor: Actor;
  private readonly perms: Set<string>;

  constructor(
    private readonly runtime: PluginRuntime,
    private readonly plugin: LoadedPlugin,
    private readonly op: PluginOperation,
    private readonly engagement: Engagement,
    private readonly ctx: OperationContext,
    input: Record<string, unknown>,
  ) {
    this.actor = pluginActor(plugin.id);
    this.perms = new Set(plugin.manifest.permissions);
    this.scope = { input, steps: this.steps, vars: this.vars, engagement: engagementScope(engagement), settings: runtime.settingsScope(plugin) };
  }

  abort(): void {
    this.controller.abort();
  }

  /**
   * Runs a code operation: `call` starts the handler in the plugin's process and gives it a way to
   * ask the core for one step at a time. Steps are validated like a manifest's (no loops or
   * variables: code has its own), and secrets in an http step are filled in here, never there.
   */
  async runCode(call: (step: (raw: unknown) => Promise<unknown>) => Promise<unknown>): Promise<unknown> {
    this.requireSettings();
    const result = await call(async (raw) => {
      if (raw && typeof raw === "object" && (raw as { do?: unknown }).do === "settings") {
        const settings = this.scope.settings as Record<string, unknown>;
        return Object.fromEntries(Object.entries(settings).filter(([, v]) => !(v instanceof SecretValue)));
      }
      const parsed = PluginStepSchema.safeParse(raw);
      if (!parsed.success) throw new StepFailure(`invalid request: ${parsed.error.issues.map((i) => `${i.path.join(".") || "(step)"}: ${i.message}`).join("; ")}`, false);
      const step = parsed.data;
      if (step.do === "each" || step.do === "set" || step.do === "fail") throw new StepFailure(`${step.do} is for manifests; code does that itself`, false);
      if (++this.executed > RUN_LIMITS.steps) throw new StepFailure(`more than ${RUN_LIMITS.steps} steps in one call`);
      const started = Date.now();
      const path = String(this.executed);
      try {
        const out = await this.step(step, this.scope, `${path}.`);
        this.runtime.trace({ path, do: step.do, ms: Date.now() - started, ok: true, output: (JSON.stringify(out) ?? "null").slice(0, 1500) });
        return this.redactOut(out);
      } catch (e) {
        this.runtime.trace({ path, do: step.do, ms: Date.now() - started, ok: false, error: message(e) });
        throw e;
      }
    });
    return this.redactOut(result);
  }

  private requireSettings(): void {
    const settings = this.scope.settings as Record<string, unknown>;
    const missing = (this.plugin.manifest.contributes.settings ?? []).filter((f) => f.required && (settings[f.name] === undefined || settings[f.name] === ""));
    if (missing.length) throw new StepFailure(`set up ${missing.map((f) => f.name).join(", ")} in the plugin's settings first`, false);
  }

  async run(): Promise<unknown> {
    // A plugin that is not configured yet says so, instead of calling its API with nothing.
    this.requireSettings();
    const last = await this.runSteps(this.op.steps ?? [], this.scope, "");
    const result = this.op.result !== undefined ? this.render(this.op.result, this.scope, "result") : last;
    return this.redactOut(result);
  }

  private async runSteps(list: PluginStep[], scope: Record<string, unknown>, prefix: string): Promise<unknown> {
    let last: unknown = null;
    for (const [i, step] of list.entries()) {
      if (this.controller.signal.aborted) throw new StepFailure("stopped");
      const where = `step ${prefix}${i + 1} (${step.do}${step.id ? ` ${step.id}` : ""})`;
      if (++this.executed > RUN_LIMITS.steps) throw new StepFailure(`more than ${RUN_LIMITS.steps} steps in one call`);
      const path = `${prefix}${i + 1}`;
      const started = Date.now();
      if (step.if !== undefined && !truthy(this.render(step.if, scope, where))) {
        this.runtime.trace({ path, do: step.do, ...(step.id ? { id: step.id } : {}), skipped: true, ms: 0, ok: true });
        continue;
      }
      try {
        last = await this.step(step, scope, `${path}.`);
        this.runtime.trace({ path, do: step.do, ...(step.id ? { id: step.id } : {}), ms: Date.now() - started, ok: true, output: (JSON.stringify(last) ?? "null").slice(0, 1500) });
      } catch (e) {
        if (!(e instanceof StepFailure && e.message.startsWith("step "))) {
          this.runtime.trace({ path, do: step.do, ...(step.id ? { id: step.id } : {}), ms: Date.now() - started, ok: false, error: message(e) });
        }
        if (e instanceof StepFailure && (e.message.startsWith("step ") || e.own)) throw e;
        // A missing entity is usually the caller's id, not the plugin failing; everything else
        // (bad data from an API, a template that does not fit) is the plugin's and counts.
        const own = (e as { pluginFault?: boolean }).pluginFault;
        const notFound = (e instanceof OperationError && e.code === "NOT_FOUND") || /not found/i.test(message(e));
        throw new StepFailure(`${where}: ${message(e)}`, own ?? !notFound);
      }
      if (step.id) this.steps[step.id] = last;
    }
    return last;
  }

  private render(value: unknown, scope: Record<string, unknown>, _where: string, opts: RenderOptions = {}): unknown {
    try {
      return renderValue(value, scope, opts);
    } catch (e) {
      if (e instanceof TemplateError) throw new StepFailure(e.message);
      throw e;
    }
  }

  private need(permission: string): void {
    if (!this.perms.has(permission)) throw new StepFailure(`needs the ${permission} permission`);
  }

  private async step(step: PluginStep, scope: Record<string, unknown>, prefix: string): Promise<unknown> {
    const e = this.engagement;
    switch (step.do) {
      case "http":
        return this.http(step, scope);
      case "graph_query": {
        this.need("graph:read");
        const kind = (ENTITY_KINDS as readonly string[]).includes(step.kind) ? step.kind : `${this.plugin.id}:${step.kind}`;
        const text = step.text === undefined ? undefined : String(this.render(step.text, scope, "text") ?? "");
        return e.query({ kind: kind as never, ...(text ? { text } : {}), limit: step.limit }).map((x) => entityView(x.ext ? x : (e.get(x.id) ?? x), this.plugin.id));
      }
      case "graph_get": {
        this.need("graph:read");
        return entityView(e.get(String(this.render(step.entity, scope, "entity"))), this.plugin.id);
      }
      case "put": {
        this.need("graph:write");
        const attributes = this.render(step.attributes, scope, "attributes");
        if (!attributes || typeof attributes !== "object" || Array.isArray(attributes)) throw new StepFailure("attributes must be an object");
        const { entity, created } = e.putPluginEntity(`${this.plugin.id}:${step.type}`, attributes as Record<string, unknown>, this.actor);
        this.runtime.wrote(this.plugin.id, entity.id);
        if (step.relate !== undefined) {
          const to = String(this.render(step.relate, scope, "relate") ?? "");
          if (to) e.relate(entity.id, to, this.actor);
        }
        return { id: entity.id, created, naturalKey: entity.naturalKey };
      }
      case "annotate": {
        this.need("graph:write");
        const id = String(this.render(step.entity, scope, "entity"));
        const data = this.render(step.data, scope, "data");
        if (!data || typeof data !== "object" || Array.isArray(data)) throw new StepFailure("data must be an object");
        const out = e.annotate(id, this.plugin.id, data as Record<string, unknown>, this.actor);
        this.runtime.wrote(this.plugin.id, id);
        return out;
      }
      case "relate": {
        this.need("graph:write");
        const edge = e.relate(String(this.render(step.from, scope, "from")), String(this.render(step.to, scope, "to")), this.actor);
        return { id: edge.id };
      }
      case "store_insert": {
        const store = this.store(step.scope);
        if (step.rows !== undefined) {
          const rows = this.render(step.rows, scope, "rows");
          if (!Array.isArray(rows)) throw new StepFailure("rows must be a list");
          return { inserted: store.insertMany(step.table, rows as Array<Record<string, unknown>>) };
        }
        const row = this.render(step.row, scope, "row");
        return store.insert(step.table, (row ?? {}) as Record<string, unknown>);
      }
      case "store_query": {
        const limit = step.limit === undefined ? undefined : Number(this.render(step.limit, scope, "limit"));
        return this.store(step.scope).query(step.table, {
          ...(step.where !== undefined ? { where: this.render(step.where, scope, "where") as Where } : {}),
          ...(step.orderBy ? { orderBy: step.orderBy } : {}),
          ...(limit !== undefined ? { limit } : {}),
        });
      }
      case "store_update":
        return { updated: this.store(step.scope).updateWhere(step.table, this.render(step.where, scope, "where") as Where, this.render(step.set, scope, "set") as Record<string, unknown>) };
      case "store_delete":
        return { deleted: this.store(step.scope).deleteWhere(step.table, this.render(step.where, scope, "where") as Where) };
      case "finding_draft": {
        this.need("findings:draft");
        const affects = step.affects === undefined ? [] : this.render(step.affects, scope, "affects");
        const ids = (Array.isArray(affects) ? affects : [affects]).filter((x) => typeof x === "string" && x);
        const text = (v: unknown) => (v === undefined ? undefined : String(this.render(v, scope, "text") ?? ""));
        // Through the official operation: same rules, always a draft - only a human approves.
        const created = (await executeOperation(
          "finding.create",
          {
            engagementId: e.info.id,
            title: text(step.title),
            severity: this.render(step.severity, scope, "severity"),
            ...(step.description !== undefined ? { description: text(step.description) } : {}),
            ...(step.impact !== undefined ? { impact: text(step.impact) } : {}),
            ...(step.remediation !== undefined ? { remediation: text(step.remediation) } : {}),
            instances: (ids as string[]).map((entityId) => ({ entityId })),
          },
          { ...this.ctx, caller: { ...this.ctx.caller, actor: this.actor } },
        )) as Entity;
        this.runtime.wrote(this.plugin.id, created.id);
        return { id: created.id, status: "draft" };
      }
      case "notify": {
        this.need("notify");
        const title = String(this.render(step.title, scope, "title") ?? "");
        const body = step.body === undefined ? undefined : String(this.render(step.body, scope, "body") ?? "");
        return { sent: this.runtime.notify(this.plugin, e, title, body, step.level) };
      }
      case "file": {
        this.need("files:write");
        const name = String(this.render(step.name, scope, "name") ?? "");
        const content = this.render(step.content, scope, "content");
        const bytes =
          step.encoding === "base64"
            ? Buffer.from(String(content ?? ""), "base64")
            : Buffer.from(step.encoding === "json" || typeof content !== "string" ? JSON.stringify(content ?? null, null, 2) : content, "utf8");
        try {
          const file = writeOutput(outputDir(e.dir, this.plugin.id), name, bytes);
          e.audit(this.actor, "plugin.file_written", { plugin: this.plugin.id, name: file.name }, { size: file.size, type: file.type });
          return file;
        } catch (err) {
          if (err instanceof OutputError) throw new StepFailure(err.message, false);
          throw err;
        }
      }
      case "report":
        return this.report(step, scope);
      case "set": {
        for (const [k, v] of Object.entries(step.vars)) this.vars[k] = this.render(v, scope, `vars.${k}`);
        return { ...this.vars };
      }
      case "fail":
        throw new StepFailure(String(this.render(step.message, scope, "message") ?? "failed"), false, true);
      case "each":
        return this.each(step, scope, prefix);
    }
  }

  /**
   * The official deliverable with the plugin's choices, saved among its files. The file carries the
   * real values; what the plugin gets back (the markdown) keeps the vault's markers, as anything
   * that may reach the Maestro does.
   */
  private async report(step: Extract<PluginStep, { do: "report" }>, scope: Record<string, unknown>): Promise<unknown> {
    this.need("graph:read");
    this.need("files:write");
    const e = this.engagement;
    const info = e.info;
    const text = (v: string | undefined, where: string) => (v === undefined ? undefined : String(this.render(v, scope, where) ?? "").trim() || undefined);
    const includeDrafts = step.includeDrafts === undefined ? false : truthy(this.render(step.includeDrafts, scope, "includeDrafts"));
    // A section whose text comes out empty (an optional note left blank) is left out.
    const extra = (step.extra ?? [])
      .map((x, i) => ({
        title: text(x.title, `extra.${i}.title`) ?? "-",
        markdown: String(this.render(x.markdown, scope, `extra.${i}.markdown`) ?? ""),
        ...(x.after ? { after: x.after } : {}),
      }))
      .filter((x) => x.markdown.trim());
    const ids = (v: unknown, where: string): ReportSectionId[] | undefined => {
      if (v === undefined) return undefined;
      const r = Array.isArray(v) ? v : this.render(v, scope, where);
      const list = (Array.isArray(r) ? r : String(r ?? "").split(",")).map((x) => String(x).trim()).filter(Boolean);
      const bad = list.filter((x) => !(REPORT_SECTION_IDS as readonly string[]).includes(x));
      if (bad.length) throw new StepFailure(`${where}: unknown sections ${bad.join(", ")} (they are ${REPORT_SECTION_IDS.join(", ")})`, false);
      return list as ReportSectionId[];
    };
    const only = ids(step.sections, "sections");
    const skip = ids(step.skip, "skip");
    const minRaw = step.minSeverity === undefined ? undefined : String(this.render(step.minSeverity, scope, "minSeverity") ?? "").trim();
    if (minRaw && !(SEVERITY_LEVELS as readonly string[]).includes(minRaw)) throw new StepFailure(`minSeverity: "${minRaw}" is not one of ${SEVERITY_LEVELS.join(", ")}`, false);
    const minSeverity = minRaw ? (minRaw as (typeof SEVERITY_LEVELS)[number]) : undefined;
    const title = text(step.title, "title");
    const markdown = renderReport(e, {
      includeDrafts,
      ...(only?.length ? { only } : {}),
      ...(skip?.length ? { skip } : {}),
      ...(minSeverity ? { minSeverity } : {}),
      ...(title ? { title } : {}),
      extra,
    });
    const forPeople = restore(e, markdown).text;
    const T = REPORT_TEXT[info.language ?? "en"];
    const date = new Date().toISOString().slice(0, 10);
    const ext = step.format === "docx" ? ".docx" : ".md";
    let name = text(step.name, "name") ?? `${T.fileName}-${date}${includeDrafts ? `-${T.draftSuffix}` : ""}`;
    if (!name.toLowerCase().endsWith(ext)) name += ext;
    let bytes: Buffer;
    if (step.format === "docx") {
      const color = text(step.color, "color");
      if (color && !/^#[0-9a-fA-F]{6}$/.test(color)) throw new StepFailure(`color must be like #1f6feb, not "${color}"`, false);
      const author = text(step.author, "author");
      const company = text(step.company, "company");
      const confidentiality = text(step.confidentiality, "confidentiality");
      const logoRef = text(step.logo, "logo");
      const parsed = Branding.safeParse({
        ...this.ctx.workspace.branding(),
        ...(author ? { authors: author } : {}),
        ...(company ? { companyName: company } : {}),
        ...(color ? { primaryColor: color } : {}),
        ...(confidentiality ? { confidentiality } : {}),
        ...(logoRef ? { logo: this.logo(logoRef) } : {}),
      });
      if (!parsed.success) throw new StepFailure(`report options: ${parsed.error.issues.map((i) => `${i.path.join(".")}: ${i.message}`).join("; ")}`, false);
      bytes = await reportToDocx(forPeople, parsed.data, { client: info.clientName, engagement: info.name, date, draft: includeDrafts, language: info.language });
    } else bytes = Buffer.from(forPeople, "utf8");
    try {
      const file = writeOutput(outputDir(e.dir, this.plugin.id), name, bytes);
      e.audit(this.actor, "plugin.report", { plugin: this.plugin.id, name: file.name }, { format: step.format, includeDrafts, size: file.size });
      return { ...file, ...(step.format === "markdown" ? { markdown } : {}) };
    } catch (err) {
      if (err instanceof OutputError) throw new StepFailure(err.message, false);
      throw err;
    }
  }

  /** A logo for the report: a data: URL as is, or a PNG/JPEG of the plugin's folder or of its files. */
  private logo(ref: string): string {
    if (ref.startsWith("data:")) return ref;
    const type = { ".png": "png", ".jpg": "jpeg", ".jpeg": "jpeg" }[extname(ref).toLowerCase()];
    if (!type) throw new StepFailure(`the logo must be a PNG or JPEG file, or a data: URL ("${ref}")`, false);
    let bytes: Buffer | undefined;
    try {
      const name = outputName(ref);
      const own = resolve(this.plugin.dir, name);
      if (existsSync(own) && statSync(own).isFile() && realpathSync(own).startsWith(realpathSync(this.plugin.dir) + sep)) bytes = readFileSync(own);
      else bytes = readOutput(outputDir(this.engagement.dir, this.plugin.id), name).bytes;
    } catch {
      throw new StepFailure(`no logo "${ref}" in the plugin's folder or its files`, false);
    }
    if (bytes.length > 440_000) throw new StepFailure(`the logo "${ref}" is larger than 430 KB`, false);
    return `data:image/${type};base64,${bytes.toString("base64")}`;
  }

  private async each(step: EachStep, scope: Record<string, unknown>, prefix: string): Promise<unknown> {
    const list = this.render(step.over, scope, "over");
    if (list === null || list === undefined) return [];
    if (!Array.isArray(list)) throw new StepFailure("over must be a list");
    const out: unknown[] = [];
    for (const [index, item] of list.slice(0, step.max).entries()) {
      const inner = { ...scope, [step.as]: item, index };
      const last = await this.runSteps(step.steps, inner, prefix);
      out.push(step.collect !== undefined ? this.render(step.collect, inner, "collect") : last);
    }
    return out;
  }

  private store(scope: "project" | "global") {
    return scope === "global" ? this.runtime.data.global(this.plugin.id) : this.runtime.data.project(this.plugin.id, this.engagement);
  }

  private async http(step: Extract<PluginStep, { do: "http" }>, scope: Record<string, unknown>): Promise<unknown> {
    if (++this.requests > RUN_LIMITS.requests) throw new StepFailure(`more than ${RUN_LIMITS.requests} requests in one call`);
    const used = new Set<string>();
    const opts: RenderOptions = {
      allowSecrets: true,
      usedSecrets: used,
      secret: (name) => {
        if (!this.perms.has(`secrets:${name}`)) throw new StepFailure(`secret:${name} needs the secrets:${name} permission`);
        const v = this.engagement.secretValue(name);
        return v || undefined;
      },
    };
    const url = new URL(String(this.render(step.url, scope, "url", opts)));
    for (const [k, v] of Object.entries(step.query ?? {})) {
      const value = this.render(v, scope, `query.${k}`, opts);
      if (value === undefined || value === null) continue;
      for (const x of Array.isArray(value) ? value : [value]) url.searchParams.append(k, typeof x === "object" ? JSON.stringify(x) : String(x));
    }
    const headers: Record<string, string> = { "user-agent": `Penteos-plugin/${this.plugin.id}`, accept: "application/json, text/plain;q=0.9, */*;q=0.5" };
    for (const [k, v] of Object.entries(step.headers ?? {})) {
      const value = this.render(v, scope, `headers.${k}`, opts);
      if (value !== undefined && value !== null && value !== "") headers[k.toLowerCase()] = String(value);
    }
    let body: string | undefined;
    if (step.body !== undefined) {
      body = JSON.stringify(this.render(step.body, scope, "body", opts));
      headers["content-type"] ??= "application/json";
    } else if (step.form !== undefined) {
      const form = new URLSearchParams();
      for (const [k, v] of Object.entries(step.form)) {
        const value = this.render(v, scope, `form.${k}`, opts);
        if (value !== undefined && value !== null) form.append(k, String(value));
      }
      body = form.toString();
      headers["content-type"] ??= "application/x-www-form-urlencoded";
    }
    // Each secret in every form it can travel in: as is, percent-encoded, and form-encoded.
    const secrets = [...new Set([...used, ...this.runtime.pluginSecrets(this.plugin)].filter((s) => s.length >= 4).flatMap((s) => [s, encodeURIComponent(s), new URLSearchParams({ x: s }).toString().slice(2)]))].sort((a, b) => b.length - a.length);
    const redact = (text: string) => secrets.reduce((t, s) => t.split(s).join("«secret»"), text);

    const timeoutMs = step.timeoutMs ?? HTTP_LIMITS.defaultTimeoutMs;
    const maxBytes = step.maxBytes ?? HTTP_LIMITS.defaultBytes;
    const signal = AbortSignal.any([this.controller.signal, AbortSignal.timeout(timeoutMs)]);
    let current = url;
    let res: Response | undefined;
    let method: string = step.method;
    let sendBody = body;
    for (let hop = 0; ; hop++) {
      // Every hop is checked: a redirect to a host outside the plugin's net: permissions is refused.
      if (current.protocol !== "https:" && current.protocol !== "http:") throw new StepFailure(`refused ${current.protocol}// (plugins talk http and https)`);
      if (!netAllows(this.plugin.manifest.permissions, current.hostname)) throw new StepFailure(`refused ${current.hostname}: not in the plugin's net: permissions`);
      try {
        res = await this.runtime.http(current, { method, headers, ...(sendBody !== undefined && method !== "GET" && method !== "HEAD" ? { body: sendBody } : {}), redirect: "manual", signal });
      } catch (e) {
        throw new StepFailure(`${current.hostname}: ${signal.aborted ? `no answer within ${timeoutMs} ms` : message(e)}`);
      }
      const location = res.headers.get("location");
      if (res.status >= 300 && res.status < 400 && location) {
        if (hop >= RUN_LIMITS.redirects) throw new StepFailure(`more than ${RUN_LIMITS.redirects} redirects`);
        await res.body?.cancel();
        current = new URL(location, current);
        if (res.status === 303 || ((res.status === 301 || res.status === 302) && method === "POST")) {
          method = "GET";
          sendBody = undefined;
        }
        continue;
      }
      break;
    }
    const raw = redact(await readCapped(res, maxBytes, current.hostname));
    const type = res.headers.get("content-type") ?? "";
    let parsed: unknown = raw;
    if (/json/i.test(type) || /^\s*[[{]/.test(raw)) {
      try {
        parsed = JSON.parse(raw);
      } catch {
        parsed = raw;
      }
    }
    const responseHeaders: Record<string, string> = {};
    res.headers.forEach((v, k) => {
      if (k !== "set-cookie") responseHeaders[k] = redact(v);
    });
    // What left the machine, for the audit chain: who, where, how much, and the request itself with secrets redacted.
    // Kept in the subject (stored as is), not only hashed: the audit says what left, readable.
    const sent = {
      plugin: this.plugin.id,
      host: url.hostname,
      method: step.method,
      url: redact(url.toString()).slice(0, 2000),
      bytesOut: body ? Buffer.byteLength(body) : 0,
      ...(body ? { body: redact(body).slice(0, 1024) } : {}),
      status: res.status,
      onBehalfOf: this.ctx.caller.actor,
    };
    this.engagement.audit(this.actor, "plugin.egress", sent, sent);
    this.runtime.mediated(this.plugin.id, this.engagement, url, body);
    const ok = step.expect ? step.expect.includes(res.status) : res.status >= 200 && res.status < 300;
    if (!ok) {
      const detail = typeof parsed === "string" ? parsed.slice(0, 300) : JSON.stringify(parsed).slice(0, 300);
      throw new StepFailure(`${url.hostname} answered ${res.status}${detail ? `: ${detail}` : ""}`);
    }
    return { status: res.status, ok: res.status >= 200 && res.status < 300, headers: responseHeaders, body: parsed };
  }

  /** Nothing of a secret leaves in a result, even if an API echoed it back in a field we did not expect. */
  private redactOut(result: unknown): unknown {
    if (result === undefined) return null;
    let text = JSON.stringify(result);
    if (text === undefined) return null;
    for (const s of this.runtime.pluginSecrets(this.plugin)) text = text.split(JSON.stringify(s).slice(1, -1)).join("«secret»");
    if (Buffer.byteLength(text) > RUN_LIMITS.resultBytes) throw new StepFailure(`the result is larger than ${RUN_LIMITS.resultBytes} bytes: narrow it with result or take`);
    return JSON.parse(text);
  }
}

async function readCapped(res: Response, maxBytes: number, host: string): Promise<string> {
  if (!res.body) return "";
  const reader = res.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > maxBytes) {
      await reader.cancel();
      throw new StepFailure(`${host} sent more than ${maxBytes} bytes (raise maxBytes or narrow the request)`);
    }
    chunks.push(value);
  }
  return new TextDecoder().decode(Buffer.concat(chunks));
}

