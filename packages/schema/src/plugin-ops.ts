import { z } from "zod";
import { ENTITY_KINDS } from "./entities.js";
import { FieldName, FieldSpec, pluginText, replayMigrations, type StorageShape, uniqueNames } from "./plugin-data.js";
import { TemplateError, templateRefs } from "./plugin-template.js";

/**
 * What a declarative plugin *does*: operations made of steps the core
 * already knows how to run, the forms and views around them, menu entries, reactions to events,
 * settings and AI providers. All data: the core executes it with its own tested code, under the
 * plugin's declared permissions, checked here before anything runs and again at run time.
 */

const Name = z.string().regex(/^[a-z][a-z0-9_]{0,31}$/, "expected a lowercase name like lookup_host");
const StepId = z.string().regex(/^[a-z][a-zA-Z0-9_]{0,31}$/, "expected a step id like search");
/** Any JSON; strings in it may hold templates. */
const Tpl = z.unknown();
const TplString = z.string().max(4000);

const stepBase = {
  /** Name to read its result later: `{{steps.<id>…}}`. */
  id: StepId.optional(),
  /** Runs only when this renders truthy. */
  if: z.string().max(500).optional(),
};

export const HTTP_METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"] as const;
export const HTTP_LIMITS = { maxBytes: 5 * 1024 * 1024, defaultBytes: 1024 * 1024, timeoutMs: 60_000, defaultTimeoutMs: 15_000 } as const;

const HttpStep = z
  .object({
    do: z.literal("http"),
    ...stepBase,
    method: z.enum(HTTP_METHODS).default("GET"),
    /** https only; the host is written literally (templates only after it) and must be in a net: permission. */
    url: z.string().min(9).max(4000),
    headers: z.record(z.string().regex(/^[A-Za-z0-9-]{1,64}$/), z.string().max(4000)).optional(),
    query: z.record(z.string().max(100), Tpl).optional(),
    /** JSON body. */
    body: Tpl.optional(),
    /** application/x-www-form-urlencoded body. */
    form: z.record(z.string().max(100), Tpl).optional(),
    /** Status codes that count as success (default: any 2xx). */
    expect: z.array(z.number().int().min(100).max(599)).max(20).optional(),
    maxBytes: z.number().int().min(1024).max(HTTP_LIMITS.maxBytes).optional(),
    timeoutMs: z.number().int().min(500).max(HTTP_LIMITS.timeoutMs).optional(),
  })
  .strict();

const GraphQueryStep = z
  .object({ do: z.literal("graph_query"), ...stepBase, kind: z.string().max(120), text: TplString.optional(), limit: z.number().int().min(1).max(500).default(100) })
  .strict();
const GraphGetStep = z.object({ do: z.literal("graph_get"), ...stepBase, entity: TplString }).strict();
const PutStep = z.object({ do: z.literal("put"), ...stepBase, type: Name, attributes: Tpl, relate: TplString.optional() }).strict();
const AnnotateStep = z.object({ do: z.literal("annotate"), ...stepBase, entity: TplString, data: Tpl }).strict();
const RelateStep = z.object({ do: z.literal("relate"), ...stepBase, from: TplString, to: TplString }).strict();

const StoreScope = z.enum(["project", "global"]).default("project");
const StoreInsertStep = z.object({ do: z.literal("store_insert"), ...stepBase, scope: StoreScope, table: Name, row: Tpl.optional(), rows: Tpl.optional() }).strict();
const StoreQueryStep = z
  .object({ do: z.literal("store_query"), ...stepBase, scope: StoreScope, table: Name, where: Tpl.optional(), orderBy: z.object({ column: z.string().max(40), dir: z.enum(["asc", "desc"]).default("asc") }).strict().optional(), limit: Tpl.optional() })
  .strict();
const StoreUpdateStep = z.object({ do: z.literal("store_update"), ...stepBase, scope: StoreScope, table: Name, where: Tpl, set: Tpl }).strict();
const StoreDeleteStep = z.object({ do: z.literal("store_delete"), ...stepBase, scope: StoreScope, table: Name, where: Tpl }).strict();

const FindingDraftStep = z
  .object({
    do: z.literal("finding_draft"),
    ...stepBase,
    title: TplString,
    severity: Tpl,
    description: Tpl.optional(),
    impact: Tpl.optional(),
    remediation: Tpl.optional(),
    /** Entity ids the finding affects. */
    affects: Tpl.optional(),
  })
  .strict();
const NotifyStep = z.object({ do: z.literal("notify"), ...stepBase, title: TplString, body: TplString.optional(), level: z.enum(["info", "warn"]).default("info") }).strict();
const SetStep = z.object({ do: z.literal("set"), ...stepBase, vars: z.record(FieldName, Tpl) }).strict();
const FailStep = z.object({ do: z.literal("fail"), ...stepBase, message: TplString }).strict();
/**
 * A file for the operator (a .docx, a .csv, an image…), saved in the project's folder for this
 * plugin: the interface offers it to download or open, and it travels with the project's export.
 * `name` may hold subfolders ("informes/acme.docx"); `content` is text, base64 or any JSON value.
 */
export const OUTPUT_ENCODINGS = ["text", "base64", "json"] as const;

/** The official deliverable's sections, in their order (a report step picks among them). */
export const REPORT_SECTION_IDS = [
  "executive_summary",
  "scope",
  "paths",
  "retest",
  "findings",
  "detailed",
  "surface",
  "coverage",
  "conclusion",
  "traces",
  "annex",
  // The complete technical report (2026-11): before, around and after the original ones.
  "document_control",
  "methodology",
  "timeline",
  "remediation_plan",
  "inventory",
  "limitations",
  "tools",
] as const;
const ReportSectionId = z.enum(REPORT_SECTION_IDS);
export const SEVERITY_LEVELS = ["critical", "high", "medium", "low", "info"] as const;
/**
 * The official deliverable, made by the core with the plugin's choices: a Word document (or its
 * markdown) saved among the plugin's files. Author, title, company, color, logo and confidentiality
 * replace the organization's branding for this document; sections pick or leave out the official
 * ones; extra adds the plugin's own (markdown), after a given section or before the annex.
 */
const ReportStep = z
  .object({
    do: z.literal("report"),
    ...stepBase,
    format: z.enum(["docx", "markdown"]).default("docx"),
    name: TplString.optional(),
    includeDrafts: Tpl.optional(),
    title: TplString.optional(),
    author: TplString.optional(),
    company: TplString.optional(),
    color: TplString.optional(),
    /** A data: URL, or a PNG/JPEG file of the plugin's folder or of its files ("assets/logo.png"). */
    logo: TplString.optional(),
    confidentiality: TplString.optional(),
    /** Section ids, or a template that gives them (a list, or a text with commas). */
    sections: z.union([z.array(ReportSectionId).max(REPORT_SECTION_IDS.length), TplString]).optional(),
    skip: z.union([z.array(ReportSectionId).max(REPORT_SECTION_IDS.length), TplString]).optional(),
    /** A severity, or a template that gives one. */
    minSeverity: z.union([z.enum(SEVERITY_LEVELS), TplString]).optional(),
    extra: z
      .array(z.object({ title: TplString, markdown: z.string().max(200_000), after: ReportSectionId.optional() }).strict())
      .max(30)
      .optional(),
  })
  .strict();
const FileStep = z
  .object({ do: z.literal("file"), ...stepBase, name: TplString, content: Tpl, encoding: z.enum(OUTPUT_ENCODINGS).default("text") })
  .strict();

export type PluginStep =
  | z.infer<typeof HttpStep>
  | z.infer<typeof GraphQueryStep>
  | z.infer<typeof GraphGetStep>
  | z.infer<typeof PutStep>
  | z.infer<typeof AnnotateStep>
  | z.infer<typeof RelateStep>
  | z.infer<typeof StoreInsertStep>
  | z.infer<typeof StoreQueryStep>
  | z.infer<typeof StoreUpdateStep>
  | z.infer<typeof StoreDeleteStep>
  | z.infer<typeof FindingDraftStep>
  | z.infer<typeof NotifyStep>
  | z.infer<typeof SetStep>
  | z.infer<typeof FailStep>
  | z.infer<typeof FileStep>
  | z.infer<typeof ReportStep>
  | EachStep;

export interface EachStep {
  do: "each";
  id?: string;
  if?: string;
  /** A list: `{{steps.search.body.matches}}`. */
  over: string;
  as: string;
  /** At most this many items are processed (the rest are reported as skipped). */
  max: number;
  steps: PluginStep[];
  /** What each iteration contributes to the step's result. */
  collect?: unknown;
}

export const PluginStepSchema: z.ZodType<PluginStep, unknown> = z.lazy(() =>
  z.discriminatedUnion("do", [
    HttpStep,
    GraphQueryStep,
    GraphGetStep,
    PutStep,
    AnnotateStep,
    RelateStep,
    StoreInsertStep,
    StoreQueryStep,
    StoreUpdateStep,
    StoreDeleteStep,
    FindingDraftStep,
    NotifyStep,
    SetStep,
    FailStep,
    FileStep,
    ReportStep,
    z
      .object({
        do: z.literal("each"),
        ...stepBase,
        over: TplString,
        as: FieldName.default("item"),
        max: z.number().int().min(1).max(500).default(100),
        steps: z.array(PluginStepSchema).min(1).max(20),
        collect: Tpl.optional(),
      })
      .strict(),
  ]),
) as z.ZodType<PluginStep, unknown>;

/** Steps that change Penteos's state (an operation with any of them is a write). */
export const WRITE_STEPS = new Set(["put", "annotate", "relate", "store_insert", "store_update", "store_delete", "finding_draft", "notify", "file", "report"]);

// ---------------------------------------------------------------------------------------------
// Views: how a result is shown, with Penteos's own components
// ---------------------------------------------------------------------------------------------

const ViewField = z.object({ field: z.string().max(200), label: pluginText(60) }).strict();
export const PluginView = z.discriminatedUnion("type", [
  z.object({ type: z.literal("table"), items: z.string().max(200).optional(), columns: z.array(ViewField).min(1).max(12) }).strict(),
  z.object({ type: z.literal("card"), fields: z.array(ViewField).min(1).max(24) }).strict(),
  z.object({ type: z.literal("message"), text: TplString }).strict(),
  z.object({ type: z.literal("json") }).strict(),
  /** Text with format: the result itself, or one of its fields (`field`). */
  z.object({ type: z.literal("markdown"), field: z.string().max(200).optional() }).strict(),
  /** An HTML document, shown as a preview (no scripts): the result itself or one of its fields. */
  z.object({ type: z.literal("document"), field: z.string().max(200).optional() }).strict(),
]);
export type PluginView = z.infer<typeof PluginView>;

// ---------------------------------------------------------------------------------------------
// Operations, menus, events, providers
// ---------------------------------------------------------------------------------------------

/** Icons an operation's button may use (the interface draws them). */
export const PLUGIN_ICONS = ["play", "search", "file-text", "download", "send", "shield", "bug", "globe", "zap", "wand", "key", "lock", "radar", "database", "terminal", "image", "chart", "mail", "refresh", "upload"] as const;

export const PluginOperation = z
  .object({
    name: Name,
    title: pluginText(80),
    /** What the button says ("Generate report"): the verb of the operation. */
    action: pluginText(40).optional(),
    icon: z.enum(PLUGIN_ICONS).optional(),
    /** For the operator and for the Maestro: what it does and when to use it (English reads best for models). */
    description: pluginText(1000),
    /** Who may call it. An agent-callable operation becomes a Maestro tool. */
    actors: z.array(z.enum(["human", "agent"])).min(1).default(["human", "agent"]),
    input: z.array(FieldSpec).max(32).default([]),
    /** Declarative operations: what it does, step by step. */
    steps: z.array(PluginStepSchema).min(1).max(40).optional(),
    /** Code plugins: the name its code registers the operation under (instead of steps). */
    handler: Name.optional(),
    /** What the call returns (default: the last step's result). */
    result: Tpl.optional(),
    view: PluginView.optional(),
    timeoutMs: z.number().int().min(1000).max(120_000).default(30_000),
  })
  .strict()
  .refine((o) => Boolean(o.steps) !== Boolean(o.handler), { message: "an operation has steps or a handler (code plugins), not both", path: ["steps"] });
export type PluginOperation = z.infer<typeof PluginOperation>;

export const PluginMenu = z
  .object({
    id: Name,
    title: pluginText(60),
    operation: Name,
    /** plugins: the Plugins menu. entity: the actions of an entity's detail. Both go to the palette. */
    where: z.enum(["plugins", "entity"]).default("plugins"),
    /** For entity menus: the kinds it shows on (official kinds or the plugin's own type names). */
    kinds: z.array(z.string().max(120)).max(20).optional(),
    /** Form values taken from the entity: `{ "ip": "{{entity.attributes.ip}}" }`. */
    prefill: z.record(FieldName, TplString).optional(),
    /** Run right away when the form has nothing left to fill. */
    direct: z.boolean().default(false),
  })
  .strict();
export type PluginMenu = z.infer<typeof PluginMenu>;

/**
 * A panel of its own (code plugins): an HTML file of the plugin, shown in an isolated frame with no
 * network; it reaches the plugin's operations only through the frame's bridge.
 */
export const PluginPanel = z
  .object({
    id: Name,
    title: pluginText(60),
    file: z.string().max(200).regex(/^(?!\/)(?!.*(?:^|\/)\.\.(?:\/|$))[A-Za-z0-9_./-]+\.html$/, "an .html file inside the plugin folder"),
    /** plugins: its own tab (from the Plugins menu). entity: inside an entity's detail. */
    where: z.enum(["plugins", "entity"]).default("plugins"),
    kinds: z.array(z.string().max(120)).max(20).optional(),
    height: z.number().int().min(120).max(1200).default(360),
  })
  .strict();
export type PluginPanel = z.infer<typeof PluginPanel>;

/**
 * A file format a code plugin teaches Penteos to import: when no built-in format recognizes a file,
 * the parsers of the plugins enabled in the project whose `detect` text appears in its first 8 KB
 * are asked; what they return goes through the same ingest validation as any official parser.
 */
export const PluginParser = z
  .object({
    id: Name,
    title: pluginText(60),
    /** Text that appears near the start of files of this format ("<NessusClientData_v2"). */
    detect: z.string().min(3).max(200),
    extensions: z.array(z.string().regex(/^\.[a-z0-9]{1,12}$/)).max(8).optional(),
    handler: Name,
  })
  .strict();
export type PluginParser = z.infer<typeof PluginParser>;

/** A finding write-up a plugin adds to the library (data; any plugin may bring them). */
export const PluginFindingTemplate = z
  .object({
    id: z.string().regex(/^[a-z0-9][a-z0-9-]{1,60}$/),
    title: z.string().min(1).max(300),
    severity: z.enum(["critical", "high", "medium", "low", "info"]),
    cwe: z.array(z.string().regex(/^CWE-\d+$/)).max(10).default([]),
    description: z.string().max(20_000).default(""),
    impact: z.string().max(20_000).default(""),
    remediation: z.string().max(20_000).default(""),
    references: z.array(z.string().max(500)).max(20).default([]),
    tags: z.array(z.string().max(40)).max(20).default([]),
  })
  .strict();
export type PluginFindingTemplate = z.infer<typeof PluginFindingTemplate>;

/**
 * A section a plugin adds to the official deliverable: when the report is made, its operation runs
 * (with no input) and returns the section's markdown - a string, or { markdown } - placed after
 * `after` (or before the annex). Only in projects where the plugin is enabled.
 */
export const PluginReportSection = z
  .object({
    id: Name,
    title: pluginText(120),
    operation: Name,
    after: ReportSectionId.optional(),
    /** Only in projects of these modes (web, infra, custom); every mode when absent. */
    modes: z.array(z.string().max(20)).max(8).optional(),
  })
  .strict();
export type PluginReportSection = z.infer<typeof PluginReportSection>;

/**
 * A code plugin in the proxy's path (needs the proxy permission), like an extension of an
 * intercepting proxy: its handler sees each request or response that matches. A viewing hook runs
 * aside (it never slows traffic: a passive scanner, a logger); a modifying one returns the changes
 * (method, url, headers, body; status for a response) before the operator's interception - if it
 * fails or is late, the message goes on unchanged. A changed URL is still checked against the scope.
 */
export const PluginProxyHook = z
  .object({
    id: Name,
    on: z.enum(["request", "response"]),
    handler: Name,
    modify: z.boolean().default(false),
    /** Hosts it applies to ("api.acme.example", "*.acme.example"); every host when absent. */
    hosts: z.array(z.string().regex(/^(\*\.)?[a-z0-9.-]+$/i)).max(20).optional(),
    methods: z.array(z.string().regex(/^[A-Z]{3,10}$/)).max(10).optional(),
    /** A regular expression over the path and query. */
    path: z.string().max(300).optional(),
    /** Responses whose content type starts with one of these ("application/json", "text/html"). */
    contentTypes: z.array(z.string().max(80)).max(10).optional(),
    /** How long a modifying hook may take before the message goes on unchanged. */
    timeoutMs: z.number().int().min(100).max(10_000).default(2000),
  })
  .strict();
export type PluginProxyHook = z.infer<typeof PluginProxyHook>;

/**
 * Knowledge for the Maestro (a method, a checklist, how to use the plugin's tools, the house style
 * of a report): in projects where the plugin is enabled, it is added to what the Maestro reads.
 */
export const PluginSkill = z
  .object({
    id: Name,
    title: pluginText(120),
    /** Markdown, in the language the plugin's author writes; the Maestro reads it as it is. */
    text: z.string().min(1).max(8000),
    modes: z.array(z.string().max(20)).max(8).optional(),
  })
  .strict();
export type PluginSkill = z.infer<typeof PluginSkill>;

/**
 * Another format for the deliverable (an Excel of findings, a client's template, a ticket batch):
 * a button next to Word and Markdown in the Deliverable panel that runs the plugin's operation -
 * right away when it asks for nothing, through its form when it does - and offers the files it makes.
 */
export const PluginExport = z
  .object({
    id: Name,
    title: pluginText(60),
    operation: Name,
    icon: z.enum(PLUGIN_ICONS).optional(),
  })
  .strict();
export type PluginExport = z.infer<typeof PluginExport>;

/** Official kinds whose changes plugins may react to (credentials and memory stay out: they hold secrets and the Maestro's notes). */
export const EVENT_KINDS = ["finding", "host", "domain", "webapp", "service", "endpoint", "technology", "observation", "evidence", "task"] as const;
export const PLUGIN_EVENTS = [
  ...EVENT_KINDS.flatMap((k) => [`${k}.created`, `${k}.updated`] as const),
  "run.finished",
  "scope.changed",
  /** The target called back to the out-of-band server (a blind vulnerability, likely). */
  "oob.interaction",
  /** A finding got an independent verdict. */
  "verification.done",
  /** A host that answered stopped accepting connections (this machine may be blocked). */
  "host.unreachable",
  /** An in-scope site redirects outside the scope. */
  "scope.redirect_outside",
] as const;
export const PluginEvent = z
  .object({
    on: z.enum(PLUGIN_EVENTS),
    operation: Name,
    /** Runs only when this renders truthy (with `event` in scope). */
    when: z.string().max(500).optional(),
    /** The operation's input, from the event. */
    input: z.record(FieldName, Tpl).optional(),
  })
  .strict();
export type PluginEvent = z.infer<typeof PluginEvent>;

export const PluginProvider = z
  .object({
    id: Name,
    label: pluginText(60),
    description: pluginText(200).optional(),
    /** An endpoint compatible with OpenAI's chat completions (https; its host must be in a net: permission). */
    baseUrl: z.string().url().max(500),
    models: z.array(z.string().min(1).max(120)).min(1).max(50),
    /** The secret setting holding its API key. */
    apiKey: FieldName.optional(),
  })
  .strict();
export type PluginProvider = z.infer<typeof PluginProvider>;

/** Limits on event-triggered calls, per plugin. */
export const EVENT_LIMITS = { perMinute: 30, queue: 100 } as const;

// ---------------------------------------------------------------------------------------------
// The static check: permissions, references, taint - the exact path of each problem
// ---------------------------------------------------------------------------------------------

export interface ContributionIssue {
  path: Array<string | number>;
  message: string;
}

interface CheckedManifest {
  id: string;
  level?: "declarative" | "code";
  permissions: string[];
  contributes: {
    operations?: PluginOperation[];
    menus?: PluginMenu[];
    events?: PluginEvent[];
    providers?: PluginProvider[];
    panels?: PluginPanel[];
    parsers?: PluginParser[];
    reportSections?: PluginReportSection[];
    proxy?: PluginProxyHook[];
    exports?: PluginExport[];
    settings?: FieldSpec[];
    entityTypes?: Array<{ name: string }>;
    annotations?: unknown[];
    storage?: { project?: Parameters<typeof replayMigrations>[0]; global?: Parameters<typeof replayMigrations>[0] };
  };
}

/** The host of an https URL whose host part is literal; undefined if it is not. */
export function literalHttpsHost(url: string): string | undefined {
  const m = /^https?:\/\/([a-z0-9.-]+)(?::\d{1,5})?(?:[/?#]|$)/i.exec(url);
  if (!m) return undefined;
  const hostEnd = url.indexOf(m[1]!) + m[1]!.length;
  if (url.slice(0, hostEnd).includes("{{")) return undefined;
  return m[1]!.toLowerCase();
}

/**
 * Where an https URL goes: a literal host, or `*.<suffix>` when its leftmost labels are templated
 * (`https://{{settings.site}}.atlassian.net/…`, for services with one subdomain per customer). A
 * templated host is allowed only under a wildcard net: permission, and the real host is checked
 * again at run time.
 */
export function httpsHostOf(url: string): { host: string; wildcard: boolean } | undefined {
  const literal = literalHttpsHost(url);
  if (literal) return { host: literal, wildcard: false };
  const m = /^https?:\/\/((?:\{\{[^}]*\}\}[a-z0-9-]*\.)+)([a-z0-9-]+(?:\.[a-z0-9-]+)+)(?::\d{1,5})?(?:[/?#]|$)/i.exec(url);
  if (!m) return undefined;
  return { host: `*.${m[2]!.toLowerCase()}`, wildcard: true };
}

/** Whether every host a pattern can produce is covered: `*.a.b` needs `net:*.a.b` or a wider wildcard. */
export function netAllowsPattern(permissions: readonly string[], pattern: string): boolean {
  if (permissions.includes("net:*")) return true;
  if (!pattern.startsWith("*.")) return netAllows(permissions, pattern);
  const suffix = pattern.slice(2);
  return permissions.some((p) => {
    if (!p.startsWith("net:*.")) return false;
    const rule = p.slice(6).toLowerCase();
    return suffix === rule || suffix.endsWith(`.${rule}`);
  });
}

/** Whether a host is covered by the plugin's net: permissions (exact, or `*.domain` for subdomains). */
export function netAllows(permissions: readonly string[], host: string): boolean {
  const h = host.toLowerCase();
  return permissions.some((p) => {
    if (!p.startsWith("net:")) return false;
    const rule = p.slice(4).toLowerCase();
    // net:* - any host (a free plugin; Penteos watches and warns instead of refusing).
    if (rule === "*") return true;
    if (rule.startsWith("*.")) return h.endsWith(rule.slice(1)) && h.length > rule.length - 1;
    return h === rule;
  });
}

/** The Maestro tool name of a plugin operation (providers cap tool names at 64 characters). */
export function pluginToolName(pluginId: string, op: string): string {
  return `penteos_plugin_${pluginId.replace(/[.-]/g, "_")}_${op}`;
}

export function pluginOperationName(pluginId: string, op: string): string {
  return `plugin.${pluginId}.${op}`;
}

export function checkContributions(m: CheckedManifest): ContributionIssue[] {
  const issues: ContributionIssue[] = [];
  const add = (path: Array<string | number>, message: string) => issues.push({ path: ["contributes", ...path], message });
  const c = m.contributes;
  const perms = new Set(m.permissions);
  const ops = c.operations ?? [];
  const opNames = new Set(ops.map((o) => o.name));
  const settings = new Map((c.settings ?? []).map((f) => [f.name, f]));
  const ownTypes = new Set((c.entityTypes ?? []).map((t) => t.name));
  const shapes: Record<"project" | "global", StorageShape | undefined> = { project: undefined, global: undefined };
  for (const scope of ["project", "global"] as const) {
    try {
      shapes[scope] = replayMigrations(c.storage?.[scope] ?? []);
    } catch {
      /* reported by the storage schema itself */
    }
  }

  const dup = (list: Array<{ name?: string; id?: string }>, what: string, key: "name" | "id", path: string) => {
    const seen = new Set<string>();
    list.forEach((x, i) => {
      const k = x[key]!;
      if (seen.has(k)) add([path, i, key], `duplicate ${what} "${k}"`);
      seen.add(k);
    });
  };
  dup(ops, "operation", "name", "operations");
  dup(c.menus ?? [], "menu", "id", "menus");
  dup(c.providers ?? [], "provider", "id", "providers");
  const settingIssues: z.RefinementCtx = { addIssue: (i: { message?: string; path?: Array<string | number> }) => add(["settings", ...(i.path ?? [])], i.message ?? "invalid") } as unknown as z.RefinementCtx;
  uniqueNames(c.settings ?? [], settingIssues, [], "setting");

  /** Checks the references of one templated value. */
  const refs = (value: unknown, path: Array<string | number>, scope: { input: Set<string>; steps: Set<string>; vars: Set<string>; loop: Set<string>; roots: Set<string>; http: boolean }) => {
    let found;
    try {
      found = templateRefs(value);
    } catch (e) {
      add(path, e instanceof TemplateError ? e.message : String(e));
      return;
    }
    for (const r of found) {
      if (r.secret) {
        if (!perms.has(`secrets:${r.name}`)) add(path, `secret:${r.name} needs the secrets:${r.name} permission`);
        if (!scope.http) add(path, `secret:${r.name} can only be used inside an http step`);
        continue;
      }
      if (scope.loop.has(r.root)) continue;
      if (!scope.roots.has(r.root)) {
        add(path, `"${r.root}" is not available here (available: ${[...scope.roots, ...scope.loop].join(", ")})`);
        continue;
      }
      if (r.root === "input" && r.name && !scope.input.has(r.name)) add(path, `input.${r.name} is not a declared input field`);
      if (r.root === "steps" && r.name && !scope.steps.has(r.name)) add(path, `steps.${r.name} does not exist before this point (step ids: ${[...scope.steps].join(", ") || "none"})`);
      if (r.root === "vars" && r.name && !scope.vars.has(r.name)) add(path, `vars.${r.name} is not set before this point`);
      if (r.root === "settings" && r.name) {
        const s = settings.get(r.name);
        if (!s) add(path, `settings.${r.name} is not a declared setting`);
        else if (s.secret && !scope.http) add(path, `settings.${r.name} is secret: it can only be used inside an http step`);
      }
    }
  };

  const stepPerm = (step: PluginStep, path: Array<string | number>) => {
    const need = (p: string) => {
      if (!perms.has(p)) add(path, `a ${step.do} step needs the ${p} permission`);
    };
    switch (step.do) {
      case "http": {
        // net:* takes any url, also one that comes whole from the input ("{{input.url}}").
        if (perms.has("net:*")) {
          if (!/^(https?:\/\/|\{\{)/i.test(step.url)) add([...path, "url"], "the url starts with http://, https:// or a template");
          if (step.body !== undefined && step.form !== undefined) add(path, "use body or form, not both");
          break;
        }
        const target = httpsHostOf(step.url);
        if (!target) add([...path, "url"], "the url must be http(s):// with its host written literally (or only its leftmost labels templated, under a wildcard net: permission)");
        else if (!netAllowsPattern(m.permissions, target.host)) add([...path, "url"], `${target.host} is not in the plugin's net: permissions${target.wildcard ? " (a templated host needs a wildcard one)" : ""}`);
        if (step.body !== undefined && step.form !== undefined) add(path, "use body or form, not both");
        break;
      }
      case "graph_query":
      case "graph_get":
        need("graph:read");
        if (step.do === "graph_query" && !(ENTITY_KINDS as readonly string[]).includes(step.kind) && !ownTypes.has(step.kind)) {
          add([...path, "kind"], `"${step.kind}" is neither an official kind nor one of this plugin's types`);
        }
        break;
      case "put":
        need("graph:write");
        if (!ownTypes.has(step.type)) add([...path, "type"], `"${step.type}" is not one of this plugin's entity types`);
        break;
      case "annotate":
        need("graph:write");
        if (!(c.annotations ?? []).length) add(path, "an annotate step needs annotations declared");
        break;
      case "relate":
        need("graph:write");
        break;
      case "store_insert":
      case "store_query":
      case "store_update":
      case "store_delete": {
        const shape = shapes[step.scope];
        if (!shape?.tables[step.table]) add([...path, "table"], `the ${step.scope} storage has no table "${step.table}"`);
        if (step.do === "store_insert" && (step.row === undefined) === (step.rows === undefined)) add(path, "give row or rows");
        break;
      }
      case "finding_draft":
        need("findings:draft");
        break;
      case "notify":
        need("notify");
        break;
      case "file":
        need("files:write");
        break;
      case "report":
        need("graph:read");
        need("files:write");
        break;
      default:
        break;
    }
  };

  const walk = (
    steps: PluginStep[],
    path: Array<string | number>,
    scope: { input: Set<string>; steps: Set<string>; vars: Set<string>; loop: Set<string>; roots: Set<string> },
    ids: Set<string>,
  ) => {
    steps.forEach((step, i) => {
      const at = [...path, i];
      if (step.id) {
        if (ids.has(step.id)) add([...at, "id"], `duplicate step id "${step.id}"`);
        ids.add(step.id);
      }
      stepPerm(step, at);
      const plain = { ...scope, http: false };
      if (step.if) refs(step.if, [...at, "if"], plain);
      const { do: _do, id: _id, if: _if, ...fields } = step as unknown as Record<string, unknown>;
      if (step.do === "each") {
        refs(step.over, [...at, "over"], plain);
        const inner = { ...scope, loop: new Set([...scope.loop, step.as, "index"]), steps: new Set(scope.steps), vars: new Set(scope.vars) };
        walk(step.steps, [...at, "steps"], inner, ids);
        if (step.collect !== undefined) refs(step.collect, [...at, "collect"], { ...inner, http: false });
      } else {
        for (const [k, v] of Object.entries(fields)) refs(v, [...at, k], { ...scope, http: step.do === "http" });
        if (step.do === "http") {
          // A secret may be part of the url (a webhook path); never of its host.
          const target = httpsHostOf(step.url);
          if (target?.wildcard) {
            try {
              const hostPart = step.url.slice(0, step.url.indexOf(target.host.slice(2)));
              if (templateRefs(hostPart).some((r) => r.secret || settings.get(r.name ?? "")?.secret)) add([...at, "url"], "a secret cannot be part of the host");
            } catch {
              /* reported above */
            }
          }
        }
        if (step.do === "set") for (const k of Object.keys(step.vars)) scope.vars.add(k);
      }
      if (step.id) scope.steps.add(step.id);
    });
  };

  const stepRoots = new Set<string>(["input", "steps", "vars", "engagement", "settings"]);
  ops.forEach((op, i) => {
    uniqueNames(op.input, { addIssue: (x: { message?: string; path?: Array<string | number> }) => add(["operations", i, "input", ...(x.path ?? [])], x.message ?? "invalid") } as unknown as z.RefinementCtx, [], "input field");
    op.input.forEach((f, j) => {
      if (f.secret) add(["operations", i, "input", j, "secret"], "secret fields belong in settings");
    });
    const scope = { input: new Set(op.input.map((f) => f.name)), steps: new Set<string>(), vars: new Set<string>(), loop: new Set<string>(), roots: stepRoots };
    if (op.handler && m.level !== "code") add(["operations", i, "handler"], "only code plugins have handlers; a declarative operation has steps");
    walk(op.steps ?? [], ["operations", i, "steps"], scope, new Set());
    if (op.result !== undefined) refs(op.result, ["operations", i, "result"], { ...scope, http: false });
    if (op.view?.type === "message") refs(op.view.text, ["operations", i, "view", "text"], { ...scope, roots: new Set([...stepRoots, "result"]), http: false });
    if (op.actors.includes("agent") && pluginToolName(m.id, op.name).length > 64) {
      add(["operations", i, "name"], `the Maestro tool name ${pluginToolName(m.id, op.name)} is longer than 64 characters: shorten the operation or the plugin id`);
    }
  });

  const opInput = (name: string) => new Set(ops.find((o) => o.name === name)?.input.map((f) => f.name) ?? []);
  (c.menus ?? []).forEach((menu, i) => {
    if (!perms.has("ui:menu")) add(["menus", i], "menus need the ui:menu permission");
    if (!opNames.has(menu.operation)) add(["menus", i, "operation"], `no operation "${menu.operation}"`);
    else if (!ops.find((o) => o.name === menu.operation)!.actors.includes("human")) add(["menus", i, "operation"], `"${menu.operation}" is not callable by people`);
    for (const [field, tpl] of Object.entries(menu.prefill ?? {})) {
      if (!opInput(menu.operation).has(field)) add(["menus", i, "prefill", field], `"${field}" is not an input of ${menu.operation}`);
      refs(tpl, ["menus", i, "prefill", field], { input: new Set(), steps: new Set(), vars: new Set(), loop: new Set(), roots: new Set(menu.where === "entity" ? ["entity", "engagement"] : ["engagement"]), http: false });
    }
    if (menu.where === "entity" && !menu.kinds?.length) add(["menus", i, "kinds"], "an entity menu says which kinds it shows on");
    for (const [j, k] of (menu.kinds ?? []).entries()) {
      if (!(ENTITY_KINDS as readonly string[]).includes(k) && !ownTypes.has(k)) add(["menus", i, "kinds", j], `"${k}" is neither an official kind nor one of this plugin's types`);
    }
  });

  (c.panels ?? []).forEach((panel, i) => {
    if (m.level !== "code") add(["panels", i], "panels run code: only code plugins have them");
    if (!perms.has("ui:panel")) add(["panels", i], "panels need the ui:panel permission");
    if (panel.where === "entity" && !panel.kinds?.length) add(["panels", i, "kinds"], "an entity panel says which kinds it shows on");
    for (const [j, k] of (panel.kinds ?? []).entries()) {
      if (!(ENTITY_KINDS as readonly string[]).includes(k) && !ownTypes.has(k)) add(["panels", i, "kinds", j], `"${k}" is neither an official kind nor one of this plugin's types`);
    }
  });
  dup(c.panels ?? [], "panel", "id", "panels");
  (c.parsers ?? []).forEach((_p, i) => {
    if (m.level !== "code") add(["parsers", i], "parsers run code: only code plugins have them");
  });
  dup(c.parsers ?? [], "parser", "id", "parsers");

  (c.reportSections ?? []).forEach((r, i) => {
    const op = ops.find((o) => o.name === r.operation);
    if (!op) add(["reportSections", i, "operation"], `no operation "${r.operation}"`);
    else if (op.input.some((f) => f.required && f.default === undefined)) add(["reportSections", i, "operation"], `${r.operation} runs with no input: it cannot have required fields`);
  });
  dup(c.reportSections ?? [], "report section", "id", "reportSections");

  (c.exports ?? []).forEach((x, i) => {
    const op = ops.find((o) => o.name === x.operation);
    if (!op) add(["exports", i, "operation"], `no operation "${x.operation}"`);
    else if (!op.actors.includes("human")) add(["exports", i, "operation"], `${x.operation} must be available to people (actors)`);
  });
  dup(c.exports ?? [], "export", "id", "exports");

  (c.proxy ?? []).forEach((h, i) => {
    if (m.level !== "code") add(["proxy", i], "proxy hooks run code: only code plugins have them");
    if (!perms.has("proxy")) add(["proxy", i], "proxy hooks need the proxy permission");
    if (h.path !== undefined) {
      try {
        new RegExp(h.path);
      } catch {
        add(["proxy", i, "path"], "not a valid regular expression");
      }
    }
    if (h.contentTypes && h.on !== "response") add(["proxy", i, "contentTypes"], "contentTypes is for response hooks");
  });
  dup(c.proxy ?? [], "proxy hook", "id", "proxy");

  (c.events ?? []).forEach((ev, i) => {
    if (!opNames.has(ev.operation)) add(["events", i, "operation"], `no operation "${ev.operation}"`);
    const scope = { input: new Set<string>(), steps: new Set<string>(), vars: new Set<string>(), loop: new Set<string>(), roots: new Set(["event", "engagement", "settings"]), http: false };
    if (ev.when) refs(ev.when, ["events", i, "when"], scope);
    for (const [field, tpl] of Object.entries(ev.input ?? {})) {
      if (!opInput(ev.operation).has(field)) add(["events", i, "input", field], `"${field}" is not an input of ${ev.operation}`);
      refs(tpl, ["events", i, "input", field], scope);
    }
  });

  (c.providers ?? []).forEach((p, i) => {
    if (!perms.has("ai:provider")) add(["providers", i], "providers need the ai:provider permission");
    const host = literalHttpsHost(p.baseUrl);
    if (!host) add(["providers", i, "baseUrl"], "the endpoint must be https://");
    else if (!netAllows(m.permissions, host)) add(["providers", i, "baseUrl"], `${host} is not in the plugin's net: permissions`);
    if (p.apiKey) {
      const s = settings.get(p.apiKey);
      if (!s) add(["providers", i, "apiKey"], `no setting "${p.apiKey}"`);
      else if (!s.secret) add(["providers", i, "apiKey"], `setting "${p.apiKey}" must be secret`);
    }
  });

  return issues;
}

/** Every host a manifest can send data to (operations and providers), as the operator is told. */
export function manifestHosts(contributes: { operations?: PluginOperation[]; providers?: PluginProvider[] }, permissions: readonly string[] = []): string[] {
  const out = new Set<string>();
  // net:* - anywhere.
  if (permissions.includes("net:*")) out.add("*");
  // Code reaches whatever its net: permissions allow (always through the core).
  if ((contributes.operations ?? []).some((o) => o.handler)) for (const p of permissions) if (p.startsWith("net:")) out.add(p.slice(4));
  const walk = (steps: PluginStep[]) => {
    for (const s of steps) {
      if (s.do === "http") {
        const h = httpsHostOf(s.url);
        if (h) out.add(h.host);
      }
      if (s.do === "each") walk(s.steps);
    }
  };
  for (const op of contributes.operations ?? []) walk(op.steps ?? []);
  for (const p of contributes.providers ?? []) {
    const h = literalHttpsHost(p.baseUrl);
    if (h) out.add(h);
  }
  return [...out].sort();
}
