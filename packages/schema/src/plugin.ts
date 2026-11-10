import { z } from "zod";
import { AnnotationSpec, EntityTypeSpec, FieldSpec, pluginText, StorageSpec } from "./plugin-data.js";
import { checkContributions, PluginEvent, PluginMenu, PluginFindingTemplate, PluginOperation, PluginPanel, PluginParser, PluginProvider, PluginProxyHook, PluginReportSection, PluginSkill, PluginExport } from "./plugin-ops.js";

/**
 * The plugin contract. This is the only thing a plugin depends on: the core
 * can change inside without breaking plugins as long as this stays compatible. `apiVersion` is the
 * contract version; the core supports the current one and the previous one.
 */

/** The contract version plugins written today declare. */
export const PLUGIN_API_VERSION = 1;
/** Every contract version this core still loads (current and previous). */
export const SUPPORTED_PLUGIN_API_VERSIONS: readonly number[] = [1];

/** `author.name`, lowercase: everything the plugin contributes lives under this prefix. */
export const PluginId = z
  .string()
  .max(80)
  .regex(/^[a-z0-9][a-z0-9-]*(\.[a-z0-9][a-z0-9-]*)+$/, "expected author.name in lowercase, e.g. acme.shodan");

const Semver = z.string().regex(/^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$/, "expected a version like 1.2.3");

/**
 * What a plugin may touch, declared up front and enforced by the core (a call without the
 * permission fails). `net:<host>` talks to a third party; `target` acts on engagement targets and
 * always goes through the runner (scope, risk, approval).
 */
export const PluginPermission = z
  .string()
  .regex(
    /^(graph:read|graph:write|findings:draft|target|ai:provider|ui:form|ui:menu|ui:panel|notify|files:write|proxy|net:\*|net:(\*\.)?[a-z0-9-]+(\.[a-z0-9-]+)+|secrets:[a-z0-9_-]+)$/,
    "unknown permission",
  );
export type PluginPermission = z.infer<typeof PluginPermission>;

/**
 * What a plugin adds, by extension point. Each list is validated in detail by the phase that
 * enables that extension point; until then an entry is accepted but nothing is registered from it.
 */
const Contributions = z
  .object({
    /** Operations made of steps; each is a form for people and, if agents may call it, a Maestro tool. */
    operations: z.array(PluginOperation).max(64),
    /** Entries in the Plugins menu, in an entity's actions and in the palette. */
    menus: z.array(PluginMenu).max(64),
    /** The plugin's settings (API keys and the like), as a form the core generates. */
    settings: z.array(FieldSpec).max(32),
    /** Operations that run when something happens in a project. */
    events: z.array(PluginEvent).max(32),
    /** AI endpoints compatible with OpenAI's API. */
    providers: z.array(PluginProvider).max(8),
    /** Entity types of its own in the graph (`<id>:<name>`). */
    entityTypes: z.array(EntityTypeSpec).max(32),
    /** Extra data on official entities, in its own space. */
    annotations: z.array(AnnotationSpec).max(16),
    /** Tables of its own, in a database of its own. */
    storage: StorageSpec,
    /** Code plugins: panels of their own, in an isolated frame. */
    panels: z.array(PluginPanel).max(16),
    /** Code plugins: file formats to import. */
    parsers: z.array(PluginParser).max(8),
    // Validated by the phase that enables them.
    /** Finding write-ups for the library. */
    findingTemplates: z.array(PluginFindingTemplate).max(200),
    /** Sections of its own in the official deliverable. */
    reportSections: z.array(PluginReportSection).max(8),
    /** Code plugins: hooks in the proxy's path (see or change traffic). */
    proxy: z.array(PluginProxyHook).max(8),
    /** Knowledge for the Maestro in projects where it is enabled. */
    skills: z.array(PluginSkill).max(8),
    /** More formats for the deliverable. */
    exports: z.array(PluginExport).max(8),
  })
  .partial()
  .strict();

export const PluginManifest = z
  .object({
    id: PluginId,
    name: z.string().min(1).max(80),
    version: Semver,
    apiVersion: z.number().int().positive(),
    /** Penteos versions it works with: "*", "1.2.3", ">=1.2.3" or "^1.2.3". */
    engine: z.string().max(40).default("*"),
    /** declarative: data only, run by the core. code: its own logic, in an isolated process. */
    level: z.enum(["declarative", "code"]),
    description: pluginText(500).optional(),
    author: z.object({ type: z.enum(["human", "maestro"]), name: z.string().max(80).optional() }).strict(),
    permissions: z.array(PluginPermission).max(40).default([]),
    /** Code plugins: the entry file, relative to the plugin folder. */
    /** Code plugins: the entry file (an ES module), relative to the plugin folder. */
    main: z
      .string()
      .max(200)
      .regex(/^(?!\/)(?!.*(?:^|\/)\.\.(?:\/|$))[A-Za-z0-9_./-]+\.(?:mjs|js|py)$/, "a .mjs, .js or .py file inside the plugin folder")
      .optional(),
    /** Code plugins: what runs main - Node (default) or Python (free plugins only). */
    runtime: z.enum(["node", "python"]).default("node"),
    contributes: Contributions.default({}),
  })
  .strict()
  .refine((m) => m.level !== "code" || Boolean(m.main), { message: "a code plugin needs main", path: ["main"] })
  .refine((m) => m.runtime !== "python" || (m.level === "code" && Boolean(m.main?.endsWith(".py"))), { message: "a Python plugin is a code plugin whose main is a .py file", path: ["runtime"] })
  .refine((m) => m.runtime === "python" || !m.main?.endsWith(".py"), { message: "a .py main needs runtime: python", path: ["main"] })
  .superRefine((m, ctx) => {
    const c = m.contributes;
    const types = c.entityTypes ?? [];
    const seen = new Set<string>();
    types.forEach((t, i) => {
      if (seen.has(t.name)) ctx.addIssue({ code: "custom", message: `duplicate entity type "${t.name}"`, path: ["contributes", "entityTypes", i, "name"] });
      seen.add(t.name);
    });
    const annotated = new Set<string>();
    (c.annotations ?? []).forEach((a, i) =>
      a.on.forEach((k, j) => {
        if (annotated.has(k)) ctx.addIssue({ code: "custom", message: `"${k}" is annotated twice; one annotation per kind`, path: ["contributes", "annotations", i, "on", j] });
        annotated.add(k);
      }),
    );
    // Writing to the graph is a permission the operator sees before approving.
    if ((types.length > 0 || annotated.size > 0) && !m.permissions.includes("graph:write")) {
      ctx.addIssue({ code: "custom", message: "entity types and annotations need the graph:write permission", path: ["permissions"] });
    }
    for (const issue of checkContributions(m)) ctx.addIssue({ code: "custom", message: issue.message, path: issue.path });
  });
export type PluginManifest = z.infer<typeof PluginManifest>;

/** Why a plugin is not running: a code the interface turns into a sentence, plus technical detail. */
export const PLUGIN_REASONS = [
  "INVALID_JSON",
  "INVALID_MANIFEST",
  "INVALID_PACKAGE",
  "DUPLICATE_ID",
  "INCOMPATIBLE_API",
  "INCOMPATIBLE_ENGINE",
  "NOT_APPROVED",
  "MODIFIED",
  "CRASH_ON_ACTIVATE",
  "ACTIVATION_FAILED",
  "ACTIVATION_TIMEOUT",
  "LEVEL_UNAVAILABLE",
  "TOO_MANY_ERRORS",
  "TOO_MANY_TIMEOUTS",
  "TOO_MANY_CRASHES",
  "DISABLED_BY_USER",
  "SAFE_MODE",
  /** Its database could not be opened or migrated; the data was left as it was. */
  "STORAGE_FAILED",
] as const;
export type PluginReasonCode = (typeof PLUGIN_REASONS)[number];

/** Whether `version` satisfies an engine range ("*", exact, ">=x.y.z", "^x.y.z"). Unknown forms do not. */
export function engineSatisfies(range: string, version: string): boolean {
  const parse = (v: string): [number, number, number] | undefined => {
    const m = /^(\d+)\.(\d+)\.(\d+)/.exec(v.trim());
    return m ? [Number(m[1]), Number(m[2]), Number(m[3])] : undefined;
  };
  const cmp = (a: [number, number, number], b: [number, number, number]) => a[0] - b[0] || a[1] - b[1] || a[2] - b[2];
  const r = range.trim();
  const v = parse(version);
  if (!v) return false;
  if (r === "*" || r === "") return true;
  if (r.startsWith(">=")) {
    const min = parse(r.slice(2));
    return Boolean(min && cmp(v, min) >= 0);
  }
  if (r.startsWith("^")) {
    const min = parse(r.slice(1));
    return Boolean(min && v[0] === min[0] && cmp(v, min) >= 0);
  }
  const exact = parse(r);
  return Boolean(exact && cmp(v, exact) === 0);
}
