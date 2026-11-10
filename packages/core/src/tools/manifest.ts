import {
  EdgeType,
  EntityKind,
  type IngestBatch,
  IngestItem,
  INGEST_FORMAT,
  isIp,
  isKeyedKind,
  naturalKeyFor,
  RiskLevel,
} from "@penteos/schema";
import { z } from "zod";

/**
 * Tool manifests. A manifest teaches Penteos how to
 * use a tool: how to recognize the binary, where the targets are in its arguments, how risky it
 * is, how to install it and how to map its output into the graph.
 *
 * Manifests are DATA, never code: mapping rules are templates and regular expressions, so a
 * manifest written by an agent cannot execute anything. That is what makes them safe to author
 * dynamically (an agent proposes one, a human approves it).
 */

const Template = z.string().max(500);
const KeyTemplate = z.record(z.string(), Template);
const RefTemplate = z.object({ kind: EntityKind, key: KeyTemplate });

const Emit = z.discriminatedUnion("op", [
  z.object({
    op: z.literal("upsert"),
    kind: EntityKind,
    key: KeyTemplate,
    attributes: z.record(z.string(), z.unknown()).optional(),
    confidence: z.number().min(0).max(1).optional(),
  }),
  z.object({ op: z.literal("relate"), type: EdgeType, from: RefTemplate, to: RefTemplate }),
  z.object({
    op: z.literal("observe"),
    title: Template,
    sourceRule: Template,
    affects: z.array(RefTemplate).min(1),
    severityHint: Template.optional(),
    detail: Template.optional(),
    location: Template.optional(),
  }),
]);
export type ManifestEmit = z.infer<typeof Emit>;

const Rule = z.object({
  /** For "lines" output: regex applied to each line; named groups become fields. */
  match: z.string().max(500).optional(),
  /** Regex flags for `match`; only "i" (case-insensitive) is allowed. */
  flags: z.enum(["i"]).optional(),
  /** For "jsonl" output: field conditions. A value of "*" means "present and not empty". */
  when: z.record(z.string(), z.union([z.string(), z.number(), z.boolean()])).optional(),
  /** Repeat the emits for each element of an array field, available as {{item}}. */
  each: z.string().optional(),
  emit: z.array(Emit).min(1).max(20),
});

export const ToolManifest = z.object({
  name: z.string().regex(/^[a-z0-9][a-z0-9_-]{0,40}$/),
  version: z.string().regex(/^[\w.+-]+$/).default("0.1.0"),
  description: z.string().min(1).max(300),
  /** Binary names or paths ("~/go/bin/httpx"); the first one whose identity matches is used. */
  binaries: z.array(z.string().min(1)).min(1),
  /** How to tell the real tool from a homonym (e.g. ProjectDiscovery httpx vs Python httpx). */
  identity: z.object({ args: z.array(z.string()), pattern: z.string() }).optional(),
  risk: RiskLevel,
  /** MITRE ATT&CK techniques this tool's use corresponds to. */
  attack: z.array(z.string().regex(/^T\d{4}(\.\d{3})?$/)).default([]),
  targets: z
    .object({
      /** Flags whose value is a target: ["-u", "-d", "--url"]. Comma-separated values are split. */
      flags: z.array(z.string()).default([]),
      /** Whether bare arguments (not flags or flag values) are targets. */
      positional: z.boolean().default(false),
      /** Flags that read targets from a file: their presence makes targets unverifiable. */
      fileFlags: z.array(z.string()).default([]),
      /** Bare words that are never targets (record types, protocol names…), case-insensitive. */
      ignore: z.array(z.string()).default([]),
    })
    .default({ flags: [], positional: false, fileFlags: [], ignore: [] }),
  /** Flags that take a value, so their values are not mistaken for positional targets. */
  valueFlags: z.array(z.string()).default([]),
  /**
   * Flag/value pairs added when the command does not set that flag: polite defaults (request rate,
   * concurrency) so a scan does not get the tester's IP banned. Passing the flag overrides them.
   */
  defaults: z.array(z.tuple([z.string(), z.string()])).default([]),
  /** How tool.run builds a command for a list of targets. */
  invoke: z
    .object({ base: z.array(z.string()).default([]), perTarget: z.array(z.string()).min(1) })
    .optional(),
  output: z
    .object({
      format: z.enum(["jsonl", "lines"]),
      /** Arguments appended when missing, to get parseable output (e.g. ["-jsonl"]). */
      ensureArgs: z.array(z.string()).default([]),
      rules: z.array(Rule).min(1).max(30),
    })
    .optional(),
  install: z
    .discriminatedUnion("method", [
      z.object({ method: z.literal("go"), package: z.string().regex(/^[\w./-]+@[\w.-]+$/) }),
      // Package names differ between distributions (dig: dnsutils / bind / bind-utils).
      z.object({
        method: z.literal("system"),
        packages: z.partialRecord(z.enum(["apt", "pacman", "dnf", "zypper", "brew"]), z.string().regex(/^[\w.+-]+$/)),
      }),
      z.object({ method: z.literal("manual"), command: z.string().min(1) }),
    ])
    .optional(),
});
export type ToolManifest = z.infer<typeof ToolManifest>;

/** Validates a manifest, including that every regex compiles. Throws with a readable message. */
export function validateManifest(input: unknown): ToolManifest {
  const manifest = ToolManifest.parse(input);
  for (const rule of manifest.output?.rules ?? []) {
    if (rule.match) new RegExp(rule.match, rule.flags);
    if (manifest.output?.format === "lines" && !rule.match) throw new Error("rules of a 'lines' manifest need a 'match' regex");
  }
  if (manifest.identity) new RegExp(manifest.identity.pattern);
  return manifest;
}

// ---------------------------------------------------------------------------------------------
// Targets
// ---------------------------------------------------------------------------------------------

export function manifestTargets(manifest: ToolManifest, argv: string[]): { targets: string[]; unchecked?: string } {
  const targets: string[] = [];
  const valueFlags = new Set([...manifest.valueFlags, ...manifest.targets.flags, ...manifest.targets.fileFlags]);
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i]!;
    if (arg.startsWith("-")) {
      const [flag, inline] = arg.includes("=") ? [arg.slice(0, arg.indexOf("=")), arg.slice(arg.indexOf("=") + 1)] : [arg, undefined];
      const value = valueFlags.has(flag!) && inline === undefined ? argv[++i] : inline;
      if (manifest.targets.fileFlags.includes(flag!)) return { targets, unchecked: `targets read from a file (${flag} ${value ?? ""})` };
      if (manifest.targets.flags.includes(flag!) && value) targets.push(...value.split(",").map((v) => v.trim()).filter(Boolean));
      continue;
    }
    const ignored = manifest.targets.ignore.some((w) => w.toLowerCase() === arg.toLowerCase());
    if (manifest.targets.positional && !ignored && !arg.startsWith("+") && !arg.startsWith("@")) targets.push(arg);
  }
  return { targets: [...new Set(targets)] };
}

/** argv for tool.run: base args, then perTarget args for each target. */
export function manifestInvocation(manifest: ToolManifest, targets: string[]): string[] {
  if (!manifest.invoke) throw new Error(`${manifest.name} has no 'invoke' section; pass explicit args`);
  return [...manifest.invoke.base, ...targets.flatMap((t) => manifest.invoke!.perTarget.map((a) => a.replaceAll("{{target}}", t)))];
}

/** The manifest's polite defaults for the flags the command does not set itself. */
export function withDefaults(manifest: ToolManifest, argv: string[]): string[] {
  const extra = manifest.defaults.filter(([flag]) => !argv.some((a) => a === flag || a.startsWith(`${flag}=`))).flat();
  return [...argv, ...extra];
}

export function withOutputArgs(manifest: ToolManifest, argv: string[]): string[] {
  const missing = (manifest.output?.ensureArgs ?? []).filter((a) => !argv.includes(a));
  return [...argv, ...missing];
}

// ---------------------------------------------------------------------------------------------
// Output → ingest batch
// ---------------------------------------------------------------------------------------------

type Scope = Record<string, unknown>;

function lookup(scope: Scope, path: string): unknown {
  return path.split(".").reduce<unknown>((value, part) => (value && typeof value === "object" ? (value as Record<string, unknown>)[part] : undefined), scope);
}

function toUrl(value: string): URL | undefined {
  try {
    return new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(value) ? value : `http://${value}`);
  } catch {
    return undefined;
  }
}

const FILTERS: Record<string, (v: unknown) => unknown> = {
  lower: (v) => String(v).toLowerCase(),
  upper: (v) => String(v).toUpperCase(),
  trim: (v) => String(v).trim(),
  /** "https://a.b:8443/x" or "a.b:8443" → "a.b" */
  host: (v) => toUrl(String(v))?.hostname.replace(/^\[|\]$/g, ""),
  /** URL → port, with scheme defaults */
  port: (v) => {
    const u = toUrl(String(v));
    return u ? Number(u.port || (u.protocol === "https:" ? 443 : 80)) : undefined;
  },
  origin: (v) => toUrl(String(v))?.origin,
  path: (v) => toUrl(String(v))?.pathname,
  /** "a.b." → "a.b" (DNS answers) */
  undot: (v) => String(v).replace(/\.$/, ""),
  number: (v) => Number(v),
  /** keeps the value only if it is an IP address */
  ip: (v) => (isIp(String(v)) ? String(v) : undefined),
  /** keeps the value only if it is NOT an IP address */
  name: (v) => (isIp(String(v)) ? undefined : String(v)),
};

// Field paths may contain dashes (nuclei uses "matched-at", "template-id").
const WHOLE = /^\{\{\s*([\w.-]+)((?:\s*\|\s*\w+)*)\s*\}\}$/;
const PART = /\{\{\s*([\w.-]+)((?:\s*\|\s*\w+)*)\s*\}\}/g;

function evaluate(scope: Scope, path: string, filters: string): unknown {
  let value = lookup(scope, path);
  for (const f of filters.split("|").map((x) => x.trim()).filter(Boolean)) {
    if (value === undefined || value === null || value === "") return undefined;
    const fn = FILTERS[f];
    if (!fn) throw new Error(`unknown filter "${f}"`);
    value = fn(value);
  }
  return value;
}

class Missing extends Error {}

/** Renders templates; a whole-value template keeps the raw type (arrays, numbers). */
function render(value: unknown, scope: Scope): unknown {
  if (typeof value === "string") {
    const whole = WHOLE.exec(value);
    if (whole) {
      const v = evaluate(scope, whole[1]!, whole[2] ?? "");
      if (v === undefined || v === null || v === "") throw new Missing();
      return v;
    }
    return value.replace(PART, (_m, path: string, filters: string) => {
      const v = evaluate(scope, path, filters ?? "");
      if (v === undefined || v === null || v === "") throw new Missing();
      return String(v);
    });
  }
  if (Array.isArray(value)) return value.map((v) => render(v, scope));
  if (value && typeof value === "object") return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, render(v, scope)]));
  return value;
}

/** Optional attributes: a missing value drops that attribute instead of the whole item. */
function renderAttributes(attributes: Record<string, unknown>, scope: Scope): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(attributes)) {
    try {
      out[k] = render(v, scope);
    } catch (e) {
      if (!(e instanceof Missing)) throw e;
    }
  }
  return out;
}

function matches(when: Record<string, string | number | boolean> | undefined, scope: Scope): boolean {
  if (!when) return true;
  return Object.entries(when).every(([path, expected]) => {
    const v = lookup(scope, path);
    if (expected === "*") return v !== undefined && v !== null && v !== "" && !(Array.isArray(v) && v.length === 0);
    return v === expected || String(v) === String(expected);
  });
}

/** One bad value (a malformed hostname in a tool's output) must not sink the whole batch. */
function keysAreValid(item: IngestBatch["items"][number], context?: string): boolean {
  const refs =
    item.op === "upsert" ? [{ kind: item.kind, key: item.key }] : item.op === "relate" ? [item.from, item.to] : item.op === "observe" ? item.affects : [];
  try {
    for (const ref of refs) if (isKeyedKind(ref.kind)) naturalKeyFor(ref.kind, ref.key, context);
    return true;
  } catch {
    return false;
  }
}

export interface ManifestParseResult {
  batch: IngestBatch;
  /** Lines or items that could not be mapped (missing fields, invalid values). */
  skipped: number;
}

export function parseWithManifest(
  manifest: ToolManifest,
  output: string,
  options: {
    rawIds: string[];
    runId?: string;
    networkContext?: string;
    observedAt?: string;
    /** Invocation context available to templates: {{target}} is the run's first target. */
    vars?: { target?: string; targets?: string[] };
  },
): ManifestParseResult {
  if (!manifest.output) throw new Error(`${manifest.name} has no output mapping`);
  const items: IngestBatch["items"] = [];
  let skipped = 0;
  const compiled = manifest.output.rules.map((rule) => ({ rule, re: rule.match ? new RegExp(rule.match, rule.flags) : undefined }));

  for (const line of output.split("\n")) {
    const text = line.trim();
    if (!text) continue;
    let base: Scope | undefined;
    if (manifest.output.format === "jsonl") {
      if (!text.startsWith("{")) continue;
      try {
        base = JSON.parse(text) as Scope;
      } catch {
        continue;
      }
    }
    for (const { rule, re } of compiled) {
      let scope: Scope;
      const now = { _now: options.observedAt ?? new Date().toISOString(), ...(options.vars ?? {}) };
      if (re) {
        const m = re.exec(text);
        if (!m) continue;
        scope = { ...now, ...(base ?? {}), line: text, ...Object.fromEntries(m.slice(1).map((g, i) => [String(i + 1), g])), ...(m.groups ?? {}) };
      } else {
        scope = { ...now, ...(base ?? {}), line: text };
      }
      if (!matches(rule.when, scope)) continue;
      const each = rule.each ? lookup(scope, rule.each) : undefined;
      const scopes = rule.each ? (Array.isArray(each) ? each.map((item) => ({ ...scope, item })) : []) : [scope];
      for (const s of scopes) {
        for (const emit of rule.emit) {
          try {
            const rendered =
              emit.op === "upsert"
                ? { op: "upsert", kind: emit.kind, key: render(emit.key, s), ...(emit.attributes ? { attributes: renderAttributes(emit.attributes, s) } : {}), ...(emit.confidence !== undefined ? { confidence: emit.confidence } : {}) }
                : emit.op === "relate"
                  ? { op: "relate", type: emit.type, from: { kind: emit.from.kind, key: render(emit.from.key, s) }, to: { kind: emit.to.kind, key: render(emit.to.key, s) } }
                  : {
                      op: "observe",
                      title: render(emit.title, s),
                      sourceRule: render(emit.sourceRule, s),
                      affects: emit.affects.map((a) => ({ kind: a.kind, key: render(a.key, s) })),
                      ...(emit.severityHint ? (() => { try { return { severityHint: render(emit.severityHint, s) }; } catch { return {}; } })() : {}),
                      ...(emit.detail ? (() => { try { return { detail: render(emit.detail, s) }; } catch { return {}; } })() : {}),
                      ...(emit.location ? (() => { try { return { location: render(emit.location, s) }; } catch { return {}; } })() : {}),
                    };
            const parsed = IngestItem.safeParse(rendered);
            if (parsed.success && keysAreValid(parsed.data, options.networkContext)) items.push(parsed.data);
            else skipped++;
          } catch (e) {
            if (e instanceof Missing) skipped++;
            else throw e;
          }
        }
      }
    }
  }

  return {
    batch: {
      format: INGEST_FORMAT,
      source: { parser: `manifest:${manifest.name}@${manifest.version}`, tool: manifest.name },
      ...(options.runId ? { runId: options.runId } : {}),
      rawIds: options.rawIds,
      ...(options.networkContext ? { networkContext: options.networkContext } : {}),
      observedAt: options.observedAt ?? new Date().toISOString(),
      items,
    },
    skipped,
  };
}
