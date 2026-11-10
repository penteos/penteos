import type { z } from "zod";

/**
 * Argument repair. Models often get an operation's input almost right:
 * a list as a JSON string, a number as text, one value where a list goes, snake_case keys. Before
 * refusing, Penteos tries those mechanical fixes; it never invents a value. If the input still
 * does not validate, the error says what each failing field expects.
 */

type Obj = Record<string, unknown>;
const isObj = (v: unknown): v is Obj => Boolean(v) && typeof v === "object" && !Array.isArray(v);

const camel = (k: string) => k.replace(/[_-]+([a-z0-9])/g, (_, c: string) => c.toUpperCase());

function at(root: unknown, path: PropertyKey[]): unknown {
  let v = root;
  for (const p of path) v = isObj(v) || Array.isArray(v) ? (v as Obj)[p as string] : undefined;
  return v;
}

function set(root: unknown, path: PropertyKey[], value: unknown): void {
  const parent = at(root, path.slice(0, -1));
  if (isObj(parent) || Array.isArray(parent)) (parent as Obj)[path.at(-1) as string] = value;
}

function parseJson(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    return undefined;
  }
}

/**
 * snake_case or kebab-case keys renamed to the camelCase the schema uses. Runs before validation:
 * an optional field spelled wrong would otherwise be dropped in silence.
 */
export function normalizeKeys(input: unknown, known: Set<string>): unknown {
  if (!isObj(input)) return input;
  let out: Obj | undefined;
  for (const k of Object.keys(input)) {
    if (known.has(k)) continue;
    const c = camel(k);
    if (c === k || !known.has(c) || c in input) continue;
    out ??= { ...input };
    out[c] = out[k];
    delete out[k];
  }
  return out ?? input;
}

/** One fix for one issue, or false when there is nothing safe to do. */
function fix(root: unknown, issue: z.core.$ZodIssue): boolean {
  const path = issue.path;
  if (issue.code === "unrecognized_keys") {
    const parent = at(root, path);
    if (!isObj(parent)) return false;
    let changed = false;
    for (const k of issue.keys) {
      const c = camel(k);
      if (c !== k && !(c in parent)) {
        parent[c] = parent[k];
        changed = true;
      }
      delete parent[k];
      changed = true;
    }
    return changed;
  }
  if (issue.code !== "invalid_type" || path.length === 0) return false;
  const value = at(root, path);
  const expected = issue.expected;
  if (value === undefined) {
    // A required field missing because the model spelled it in snake_case or kebab-case.
    const parent = at(root, path.slice(0, -1));
    const want = String(path.at(-1));
    if (!isObj(parent)) return false;
    const alias = Object.keys(parent).find((k) => k !== want && camel(k) === want);
    if (!alias) return false;
    parent[want] = parent[alias];
    delete parent[alias];
    return true;
  }
  if (typeof value === "string") {
    const s = value.trim();
    if (expected === "number" && s !== "" && Number.isFinite(Number(s))) return set(root, path, Number(s)), true;
    if (expected === "boolean" && /^(true|false)$/i.test(s)) return set(root, path, s.toLowerCase() === "true"), true;
    if (expected === "array" || expected === "object") {
      const parsed = parseJson(s);
      if (expected === "array" && Array.isArray(parsed)) return set(root, path, parsed), true;
      if (expected === "object" && isObj(parsed)) return set(root, path, parsed), true;
      if (expected === "array") return set(root, path, [value]), true;
    }
    return false;
  }
  if (expected === "array" && (typeof value === "number" || isObj(value))) return set(root, path, [value]), true;
  if (expected === "string" && (typeof value === "number" || typeof value === "boolean")) return set(root, path, String(value)), true;
  return false;
}

/** The input repaired so it validates, with what was changed; undefined when it cannot be. */
export function repairInput<T extends z.ZodType>(schema: T, raw: unknown): { data: z.infer<T>; fixes: number } | undefined {
  let input: unknown = typeof raw === "string" ? parseJson(raw) : structuredClone(raw ?? {});
  if (!isObj(input)) return undefined;
  for (let pass = 0, fixes = 0; pass < 4; pass++) {
    const r = schema.safeParse(input);
    if (r.success) return fixes ? { data: r.data, fixes } : undefined;
    const before = fixes;
    for (const issue of r.error.issues) if (fix(input, issue)) fixes++;
    if (fixes === before) return undefined;
  }
  return undefined;
}

/** Validation issues as the model needs them: field, problem and what the field expects. */
export function describeIssues(issues: z.core.$ZodIssue[], jsonSchema: Record<string, unknown>): string[] {
  const props = (jsonSchema.properties ?? {}) as Record<string, Record<string, unknown>>;
  return issues.map((i) => {
    const field = i.path.join(".") || "(input)";
    const top = props[String(i.path[0])];
    const shape = top ? ` - expects ${JSON.stringify(compact(top))}` : "";
    return `${field}: ${i.message}${shape}`;
  });
}

/** A field's JSON Schema without the descriptions, short enough for an error line. */
function compact(s: unknown): unknown {
  if (Array.isArray(s)) return s.map(compact);
  if (!isObj(s)) return s;
  const out: Obj = {};
  for (const [k, v] of Object.entries(s)) if (k !== "description" && k !== "$schema") out[k] = compact(v);
  const text = JSON.stringify(out);
  return text.length > 300 ? `${text.slice(0, 300)}…` : out;
}
