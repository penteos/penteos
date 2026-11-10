/**
 * The template language of declarative plugins. Values in a manifest may hold
 * `{{ path | filter:arg }}`; there is no code, no loops and no function calls - only reading what
 * the core puts in scope and a fixed set of pure filters. A string that is exactly one `{{…}}` keeps
 * the value's type (a number stays a number, a list stays a list); otherwise it is text.
 *
 * Secrets (`{{secret:name}}`, secret settings) are *tainted*: they can only end up inside an HTTP
 * request, which the core then redacts from what comes back. Anywhere else they are an error.
 */

export class SecretValue {
  constructor(readonly value: string) {}
  toJSON(): string {
    return "«secret»";
  }
  toString(): string {
    return "«secret»";
  }
}

export class TemplateError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "TemplateError";
  }
}

type Literal = string | number | boolean | null;
type Arg = { lit: Literal } | { path: PathExpr };
interface PathExpr {
  root: string;
  /** For `secret:name`. */
  secret?: string;
  segments: Array<string | number>;
}
interface Expr {
  head: { lit: Literal } | { path: PathExpr };
  filters: Array<{ name: string; args: Arg[] }>;
}
type Part = string | Expr;

export const TEMPLATE_ROOTS = ["input", "steps", "vars", "item", "index", "engagement", "entity", "event", "settings", "result", "secret"] as const;

const MAX_OUTPUT = 1024 * 1024;

// ---------------------------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------------------------

const cache = new Map<string, Part[]>();

export function parseTemplate(text: string): Part[] {
  const hit = cache.get(text);
  if (hit) return hit;
  const parts: Part[] = [];
  let i = 0;
  while (i < text.length) {
    const open = text.indexOf("{{", i);
    if (open < 0) {
      parts.push(text.slice(i));
      break;
    }
    if (open > i) parts.push(text.slice(i, open));
    const close = text.indexOf("}}", open + 2);
    if (close < 0) throw new TemplateError(`unclosed {{ in "${text.slice(open, open + 40)}"`);
    parts.push(parseExpr(text.slice(open + 2, close).trim()));
    i = close + 2;
  }
  if (cache.size > 5000) cache.clear();
  cache.set(text, parts);
  return parts;
}

function parseExpr(src: string): Expr {
  if (!src) throw new TemplateError("empty {{ }}");
  const pieces = splitTop(src, "|");
  const head = parseOperand(pieces[0]!.trim());
  const filters = pieces.slice(1).map((p) => {
    const [name, ...args] = splitTop(p.trim(), ":");
    if (!name || !/^[a-z_][a-z0-9_]*$/.test(name.trim())) throw new TemplateError(`bad filter "${p.trim()}"`);
    const f = name.trim();
    if (!(f in FILTERS)) throw new TemplateError(`unknown filter "${f}" (known: ${Object.keys(FILTERS).join(", ")})`);
    return { name: f, args: args.map((a) => parseOperand(a.trim())) };
  });
  return { head, filters };
}

/** Splits on a separator outside quotes. `secret:x` is one operand, so ":" right after `secret` is kept. */
function splitTop(src: string, sep: string): string[] {
  const out: string[] = [];
  let cur = "";
  let quote: string | null = null;
  for (let i = 0; i < src.length; i++) {
    const c = src[i]!;
    if (quote) {
      cur += c;
      if (c === "\\" && i + 1 < src.length) {
        cur += src[++i];
        continue;
      }
      if (c === quote) quote = null;
      continue;
    }
    if (c === '"' || c === "'") {
      quote = c;
      cur += c;
      continue;
    }
    if (c === sep && !(sep === ":" && cur.trim() === "secret")) {
      out.push(cur);
      cur = "";
      continue;
    }
    cur += c;
  }
  if (quote) throw new TemplateError(`unclosed quote in "${src}"`);
  out.push(cur);
  return out;
}

function parseOperand(src: string): { lit: Literal } | { path: PathExpr } {
  if (src === "") throw new TemplateError("missing value");
  if (/^"(?:[^"\\]|\\.)*"$/.test(src) || /^'(?:[^'\\]|\\.)*'$/.test(src)) {
    // \n and \t are a new line and a tab; any other escaped character stands for itself.
    return { lit: src.slice(1, -1).replace(/\\(.)/g, (_m, c: string) => (c === "n" ? "\n" : c === "t" ? "\t" : c)) };
  }
  if (/^-?\d+(\.\d+)?$/.test(src)) return { lit: Number(src) };
  if (src === "true" || src === "false") return { lit: src === "true" };
  if (src === "null") return { lit: null };
  const secret = /^secret:([a-z0-9_-]+)$/.exec(src);
  if (secret) return { path: { root: "secret", secret: secret[1]!, segments: [] } };
  const m = /^([a-z][a-zA-Z0-9_]*)((?:\.[a-zA-Z_][a-zA-Z0-9_-]*|\[\d+\])*)$/.exec(src);
  if (!m) throw new TemplateError(`cannot read "${src}": expected a path like input.ip, a quoted text or a number`);
  const root = m[1]!;
  // Which names exist depends on where the template is (a loop adds its variable): the manifest
  // check decides that; here any name parses, and an unknown one reads as nothing.
  if (root === "secret") throw new TemplateError("write secrets as secret:<name>");
  const segments: Array<string | number> = [];
  for (const s of m[2]!.matchAll(/\.([a-zA-Z_][a-zA-Z0-9_-]*)|\[(\d+)\]/g)) segments.push(s[1] !== undefined ? s[1] : Number(s[2]));
  return { path: { root, segments } };
}

// ---------------------------------------------------------------------------------------------
// Static analysis: what a template reads (to validate a manifest before it runs)
// ---------------------------------------------------------------------------------------------

export interface TemplateRef {
  root: string;
  /** The first segment (input.<field>, steps.<id>, settings.<field>) or the secret name. */
  name?: string;
  secret: boolean;
}

/** Every reference in a value (deep), or throws a TemplateError naming the bad template. */
export function templateRefs(value: unknown): TemplateRef[] {
  const out: TemplateRef[] = [];
  const visit = (v: unknown, depth: number) => {
    if (depth > 30) throw new TemplateError("value nested too deep");
    if (typeof v === "string") {
      if (!v.includes("{{")) return;
      for (const part of parseTemplate(v)) {
        if (typeof part === "string") continue;
        for (const op of [part.head, ...part.filters.flatMap((f) => f.args)]) {
          if (!("path" in op)) continue;
          const p = op.path;
          const first = p.segments[0];
          out.push({ root: p.root, ...(p.secret ? { name: p.secret } : typeof first === "string" ? { name: first } : {}), secret: p.root === "secret" });
        }
      }
    } else if (Array.isArray(v)) v.forEach((x) => visit(x, depth + 1));
    else if (v && typeof v === "object") for (const x of Object.values(v)) visit(x, depth + 1);
  };
  visit(value, 0);
  return out;
}

// ---------------------------------------------------------------------------------------------
// Evaluation
// ---------------------------------------------------------------------------------------------

export interface RenderOptions {
  /** Inside an HTTP request: secrets may be used (the caller collects them to redact). */
  allowSecrets?: boolean;
  /** Values of `{{secret:name}}`, looked up only when used. */
  secret?: (name: string) => string | undefined;
  /** Every secret value that went into the output (so the caller can redact it from responses). */
  usedSecrets?: Set<string>;
}

export type Scope = Record<string, unknown>;

/** Renders a value (deep): strings with templates are evaluated, everything else is kept. */
export function renderValue(value: unknown, scope: Scope, options: RenderOptions = {}): unknown {
  const visit = (v: unknown, depth: number): unknown => {
    if (depth > 30) throw new TemplateError("value nested too deep");
    if (typeof v === "string") return v.includes("{{") ? renderString(v, scope, options) : v;
    if (Array.isArray(v)) return v.map((x) => visit(x, depth + 1));
    if (v && typeof v === "object") return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, visit(x, depth + 1)]));
    return v;
  };
  return reveal(visit(value, 0), options);
}

function renderString(text: string, scope: Scope, options: RenderOptions): unknown {
  const parts = parseTemplate(text);
  if (parts.length === 1 && typeof parts[0] !== "string") return evalExpr(parts[0]!, scope, options);
  let out = "";
  for (const p of parts) {
    if (typeof p === "string") out += p;
    else {
      const v = evalExpr(p, scope, options);
      if (v instanceof SecretValue) {
        if (!options.allowSecrets) throw new TemplateError("secrets can only be used inside an HTTP request");
        options.usedSecrets?.add(v.value);
        out += v.value;
      } else out += v === undefined || v === null ? "" : typeof v === "object" ? JSON.stringify(v) : String(v);
    }
    if (out.length > MAX_OUTPUT) throw new TemplateError("template output too large");
  }
  return out;
}

/** A secret left as a value (a whole-string template) is unwrapped only where allowed. */
function reveal(v: unknown, options: RenderOptions): unknown {
  if (v instanceof SecretValue) {
    if (!options.allowSecrets) throw new TemplateError("secrets can only be used inside an HTTP request");
    options.usedSecrets?.add(v.value);
    return v.value;
  }
  if (Array.isArray(v)) return v.map((x) => reveal(x, options));
  if (v && typeof v === "object" && Object.getPrototypeOf(v) === Object.prototype) {
    return Object.fromEntries(Object.entries(v).map(([k, x]) => [k, reveal(x, options)]));
  }
  return v;
}

function evalOperand(op: { lit: Literal } | { path: PathExpr }, scope: Scope, options: RenderOptions): unknown {
  if ("lit" in op) return op.lit;
  const p = op.path;
  if (p.root === "secret") {
    const value = options.secret?.(p.secret!);
    if (value === undefined) throw new TemplateError(`secret "${p.secret}" is not set in this project`);
    return new SecretValue(value);
  }
  let cur: unknown = scope[p.root];
  for (const seg of p.segments) {
    if (cur === null || cur === undefined) return undefined;
    if (cur instanceof SecretValue) return cur;
    if (typeof seg === "number") cur = Array.isArray(cur) ? cur[seg] : undefined;
    else if (seg === "length" && (Array.isArray(cur) || typeof cur === "string")) cur = cur.length;
    else cur = typeof cur === "object" && Object.hasOwn(cur as object, seg) ? (cur as Record<string, unknown>)[seg] : undefined;
  }
  return cur;
}

function evalExpr(e: Expr, scope: Scope, options: RenderOptions): unknown {
  let v = evalOperand(e.head, scope, options);
  for (const f of e.filters) {
    const args = f.args.map((a) => evalOperand(a, scope, options));
    // Taint travels through filters: whatever a secret touches (as the value or as an argument,
    // like user:token for Basic auth) is a secret too.
    const tainted = v instanceof SecretValue || args.some((a) => a instanceof SecretValue);
    if (tainted) {
      const plain = (x: unknown) => (x instanceof SecretValue ? x.value : x);
      const out = FILTERS[f.name]!(plain(v), args.map(plain));
      v = new SecretValue(typeof out === "string" ? out : JSON.stringify(out));
    } else v = FILTERS[f.name]!(v, args);
  }
  return v;
}

// ---------------------------------------------------------------------------------------------
// Filters: pure, total (bad input gives null or the value back, never a crash)
// ---------------------------------------------------------------------------------------------

const num = (v: unknown): number | null => {
  const n = typeof v === "number" ? v : typeof v === "string" && v.trim() !== "" ? Number(v) : NaN;
  return Number.isFinite(n) ? n : null;
};
const str = (v: unknown): string => (v === null || v === undefined ? "" : typeof v === "object" ? JSON.stringify(v) : String(v));
const isEmpty = (v: unknown) => v === null || v === undefined || v === "" || (Array.isArray(v) && v.length === 0) || (typeof v === "object" && v !== null && Object.keys(v).length === 0);
const equal = (a: unknown, b: unknown) => JSON.stringify(a) === JSON.stringify(b) || (num(a) !== null && num(a) === num(b) && typeof a !== "boolean" && typeof b !== "boolean");

/** Reads a dotted path (`attributes.ip`) from a value; anything missing is undefined. */
function at(value: unknown, path: string): unknown {
  let cur = value;
  for (const seg of path.split(".")) {
    if (cur === null || typeof cur !== "object" || !Object.hasOwn(cur, seg)) return undefined;
    cur = (cur as Record<string, unknown>)[seg];
  }
  return cur;
}

function isPrivateIp(ip: string): boolean {
  const v4 = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(ip.trim());
  if (v4) {
    const [a, b] = [Number(v4[1]), Number(v4[2])];
    return a === 10 || a === 127 || a === 0 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 169 && b === 254) || (a === 100 && b >= 64 && b <= 127) || a >= 224;
  }
  const v6 = ip.trim().toLowerCase();
  if (!v6.includes(":")) return false;
  return v6 === "::1" || v6 === "::" || v6.startsWith("fc") || v6.startsWith("fd") || v6.startsWith("fe80");
}

function toBase64(s: string): string {
  const bytes = new TextEncoder().encode(s);
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}

export const FILTERS: Record<string, (v: unknown, args: unknown[]) => unknown> = {
  default: (v, [d]) => (isEmpty(v) ? d : v),
  lower: (v) => str(v).toLowerCase(),
  upper: (v) => str(v).toUpperCase(),
  trim: (v) => str(v).trim(),
  string: (v) => str(v),
  number: (v) => num(v),
  int: (v) => (num(v) === null ? null : Math.trunc(num(v)!)),
  bool: (v) => !isEmpty(v) && v !== false && v !== 0 && v !== "false",
  json: (v) => JSON.stringify(v ?? null),
  parse_json: (v) => {
    try {
      return JSON.parse(str(v));
    } catch {
      return null;
    }
  },
  length: (v) => (Array.isArray(v) || typeof v === "string" ? v.length : v && typeof v === "object" ? Object.keys(v).length : 0),
  first: (v) => (Array.isArray(v) ? v[0] : v),
  last: (v) => (Array.isArray(v) ? v[v.length - 1] : v),
  take: (v, [n]) => (Array.isArray(v) ? v.slice(0, Math.max(0, num(n) ?? 0)) : v),
  slice: (v, [a, b]) => (Array.isArray(v) || typeof v === "string" ? v.slice(num(a) ?? 0, b === undefined ? undefined : (num(b) ?? undefined)) : v),
  join: (v, [sep]) => (Array.isArray(v) ? v.map(str).join(sep === undefined ? ", " : str(sep)) : str(v)),
  split: (v, [sep]) => str(v).split(sep === undefined ? "," : str(sep)),
  pluck: (v, [k]) => (Array.isArray(v) ? v.map((x) => at(x, str(k))) : undefined),
  where: (v, [k, val]) => (Array.isArray(v) ? v.filter((x) => equal(at(x, str(k)), val)) : v),
  keys: (v) => (v && typeof v === "object" && !Array.isArray(v) ? Object.keys(v) : []),
  values: (v) => (v && typeof v === "object" && !Array.isArray(v) ? Object.values(v) : []),
  unique: (v) => (Array.isArray(v) ? [...new Map(v.map((x) => [JSON.stringify(x), x])).values()] : v),
  compact: (v) => (Array.isArray(v) ? v.filter((x) => !isEmpty(x)) : v),
  sort: (v) => (Array.isArray(v) ? [...v].sort((a, b) => (num(a) !== null && num(b) !== null ? num(a)! - num(b)! : str(a).localeCompare(str(b)))) : v),
  concat: (v, [x]) => (Array.isArray(v) ? v.concat(x ?? []) : str(v) + str(x)),
  replace: (v, [a, b]) => str(v).split(str(a)).join(str(b)),
  contains: (v, [x]) => (Array.isArray(v) ? v.some((y) => equal(y, x)) : str(v).includes(str(x))),
  starts_with: (v, [x]) => str(v).startsWith(str(x)),
  eq: (v, [x]) => equal(v, x),
  ne: (v, [x]) => !equal(v, x),
  gt: (v, [x]) => num(v) !== null && num(x) !== null && num(v)! > num(x)!,
  gte: (v, [x]) => num(v) !== null && num(x) !== null && num(v)! >= num(x)!,
  lt: (v, [x]) => num(v) !== null && num(x) !== null && num(v)! < num(x)!,
  lte: (v, [x]) => num(v) !== null && num(x) !== null && num(v)! <= num(x)!,
  not: (v) => isEmpty(v) || v === false || v === 0,
  and: (v, [x]) => !isEmpty(v) && v !== false && !isEmpty(x) && x !== false,
  or: (v, [x]) => (!isEmpty(v) && v !== false ? v : x),
  exists: (v) => v !== undefined && v !== null,
  empty: (v) => isEmpty(v),
  if: (v, [a, b]) => (!isEmpty(v) && v !== false && v !== 0 ? a : b),
  urlencode: (v) => encodeURIComponent(str(v)),
  base64: (v) => toBase64(str(v)),
  /** Private, loopback, link-local or reserved addresses (not worth asking a third party about). */
  private_ip: (v) => isPrivateIp(str(v)),
  round: (v, [d]) => (num(v) === null ? null : Number(num(v)!.toFixed(Math.min(10, Math.max(0, num(d) ?? 0))))),
};

/** Whether a rendered condition holds (for `if:` on steps). */
export function truthy(v: unknown): boolean {
  return !isEmpty(v) && v !== false && v !== 0 && v !== "false";
}
