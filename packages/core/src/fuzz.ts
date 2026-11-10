import { readFileSync, statSync } from "node:fs";

/**
 * The fuzzer (Intruder-style): a raw request template with positions marked §like this§, payload
 * sets, an attack type, and an engine that sends the requests with bounded concurrency and
 * flags what behaves differently from the baseline (the request with the original values).
 */

export const MARK = "§";

export type AttackType = "sniper" | "battering_ram" | "pitchfork" | "cluster_bomb";

export type PayloadSource =
  | { type: "list"; items: string[] }
  | { type: "numbers"; from: number; to: number; step?: number; pad?: number }
  | { type: "file"; path: string }
  | { type: "builtin"; name: keyof typeof BUILTIN };

export interface PayloadProcessing {
  prefix?: string;
  suffix?: string;
  encode?: "none" | "url" | "url_all" | "base64" | "hex" | "html";
}

/** Generic lists to get started (no exploit payloads: those come from the operator's wordlists). */
export const BUILTIN = {
  usuarios: ["admin", "administrator", "root", "test", "user", "guest", "demo", "dev", "support", "info", "operator", "manager", "backup", "sysadmin", "webmaster"],
  contraseñas_debiles: ["admin", "password", "123456", "12345678", "qwerty", "letmein", "welcome", "changeme", "Password1", "admin123", "root", "toor", "test", "guest", "1234"],
  rutas: ["admin", "login", "api", "api/v1", "backup", "config", "debug", "test", "dev", "old", "uploads", "files", ".git/HEAD", ".env", "robots.txt", "sitemap.xml", "server-status", "phpinfo.php", "swagger.json", "openapi.json", "graphql", "actuator/health", "console", "wp-admin", "status"],
  metodos: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD", "TRACE"],
  booleanos: ["true", "false", "1", "0", "yes", "no", "null", "undefined", "[]", "{}"],
} as const;

const MAX_FILE_LINES = 200_000;
const MAX_FILE_BYTES = 50 * 1024 * 1024;

/** The template split at the markers: fixed text and the default value of each position. */
export function parseTemplate(template: string): { parts: string[]; defaults: string[] } {
  const pieces = template.split(MARK);
  if (pieces.length % 2 === 0) throw new Error(`there is an unclosed ${MARK}: each position goes between two ${MARK}`);
  const parts: string[] = [];
  const defaults: string[] = [];
  pieces.forEach((p, i) => (i % 2 === 0 ? parts.push(p) : defaults.push(p)));
  return { parts, defaults };
}

export function render(parts: string[], values: string[]): string {
  let out = parts[0]!;
  for (let i = 0; i < values.length; i++) out += values[i]! + parts[i + 1]!;
  return out;
}

export function payloads(source: PayloadSource): string[] {
  switch (source.type) {
    case "list":
      return source.items;
    case "builtin":
      return [...(BUILTIN[source.name] ?? [])];
    case "numbers": {
      const step = source.step && source.step !== 0 ? Math.abs(source.step) : 1;
      const out: string[] = [];
      const dir = source.to >= source.from ? 1 : -1;
      for (let n = source.from; dir > 0 ? n <= source.to : n >= source.to; n += step * dir) {
        out.push(source.pad ? String(n).padStart(source.pad, "0") : String(n));
        if (out.length > MAX_FILE_LINES) throw new Error(`the range has more than ${MAX_FILE_LINES} numbers`);
      }
      return out;
    }
    case "file": {
      const st = statSync(source.path);
      if (!st.isFile()) throw new Error(`${source.path} is not a file`);
      if (st.size > MAX_FILE_BYTES) throw new Error(`${source.path} is larger than 50 MB`);
      const lines = readFileSync(source.path, "utf8").split(/\r?\n/).filter((l) => l.length > 0 && !l.startsWith("#"));
      if (lines.length > MAX_FILE_LINES) throw new Error(`${source.path} has more than ${MAX_FILE_LINES} lines`);
      return lines;
    }
  }
}

export function processPayload(value: string, p: PayloadProcessing = {}): string {
  let v = `${p.prefix ?? ""}${value}${p.suffix ?? ""}`;
  switch (p.encode) {
    case "url":
      v = encodeURIComponent(v);
      break;
    case "url_all":
      v = [...Buffer.from(v, "utf8")].map((b) => `%${b.toString(16).padStart(2, "0").toUpperCase()}`).join("");
      break;
    case "base64":
      v = Buffer.from(v, "utf8").toString("base64");
      break;
    case "hex":
      v = Buffer.from(v, "utf8").toString("hex");
      break;
    case "html":
      v = v.replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);
      break;
    default:
      break;
  }
  return v;
}

export interface Combination {
  /** The value used at each position. */
  values: string[];
  /** The payloads that differ from the defaults (what the operator reads in the results). */
  payloads: string[];
  /** Sniper: which position was being tested. */
  position?: number;
}

/** How many requests an attack makes, without generating them. */
export function countCombinations(attack: AttackType, positions: number, sets: string[][]): number {
  if (positions === 0) return 0;
  switch (attack) {
    case "sniper":
      return positions * (sets[0]?.length ?? 0);
    case "battering_ram":
      return sets[0]?.length ?? 0;
    case "pitchfork":
      return Math.min(...sets.slice(0, positions).map((s) => s.length));
    case "cluster_bomb":
      return sets.slice(0, positions).reduce((n, s) => n * s.length, 1);
  }
}

/** The combinations, lazily (a cluster bomb can be huge). */
export function* combinations(attack: AttackType, defaults: string[], sets: string[][]): Generator<Combination> {
  const n = defaults.length;
  if (attack === "sniper") {
    for (let pos = 0; pos < n; pos++) {
      for (const p of sets[0] ?? []) {
        const values = [...defaults];
        values[pos] = p;
        yield { values, payloads: [p], position: pos };
      }
    }
  } else if (attack === "battering_ram") {
    for (const p of sets[0] ?? []) yield { values: defaults.map(() => p), payloads: [p] };
  } else if (attack === "pitchfork") {
    const len = Math.min(...sets.slice(0, n).map((s) => s.length));
    for (let i = 0; i < len; i++) {
      const values = sets.slice(0, n).map((s) => s[i]!);
      yield { values, payloads: values };
    }
  } else {
    const lists = sets.slice(0, n);
    const idx = lists.map(() => 0);
    if (lists.some((l) => l.length === 0)) return;
    while (true) {
      const values = idx.map((i, k) => lists[k]![i]!);
      yield { values, payloads: values };
      let k = n - 1;
      while (k >= 0) {
        idx[k]!++;
        if (idx[k]! < lists[k]!.length) break;
        idx[k] = 0;
        k--;
      }
      if (k < 0) return;
    }
  }
}

// ---------------------------------------------------------------------------------------------
// Results

export interface FuzzResult {
  index: number;
  payloads: string[];
  position?: number;
  status?: number;
  length: number;
  words: number;
  lines: number;
  timeMs: number;
  error?: string;
  /** Grep expressions found in the response. */
  matches: string[];
  /** Values captured by the extract expression. */
  extracted?: string;
  /** Why it looks different from the baseline. */
  anomalies: string[];
  rawId?: string;
}

export function measure(body: string): { length: number; words: number; lines: number } {
  return { length: Buffer.byteLength(body), words: body.split(/\s+/).filter(Boolean).length, lines: body.split("\n").length };
}

/** Differences from the baseline that are worth a look. */
export function anomaliesOf(r: Pick<FuzzResult, "status" | "length" | "timeMs" | "error" | "matches">, base: Pick<FuzzResult, "status" | "length" | "timeMs"> | undefined, medianTime: number): string[] {
  const out: string[] = [];
  if (r.error) out.push("error");
  if (r.matches.length) out.push("match");
  if (!base) return out;
  if (r.status !== base.status) out.push(`status ${base.status ?? "-"}→${r.status ?? "-"}`);
  const delta = Math.abs(r.length - base.length);
  if (delta > Math.max(50, base.length * 0.05)) out.push(`size ${r.length > base.length ? "+" : "−"}${delta}`);
  if (medianTime > 0 && r.timeMs > Math.max(medianTime * 3, medianTime + 1500)) out.push(`slow ${r.timeMs} ms`);
  return out;
}
