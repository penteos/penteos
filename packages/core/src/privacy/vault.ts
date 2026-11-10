import { createHash } from "node:crypto";
import type { Engagement } from "../engagement.js";

/**
 * The pseudonym vault. Each sensitive value the target sends
 * gets a marker, stable across the whole engagement: the same e-mail is always the same marker, in
 * any tool, turn or agent. The model only ever sees the marker; the real value stays here,
 * encrypted with the engagement's key, and goes back in only on the way to the target (and when a
 * person reads the result).
 *
 * Marker: «type:N» or «type:N hint», e.g. «email:7 @acme.example». The hint keeps what helps
 * the test without identifying anyone (the organisation's domain, a "valid check digit").
 */

export interface PseudonymEntry {
  marker: string;
  type: string;
  /** Sealed real value. */
  value: string;
  /** sha256(type + value): lookup without unsealing. */
  key: string;
}

interface VaultState {
  counters: Record<string, number>;
  entries: PseudonymEntry[];
}

const MARKER = /«([a-z][a-z0-9_]*):(\d+)(?: [^«»\n]{0,80})?»/g;

/** Same shape of marker anywhere in a text (what the model may write back). */
export function markersIn(text: string): string[] {
  return [...text.matchAll(MARKER)].map((m) => `${m[1]}:${m[2]}`);
}

const keyOf = (type: string, value: string) => createHash("sha256").update(`${type}\u0000${value}`).digest("hex");

/** One vault per engagement, kept in memory once loaded (writes go straight to the engagement). */
const cache = new WeakMap<Engagement, { state: VaultState; byKey: Map<string, PseudonymEntry>; byId: Map<string, PseudonymEntry> }>();

function load(e: Engagement) {
  let c = cache.get(e);
  if (!c) {
    const state = e.getState<VaultState>("pseudonyms") ?? { counters: {}, entries: [] };
    c = { state, byKey: new Map(state.entries.map((x) => [x.key, x])), byId: new Map(state.entries.map((x) => [idOf(x.marker), x])) };
    cache.set(e, c);
  }
  return c;
}

const idOf = (marker: string) => {
  const m = /^«([a-z][a-z0-9_]*):(\d+)/.exec(marker);
  return m ? `${m[1]}:${m[2]}` : marker;
};

/** The marker for a value, creating it the first time it is seen. */
export function pseudonym(e: Engagement, type: string, value: string, hint?: string): string {
  const c = load(e);
  const key = keyOf(type, value);
  const found = c.byKey.get(key);
  if (found) return found.marker;
  const n = (c.state.counters[type] ?? 0) + 1;
  c.state.counters[type] = n;
  const marker = `«${type}:${n}${hint ? ` ${hint.replace(/[«»\n]/g, "").slice(0, 60)}` : ""}»`;
  const entry: PseudonymEntry = { marker, type, value: e.seal(value), key };
  c.state.entries.push(entry);
  c.byKey.set(key, entry);
  c.byId.set(idOf(marker), entry);
  dirty.add(e);
  // Written once per batch (a whole result), not once per value: the vault can hold thousands.
  queueMicrotask(() => flushVault(e));
  return marker;
}

const dirty = new WeakSet<Engagement>();

/** Persists new markers (called after each masked result; also scheduled automatically). */
export function flushVault(e: Engagement): void {
  if (!dirty.has(e)) return;
  dirty.delete(e);
  const c = cache.get(e);
  if (c) e.setState("pseudonyms", c.state);
}

/** The real value behind a marker id ("email:7"), if Penteos issued it. */
export function realValue(e: Engagement, id: string): string | undefined {
  const entry = load(e).byId.get(id);
  return entry ? e.unseal(entry.value) : undefined;
}

export interface Restored {
  text: string;
  /** Markers that look like Penteos's but were never issued (invented or garbled by the model). */
  unknown: string[];
}

/** Replaces every marker Penteos issued by its real value; reports the ones it did not issue. */
export function restore(e: Engagement, text: string): Restored {
  const unknown: string[] = [];
  const out = text.replace(MARKER, (whole, type: string, n: string) => {
    const real = realValue(e, `${type}:${n}`);
    if (real === undefined) {
      unknown.push(whole);
      return whole;
    }
    return real;
  });
  return { text: out, unknown };
}

/** Restores markers in every string of a JSON-like value. */
export function restoreDeep(e: Engagement, value: unknown, unknown: string[] = []): unknown {
  if (typeof value === "string") {
    if (!value.includes("«")) return value;
    const r = restore(e, value);
    unknown.push(...r.unknown);
    return r.text;
  }
  if (Array.isArray(value)) return value.map((v) => restoreDeep(e, v, unknown));
  if (value && typeof value === "object") return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, restoreDeep(e, v, unknown)]));
  return value;
}

const stripAccents = (s: string) => s.normalize("NFD").replace(/[̀-ͯ]/g, "");
const variantKey = (s: string) => stripAccents(s).toLowerCase().replace(/\s+/g, " ");
const escapeRe = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");

/** Values too short or too common to look for in free text (they would hit everywhere). */
const MIN_PROPAGATE = 5;

const matchers = new WeakMap<Engagement, { size: number; byFirst: Map<string, string[]>; byVariant: Map<string, string> }>();

const firstWord = (v: string) => v.split(/[\s,]+/)[0] ?? "";

/**
 * Finds, in any text, the values the vault already holds (layer 1 of free text): a name first seen
 * in a `nombre` field is masked again wherever it appears - an error message, a page, a CSV.
 * Matches without accents and in any case; names also as "Last, First". No false positives: only
 * values already known to be the client's data. Indexed by first word, so a text is only searched
 * for the values that could be in it.
 */
export function knownValues(e: Engagement): { regexFor(text: string): RegExp | undefined; markerOf(found: string): string | undefined } {
  const c = load(e);
  let m = matchers.get(e);
  if (!m || m.size !== c.state.entries.length) {
    const byVariant = new Map<string, string>();
    for (const entry of c.state.entries) {
      let value: string;
      try {
        value = e.unseal(entry.value);
      } catch {
        continue;
      }
      if (value.length < MIN_PROPAGATE || /^\d{1,6}$/.test(value)) continue;
      // A one-word "name" (or one shaped like an identifier) is too common to chase in free text:
      // "Admin", "estado", "failedAttempts" would be masked in every page and every piece of code.
      if (entry.type === "name" && (!/\s/.test(value.trim()) || /[_\d]|\p{Ll}\p{Lu}/u.test(value))) continue;
      const variants = new Set([value, stripAccents(value)]);
      const words = value.trim().split(/\s+/);
      if (entry.type === "name" && words.length >= 2) {
        // "Ana Ejemplo Prueba" also as "Ejemplo Prueba, Ana" and "Ejemplo Prueba Ana".
        const first = words[0]!;
        const last = words.slice(1).join(" ");
        variants.add(`${last}, ${first}`);
        variants.add(`${last} ${first}`);
      }
      for (const v of variants) if (!byVariant.has(variantKey(v))) byVariant.set(variantKey(v), entry.marker);
    }
    const byFirst = new Map<string, string[]>();
    for (const v of byVariant.keys()) {
      const f = firstWord(v);
      const list = byFirst.get(f) ?? [];
      list.push(v);
      byFirst.set(f, list);
    }
    m = { size: c.state.entries.length, byFirst, byVariant };
    matchers.set(e, m);
  }
  const { byFirst, byVariant } = m;
  return {
    regexFor(text: string) {
      if (!byFirst.size) return undefined;
      // The words of the text (accent-free, lower case): only values starting with one of them can be in it.
      const words = new Set(variantKey(text).split(/[^\p{L}\p{N}@._-]+/u));
      const candidates: string[] = [];
      for (const w of words) {
        const list = byFirst.get(w);
        if (list) candidates.push(...list);
      }
      if (!candidates.length) return undefined;
      candidates.sort((a, b) => b.length - a.length);
      // Accent-insensitive: each letter matches itself with or without its accent.
      const pattern = candidates.map((v) => escapeRe(v).replace(/[aeiounc]/g, (ch) => ACCENTED[ch] ?? ch).replace(/ /g, "\\s+")).join("|");
      return new RegExp(`(?<![\\p{L}\\p{N}@._-])(?:${pattern})(?![\\p{L}\\p{N}])`, "giu");
    },
    markerOf: (found: string) => byVariant.get(variantKey(found)),
  };
}

const ACCENTED: Record<string, string> = { a: "[aáàä]", e: "[eéèë]", i: "[iíìï]", o: "[oóòö]", u: "[uúùü]", n: "[nñ]", c: "[cç]" };

export function vaultSize(e: Engagement): { total: number; byType: Record<string, number> } {
  const c = load(e);
  return { total: c.state.entries.length, byType: { ...c.state.counters } };
}
