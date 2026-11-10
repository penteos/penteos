import { createHash } from "node:crypto";
import type { Engagement } from "../engagement.js";
import { detect, type SensitiveType } from "./detectors.js";

/**
 * The leak meter. Everything Penteos sends to a model goes
 * through `meterEgress`: it counts the characters, the canaries that arrived (known synthetic
 * sensitive values planted in a lab, the ground truth) and the sensitive values the detectors
 * recognise (an estimate for real engagements). Only counts and short hashes are kept, never the
 * text itself.
 */

export type EgressChannel = "system" | "prompt" | "tool";

export interface Canary {
  id: string;
  /** Kind of value: email, ar_dni, br_cpf, name, diagnosis… */
  category: string;
  value: string;
}

export interface PrivacyState {
  since: string;
  chars: Record<EgressChannel, number>;
  messages: number;
  /** Canary ids that reached a model. */
  leakedCanaries: string[];
  /** Distinct detected values (hashed) per type. */
  detected: Partial<Record<SensitiveType, string[]>>;
}

const HASHES_PER_TYPE = 5000;

const hash = (v: string) => createHash("sha256").update(v).digest("hex").slice(0, 16);
const normal = (v: string) => v.toLowerCase();
const onlyDigits = (v: string) => v.replace(/\D/g, "");

export function canaries(e: Engagement): Canary[] {
  return e.getState<Canary[]>("canaries") ?? [];
}

export function setCanaries(e: Engagement, list: Canary[]): void {
  e.setState("canaries", list);
}

export function privacyState(e: Engagement): PrivacyState {
  return e.getState<PrivacyState>("privacy") ?? { since: new Date().toISOString(), chars: { system: 0, prompt: 0, tool: 0 }, messages: 0, leakedCanaries: [], detected: {} };
}

export function resetPrivacyMeter(e: Engagement): void {
  e.setState("privacy", { since: new Date().toISOString(), chars: { system: 0, prompt: 0, tool: 0 }, messages: 0, leakedCanaries: [], detected: {} } satisfies PrivacyState);
}

/** Which canaries a text contains (formatted documents also match by their digits). */
export function canariesIn(text: string, list: Canary[]): Canary[] {
  if (!list.length) return [];
  const lower = normal(text);
  const digitsText = onlyDigits(text);
  return list.filter((c) => {
    if (lower.includes(normal(c.value))) return true;
    const d = onlyDigits(c.value);
    // Numeric documents written another way (with or without dots and dashes).
    return d.length >= 7 && d.length === c.value.replace(/[\s.\-/]/g, "").length && digitsText.includes(d);
  });
}

/** Meters one piece of text on its way to a model. Never throws. */
export function meterEgress(e: Engagement, channel: EgressChannel, text: string): void {
  if (!text) return;
  try {
    const s = privacyState(e);
    s.chars[channel] = (s.chars[channel] ?? 0) + text.length;
    s.messages++;
    const leaked = new Set(s.leakedCanaries);
    for (const c of canariesIn(text, canaries(e).filter((x) => !leaked.has(x.id)))) leaked.add(c.id);
    s.leakedCanaries = [...leaked];
    for (const d of detect(text)) {
      const set = new Set(s.detected[d.type] ?? []);
      if (set.size >= HASHES_PER_TYPE) continue;
      set.add(hash(d.value));
      s.detected[d.type] = [...set];
    }
    e.setState("privacy", s);
  } catch {
    /* measuring must never break the work */
  }
}

export interface PrivacyReport {
  since: string;
  chars: Record<EgressChannel, number>;
  messages: number;
  canaries: { total: number; leaked: number; rate: number; byCategory: Record<string, { total: number; leaked: number }> };
  detected: Partial<Record<SensitiveType, number>>;
}

export function privacyReport(e: Engagement): PrivacyReport {
  const s = privacyState(e);
  const list = canaries(e);
  const leaked = new Set(s.leakedCanaries);
  const byCategory: PrivacyReport["canaries"]["byCategory"] = {};
  for (const c of list) {
    const b = (byCategory[c.category] ??= { total: 0, leaked: 0 });
    b.total++;
    if (leaked.has(c.id)) b.leaked++;
  }
  const leakedCount = list.filter((c) => leaked.has(c.id)).length;
  return {
    since: s.since,
    chars: s.chars,
    messages: s.messages,
    canaries: { total: list.length, leaked: leakedCount, rate: list.length ? Math.round((leakedCount / list.length) * 1000) / 10 : 0, byCategory },
    detected: Object.fromEntries(Object.entries(s.detected).map(([k, v]) => [k, v?.length ?? 0])),
  };
}
