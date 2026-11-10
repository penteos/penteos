import type { Engagement } from "../engagement.js";
import { fitForModel } from "./fit.js";
import { maskForModel, type MaskStats, maskText } from "./mask.js";

/**
 * What the model reads: every tool result and every prompt goes through
 * here. With the project's privacy on, sensitive values become vault markers; then the result is
 * fitted to the budget by structure instead of being cut blindly.
 */

export type PrivacyLevel = "standard" | "off";

export function privacyLevel(e: Engagement): PrivacyLevel {
  return e.getState<PrivacyLevel>("privacyLevel") ?? "standard";
}

export function setPrivacyLevel(e: Engagement, level: PrivacyLevel): void {
  e.setState("privacyLevel", level);
}

/** Masked values per kind, for the run's privacy figures. */
function count(e: Engagement, stats: MaskStats): void {
  if (!stats.masked) return;
  try {
    const c = e.getState<Record<string, number>>("maskedCounts") ?? {};
    for (const [k, n] of Object.entries(stats.byKind)) c[k] = (c[k] ?? 0) + n;
    e.setState("maskedCounts", c);
  } catch {
    /* never break the work */
  }
}

export function maskedCounts(e: Engagement): Record<string, number> {
  return e.getState<Record<string, number>>("maskedCounts") ?? {};
}

/** Where the full data of a result lives, so a shortened result can point to it. */
function whereOf(value: unknown): string | undefined {
  if (!value || typeof value !== "object") return undefined;
  const v = value as Record<string, unknown>;
  if (typeof v.rawId === "string") return `raw_get with rawId ${v.rawId} (offset and length to read it in parts)`;
  if (typeof v.runId === "string") return `run_output for run ${v.runId}`;
  return undefined;
}

export const MODEL_BUDGET = 24_000;

/**
 * When enough new field names of the application went unrecognised, the agent is asked to
 * classify them (it sees names only): its answer protects the values from then on.
 */
function classifyHint(e: Engagement, fresh: number): string {
  if (!fresh) return "";
  const pending = (e.getState<number>("unclassifiedSinceHint") ?? 0) + fresh;
  if (pending < 8) {
    e.setState("unclassifiedSinceHint", pending);
    return "";
  }
  e.setState("unclassifiedSinceHint", 0);
  return `\n[Penteos: ${pending} field names of this application are not classified yet. Call privacy_fields to see them (names only, no values) and privacy_classify_fields to say which hold personal data, so their values reach you masked from now on.]`;
}

/**
 * A tool's result as the text the model reads. Masking only protects data that leaves the
 * machine: with a local model it is skipped (it would only cost capability).
 */
export function forModel(e: Engagement, value: unknown, budget = MODEL_BUDGET, opts: { local?: boolean } = {}): string {
  let v = value;
  let hint = "";
  if (privacyLevel(e) !== "off" && !opts.local) {
    const m = maskForModel(e, value);
    count(e, m.stats);
    v = m.value;
    hint = classifyHint(e, m.newFields);
  }
  return fitForModel(v, budget, whereOf(value)).text + hint;
}

/** Free text (a prompt, an error message) as the model reads it. */
export function textForModel(e: Engagement, text: string, opts: { local?: boolean } = {}): string {
  if (privacyLevel(e) === "off" || opts.local || !text) return text;
  const m = maskText(e, text);
  count(e, m.stats);
  return m.text;
}
