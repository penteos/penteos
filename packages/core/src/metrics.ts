import { ulid } from "@penteos/schema";
import type { Actor } from "@penteos/schema";
import type { Engagement } from "./engagement.js";
import { WSTG } from "./wstg.js";
import { privacyReport, type PrivacyReport } from "./privacy/meter.js";

/**
 * How a run went: what the agents found and the verifier confirmed, what the
 * operator says they missed, and how they behaved (errors, loops, step limits, scope denials).
 * Measured on real engagements, so runs on different clients can be compared over time.
 */

export interface Counters {
  /** Agent operation calls. */
  calls: number;
  /** Calls that failed, by error code. */
  errors: Record<string, number>;
  /** Repeated calls answered with the previous result, and refused after too many. */
  echoed: number;
  refused: number;
  /** Near-miss arguments Penteos fixed instead of refusing. */
  repaired: number;
  /** Times a turn reached its step limit, and the verifier given a last turn to close. */
  stepLimit: number;
  wrapUp: number;
  /** Most used operations. */
  ops: Record<string, number>;
  firstAt?: string;
  lastAt?: string;
}

export interface RunNote {
  id: string;
  kind: "missed" | "note";
  text: string;
  at: string;
  by: Actor;
}

const empty = (): Counters => ({ calls: 0, errors: {}, echoed: 0, refused: 0, repaired: 0, stepLimit: 0, wrapUp: 0, ops: {} });

export function counters(e: Engagement): Counters {
  return { ...empty(), ...(e.getState<Counters>("metrics") ?? {}) };
}

/** Records one agent call: its operation, and how it ended. Never throws. */
export function recordCall(e: Engagement, op: string, outcome: { error?: string; echoed?: boolean; refused?: boolean; repaired?: boolean }): void {
  try {
    const c = counters(e);
    const now = new Date().toISOString();
    c.calls++;
    c.ops[op] = (c.ops[op] ?? 0) + 1;
    if (outcome.error) c.errors[outcome.error] = (c.errors[outcome.error] ?? 0) + 1;
    if (outcome.echoed) c.echoed++;
    if (outcome.refused) c.refused++;
    if (outcome.repaired) c.repaired++;
    c.firstAt ??= now;
    c.lastAt = now;
    e.setState("metrics", c);
  } catch {
    /* measuring must never break the work */
  }
}

/** Records an event of the agent runtime (a step limit reached, a last turn given). */
export function recordEvent(e: Engagement, what: "stepLimit" | "wrapUp"): void {
  try {
    const c = counters(e);
    c[what]++;
    e.setState("metrics", c);
  } catch {
    /* never break the work */
  }
}

export function runNotes(e: Engagement): RunNote[] {
  return e.getState<RunNote[]>("runNotes") ?? [];
}

export function addRunNote(e: Engagement, kind: RunNote["kind"], text: string, by: Actor): RunNote {
  const note: RunNote = { id: ulid(), kind, text: text.trim(), at: new Date().toISOString(), by };
  e.setState("runNotes", [...runNotes(e), note]);
  return note;
}

export function removeRunNote(e: Engagement, id: string): void {
  e.setState("runNotes", runNotes(e).filter((n) => n.id !== id));
}

export interface RunSummary {
  engagement: { id: string; name: string; client: string; mode: string };
  /** From the first to the last agent call. */
  duration?: { from: string; to: string; minutes: number };
  surface: { hosts: number; webapps: number; endpoints: number };
  findings: { total: number; bySeverity: Record<string, number>; approved: number; inReview: number; draft: number; rejected: number };
  verifier: { reproduced: number; notReproduced: number; inconclusive: number; pending: number };
  coverage: { tested: number; total: number };
  traces: { pending: number; total: number };
  behaviour: Counters & { errorRate: number; outOfScope: number };
  missed: RunNote[];
  notes: RunNote[];
  /** What reached the AI models from this project (leak meter). */
  privacy: PrivacyReport;
}

/** Everything about a run, computed now from the graph and the counters. */
export function runSummary(e: Engagement): RunSummary {
  const c = counters(e);
  const findings = e.query({ kind: "finding", limit: 5000 });
  const by = (s: string) => findings.filter((f) => f.attributes.status === s).length;
  const bySeverity: Record<string, number> = {};
  const verifier = { reproduced: 0, notReproduced: 0, inconclusive: 0, pending: 0 };
  for (const f of findings) {
    const sev = String(f.attributes.severity);
    bySeverity[sev] = (bySeverity[sev] ?? 0) + 1;
    const v = f.attributes.verification as { state?: string; verdict?: string } | undefined;
    if (v?.verdict === "reproduced") verifier.reproduced++;
    else if (v?.verdict === "not_reproduced") verifier.notReproduced++;
    else if (v?.verdict === "inconclusive") verifier.inconclusive++;
    else if (v?.state === "running") verifier.pending++;
  }
  const apps = e.query({ kind: "webapp", limit: 2000 }).filter((a) => !a.outOfScope);
  let tested = 0;
  for (const a of apps) {
    const cov = (a.attributes.coverage ?? {}) as Record<string, { status?: string }>;
    tested += WSTG.filter((w) => cov[w.id] && !["untested", "in_progress"].includes(String(cov[w.id]!.status))).length;
  }
  const traces = e.getState<Array<{ status: string }>>("traces") ?? [];
  const notes = runNotes(e);
  const minutes = c.firstAt && c.lastAt ? Math.round((Date.parse(c.lastAt) - Date.parse(c.firstAt)) / 60000) : undefined;
  return {
    engagement: { id: e.info.id, name: e.info.name, client: e.info.clientName, mode: e.info.mode },
    ...(c.firstAt && c.lastAt ? { duration: { from: c.firstAt, to: c.lastAt, minutes: minutes ?? 0 } } : {}),
    surface: {
      hosts: e.query({ kind: "host", limit: 5000 }).filter((h) => !h.outOfScope).length,
      webapps: apps.length,
      endpoints: e.query({ kind: "endpoint", limit: 20000 }).filter((x) => !x.outOfScope).length,
    },
    findings: { total: findings.length, bySeverity, approved: by("approved") + by("reported"), inReview: by("in_review"), draft: by("draft"), rejected: by("wont_fix") },
    verifier,
    coverage: { tested, total: apps.length * WSTG.length },
    traces: { pending: traces.filter((t) => t.status === "pending").length, total: traces.length },
    behaviour: {
      ...c,
      errorRate: c.calls ? Math.round((Object.values(c.errors).reduce((a, b) => a + b, 0) / c.calls) * 1000) / 10 : 0,
      outOfScope: c.errors.OUT_OF_SCOPE ?? 0,
    },
    missed: notes.filter((n) => n.kind === "missed"),
    notes: notes.filter((n) => n.kind === "note"),
    privacy: privacyReport(e),
  };
}
