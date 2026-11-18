/**
 * When the Maestro's AI stops answering: out of credit, a key that no longer works, a rate limit
 * that does not lift, a provider that is down. The round should not die with one error line:
 *
 *  - the failure is classified (quota, auth, rate, down); anything else (a bad request, a refusal)
 *    is shown as before, since another model would not fix it;
 *  - the provider that failed rests for a while: quota and auth until the operator changes its
 *    settings (or 30 min), rate and down 1, 5, then 30 min;
 *  - the round goes on with the next AI the operator has configured, which gets a hand-over: what
 *    was asked and what was done so far, and where Penteos keeps the rest;
 *  - when there is none left, the round stops in order: one clear message with what happened and
 *    what to do, the AI shown as unavailable (so "Connect an AI" is offered), and, when the cause
 *    lifts by itself (rate, down), the round picks up again on its own when the rest is over.
 *
 * The SDKs already retry a 429 or a 5xx a couple of times: an error that reaches here is not a blip.
 */
import type { AgentEvent, ProviderId } from "./types.js";

export type FailureKind = "quota" | "auth" | "rate" | "down";

/** A provider says plainly why it cannot go on (the ChatGPT plan answers with codes, not statuses). */
export class ProviderFailure extends Error {
  constructor(
    readonly kind: FailureKind,
    message: string,
  ) {
    super(message);
    this.name = "ProviderFailure";
  }
}

/** Why the AI stopped answering, when another AI could carry on; undefined otherwise. */
export function classifyFailure(error: unknown): FailureKind | undefined {
  if (error instanceof ProviderFailure) return error.kind;
  // A dropped connection is the provider not answering, never a reason to show a raw error.
  if (isCutConnection(error)) return "down";
  const e = error as { status?: number; code?: string; type?: string; message?: string; error?: { code?: string; type?: string; message?: string }; cause?: { code?: string } };
  const status = typeof e?.status === "number" ? e.status : undefined;
  const text = `${e?.code ?? ""} ${e?.type ?? ""} ${e?.error?.code ?? ""} ${e?.error?.type ?? ""} ${e?.message ?? ""} ${e?.error?.message ?? ""} ${e?.cause?.code ?? ""}`.toLowerCase();
  // A conversation too long is the memory's job (memory.ts), not another model's.
  if (/context[_ ]length|context window|prompt is too long|maximum context/.test(text)) return undefined;
  if (status === 402 || /insufficient[_ ]?(quota|balance|credit)|billing|credit balance|exceeded your current quota|payment required|out of credits|usage[_ ]limit|balance is (too )?low|quota exceeded/.test(text)) return "quota";
  if (status === 401 || status === 403 || /invalid[_ ]api[_ ]key|incorrect api key|authentication|unauthori[sz]ed|permission[_ ]denied|api key (is )?(not valid|disabled|revoked)|signed out/.test(text)) return "auth";
  if (status === 429 || /rate[_ ]limit|too many requests/.test(text)) return "rate";
  if ((status !== undefined && status >= 500) || /overloaded|service unavailable|bad gateway|gateway timeout|econnrefused|enotfound|etimedout|econnreset|eai_again|socket hang up|fetch failed|connection error|network error|timed? ?out/.test(text)) return "down";
  return undefined;
}

/**
 * The connection dropped in the middle of an answer ("terminated", a reset socket): nothing was
 * stored, since a step is kept only once its answer is complete, so the step is simply asked again.
 * Not a reason to rest the provider (DeepSeek drops long streams now and then).
 */
export function isCutConnection(error: unknown): boolean {
  const e = error as { name?: string; status?: number; code?: string; message?: string; cause?: { code?: string; message?: string; name?: string } };
  if (!e || e.name === "AbortError" || typeof e.status === "number") return false;
  const text = `${e.message ?? ""} ${e.code ?? ""} ${e.cause?.code ?? ""} ${e.cause?.message ?? ""} ${e.cause?.name ?? ""}`.toLowerCase();
  return /terminated|econnreset|epipe|und_err_socket|und_err_body_timeout|other side closed|socket hang up|premature close|connection error|fetch failed|network error|stream (ended|closed)|unexpected end/.test(text);
}

/** How many times a dropped answer is asked again before it counts as a provider failure. */
export const CUT_RETRIES = 3;

/**
 * With no other AI, a provider that is not answering (or rate-limiting) is waited for, never given
 * up on: the round goes on by itself, asking again after these pauses (the last one repeats), until
 * it answers or the operator stops it. Only what needs a person (no credit, a refused key) stops it.
 */
export const WAIT_STEPS_MS = [10_000, 20_000, 40_000, 60_000, 120_000, 180_000, 300_000];

/** The pause before asking again for an answer whose connection dropped (times the attempt). */
export const timing = { cutDelayMs: 1500 };

/** What the AI that answers again reads, after a wait. */
export const RESUME_AFTER_WAIT = "[Penteos] The connection to the AI failed and is back. Continue exactly where you left off: check the last results you have, and do not repeat what is already done.";

const MIN = 60_000;
const STEPS: Record<FailureKind, number[]> = {
  quota: [30 * MIN],
  auth: [30 * MIN],
  rate: [1 * MIN, 5 * MIN, 30 * MIN],
  down: [1 * MIN, 5 * MIN, 30 * MIN],
};

export interface Rest {
  kind: FailureKind;
  until: number;
  strikes: number;
  /** What the provider said, short. */
  detail: string;
  since: number;
}

/** Providers resting after a failure. Settings changed by the operator end the rest at once. */
export class Cooldowns {
  private readonly rests = new Map<ProviderId, Rest>();

  constructor(private readonly now: () => number = Date.now) {}

  mark(id: ProviderId, kind: FailureKind, detail: string): Rest {
    const prev = this.rests.get(id);
    const strikes = prev && prev.kind === kind ? prev.strikes + 1 : 1;
    const steps = STEPS[kind];
    const rest: Rest = { kind, strikes, detail: detail.slice(0, 200), since: this.now(), until: this.now() + steps[Math.min(strikes - 1, steps.length - 1)]! };
    this.rests.set(id, rest);
    return rest;
  }

  /** The rest in force for this provider, if any (an expired one is forgotten). */
  active(id: ProviderId): Rest | undefined {
    const r = this.rests.get(id);
    if (!r) return undefined;
    if (r.until <= this.now()) {
      // Keep the strike count for a rate or outage that comes back soon; the rest itself is over.
      if (r.until + 60 * MIN <= this.now()) this.rests.delete(id);
      return undefined;
    }
    return r;
  }

  /** It worked again: the next failure starts from the first step. */
  succeeded(id: ProviderId): void {
    const r = this.rests.get(id);
    if (r && r.until <= this.now()) this.rests.delete(id);
  }

  clear(id: ProviderId): void {
    this.rests.delete(id);
  }
}

const short = (s: string, n: number) => (s.length > n ? `${s.slice(0, n)}…` : s);

/**
 * What the next AI reads to take the round over: the operator's requests, what the previous one
 * said and did (tools and their outcomes), most recent last, and where Penteos keeps everything.
 */
export function handOver(events: AgentEvent[], from: string, asked: string): string {
  const lines: string[] = [];
  for (const e of events.slice(-120)) {
    if (e.kind === "user" && !e.auto && e.text) lines.push(`OPERATOR: ${short(e.text, 600)}`);
    else if (e.kind === "text" && e.text.trim()) lines.push(`PREVIOUS AI: ${short(e.text.trim(), 500)}`);
    else if (e.kind === "tool" && e.status !== "running") lines.push(`TOOL ${e.name}${e.status === "error" ? " (error)" : ""}${e.summary ? `: ${short(e.summary, 200)}` : ""}`);
  }
  const log = lines.slice(-80).join("\n");
  return [
    `[Penteos - hand-over] You are taking this round over from ${from}, which stopped answering. You are the Maestro now, with the same rules, scope and tools.`,
    "Before acting, read engagement.brief, the board and the findings: Penteos keeps the full record, and this log is only the recent part of what was done. Do not repeat work that is already recorded; pick up the open leads and pending work.",
    log ? `Recent log (oldest first):\n${log}` : "",
    asked ? `What was being asked when it stopped:\n${asked}` : "Continue the plan.",
  ]
    .filter(Boolean)
    .join("\n\n");
}
