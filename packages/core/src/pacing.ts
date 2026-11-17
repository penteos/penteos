/**
 * How fast Penteos talks to a target. A client's production site is not a lab: a burst of
 * requests can slow it down, trip its defences or take it down. Each project has a pace, and
 * everything Penteos sends itself goes through it, per host:
 *
 *  - a token bucket (requests per second, with a small burst) and a cap on requests in flight;
 *  - a small random gap between requests, so they do not land as a perfectly regular train;
 *  - when the target says it has had enough (429, 503), the host is paused: its Retry-After when it
 *    gives one, otherwise an exponential backoff, and the request is tried again once if it was a
 *    plain read (GET, HEAD, OPTIONS without a body);
 *  - the external tools (nuclei, ffuf, katana, httpx, sqlmap, nmap…) get their own rate options
 *    from the same pace, unless the command already sets them.
 *
 * This machine (localhost, 127.0.0.0/8, ::1) is never paced: local labs and tests run at full speed.
 * The pace reaches the senders through the operation that started the work (AsyncLocalStorage),
 * so a background run keeps the pace of the project that launched it.
 */
import { AsyncLocalStorage } from "node:async_hooks";
import { isIP } from "node:net";

export type Pace = "off" | "quiet" | "normal" | "aggressive";
export const PACES: Pace[] = ["quiet", "normal", "aggressive", "off"];
export const DEFAULT_PACE: Pace = "normal";

export interface PaceLimits {
  /** Requests per second, per host. */
  rps: number;
  /** Requests that may go at once after a quiet moment. */
  burst: number;
  /** Requests in flight at the same time, per host. */
  inflight: number;
}

export const PACE_LIMITS: Record<Exclude<Pace, "off">, PaceLimits> = {
  quiet: { rps: 2, burst: 4, inflight: 1 },
  normal: { rps: 5, burst: 10, inflight: 2 },
  aggressive: { rps: 20, burst: 40, inflight: 6 },
};

/** The longest Penteos waits on a host that asked it to slow down, before trying again. */
const MAX_PAUSE_MS = 120_000;
const FIRST_BACKOFF_MS = 2_000;
const MAX_BACKOFF_MS = 60_000;

const scope = new AsyncLocalStorage<Pace>();

/** Runs fn (and everything it starts) at this pace. */
export function withPace<T>(pace: Pace, fn: () => T): T {
  return scope.run(pace, fn);
}

/** The pace of the work in progress (the project's, through the operation that started it). */
export function currentPace(): Pace {
  return scope.getStore() ?? DEFAULT_PACE;
}

export function isLocalHost(hostname: string): boolean {
  // Tests of the pace itself run against this machine.
  if (process.env.PENTEOS_PACE_LOCAL === "1") return false;
  const h = hostname.replace(/^\[|\]$/g, "").toLowerCase();
  if (h === "localhost" || h.endsWith(".localhost")) return true;
  if (isIP(h) === 4) return h.startsWith("127.");
  if (isIP(h) === 6) return h === "::1" || h.startsWith("::ffff:127.");
  return false;
}

/** The host a target names: a URL, host:port, an IP, a CIDR, a bare name. */
export function hostOfTarget(target: string): string {
  const t = target.trim();
  try {
    if (/^[a-z][a-z0-9+.-]*:\/\//i.test(t)) return new URL(t).hostname;
  } catch {
    /* not a URL after all */
  }
  if (t.startsWith("[")) return t.slice(1, t.indexOf("]"));
  const noCidr = t.split("/")[0]!;
  return isIP(noCidr) === 6 ? noCidr : noCidr.split(":")[0]!;
}

export interface HostStats {
  host: string;
  sent: number;
  /** Time requests spent waiting for their turn, in total. */
  waitedMs: number;
  /** Answers that asked Penteos to slow down (429, 503). */
  throttled: number;
  /** Until when the host is paused, when it is. */
  pausedUntil?: string;
  lastAt?: string;
}

interface HostState {
  tokens: number;
  refilledAt: number;
  inflight: number;
  pauseUntil: number;
  backoff: number;
  stats: HostStats;
}

const hosts = new Map<string, HostState>();

function state(host: string, limits: PaceLimits): HostState {
  let s = hosts.get(host);
  if (!s) {
    s = { tokens: limits.burst, refilledAt: Date.now(), inflight: 0, pauseUntil: 0, backoff: 0, stats: { host, sent: 0, waitedMs: 0, throttled: 0 } };
    hosts.set(host, s);
  }
  return s;
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/**
 * Waits for this host's turn at the given pace; returns the function that ends the request. Hosts
 * on this machine, and the "off" pace, go at once.
 */
export async function acquire(hostname: string, pace: Pace = currentPace()): Promise<() => void> {
  if (pace === "off" || isLocalHost(hostname)) return () => {};
  const limits = PACE_LIMITS[pace];
  const s = state(hostname.toLowerCase(), limits);
  const started = Date.now();
  for (;;) {
    const now = Date.now();
    s.tokens = Math.min(limits.burst, s.tokens + ((now - s.refilledAt) / 1000) * limits.rps);
    s.refilledAt = now;
    if (now >= s.pauseUntil && s.inflight < limits.inflight && s.tokens >= 1) break;
    const wait = now < s.pauseUntil ? s.pauseUntil - now : s.tokens < 1 ? ((1 - s.tokens) / limits.rps) * 1000 : 50;
    await sleep(Math.max(10, Math.min(wait, 1000)));
  }
  s.tokens -= 1;
  s.inflight++;
  // A small random gap: not a perfectly regular train of requests.
  const jitter = Math.random() * Math.min(250, (1000 / limits.rps) * 0.3);
  if (jitter >= 5) await sleep(jitter);
  s.stats.sent++;
  s.stats.waitedMs += Date.now() - started;
  s.stats.lastAt = new Date().toISOString();
  let released = false;
  return () => {
    if (!released) s.inflight = Math.max(0, s.inflight - 1);
    released = true;
  };
}

/** Seconds (or an HTTP date) from a Retry-After header, in ms. */
export function retryAfterMs(value: string | undefined): number | undefined {
  if (!value) return undefined;
  const seconds = Number(value.trim());
  if (Number.isFinite(seconds) && seconds >= 0) return seconds * 1000;
  const at = Date.parse(value);
  return Number.isNaN(at) ? undefined : Math.max(0, at - Date.now());
}

/**
 * What the target answered. A 429 or 503 pauses the host (Retry-After, or a backoff that doubles
 * up to a minute); a normal answer resets the backoff. Returns true when the request should be
 * tried again (the caller decides whether it may: only plain reads are).
 */
export function observe(hostname: string, status: number, retryAfter: string | undefined, pace: Pace = currentPace()): boolean {
  if (pace === "off" || isLocalHost(hostname)) return false;
  const s = hosts.get(hostname.toLowerCase());
  if (!s) return false;
  if (status === 429 || status === 503) {
    s.backoff = s.backoff ? Math.min(MAX_BACKOFF_MS, s.backoff * 2) : FIRST_BACKOFF_MS;
    const pause = Math.min(MAX_PAUSE_MS, retryAfterMs(retryAfter) ?? s.backoff);
    s.pauseUntil = Math.max(s.pauseUntil, Date.now() + pause);
    s.stats.throttled++;
    s.stats.pausedUntil = new Date(s.pauseUntil).toISOString();
    return true;
  }
  if (status > 0 && status < 500) {
    s.backoff = 0;
    delete s.stats.pausedUntil;
  }
  return false;
}

/** Whether a request may be sent again without side effects. */
export function isPlainRead(method: string, bodyLength: number): boolean {
  return ["GET", "HEAD", "OPTIONS"].includes(method.toUpperCase()) && bodyLength === 0;
}

/** What each host has received from Penteos in this session. */
export function paceStats(filter?: (host: string) => boolean): HostStats[] {
  return [...hosts.values()].map((s) => s.stats).filter((s) => !filter || filter(s.host)).sort((a, b) => b.sent - a.sent);
}

/** For tests: forget every host. */
export function resetPacing(): void {
  hosts.clear();
}

// ---------------------------------------------------------------------------------------------
// The external tools: their own rate options, from the same pace.

const has = (argv: string[], ...flags: string[]) => argv.some((a) => flags.some((f) => a === f || a.startsWith(`${f}=`)));

/**
 * The tool's arguments with its rate options for this pace, and a line saying what was added. A
 * command that already sets its own rate keeps it: the operator or the Maestro chose it.
 */
export function paceArguments(command: string, argv: string[], pace: Pace): { argv: string[]; added?: string } {
  if (pace === "off") return { argv };
  const { rps, inflight } = PACE_LIMITS[pace];
  const tool = command.split(/[\\/]/).pop()!.replace(/\.exe$/i, "").toLowerCase();
  let extra: string[] = [];
  switch (tool) {
    case "nuclei":
      if (!has(argv, "-rl", "-rate-limit", "-rlm", "-rate-limit-minute")) extra = ["-rl", String(rps)];
      if (!has(argv, "-c", "-concurrency")) extra.push("-c", String(Math.max(2, inflight * 2)));
      break;
    case "ffuf":
      if (!has(argv, "-rate")) extra = ["-rate", String(rps)];
      if (!has(argv, "-t")) extra.push("-t", String(Math.max(1, inflight)));
      break;
    case "katana":
    case "httpx":
      if (!has(argv, "-rl", "-rate-limit", "-rlm", "-rate-limit-minute")) extra = ["-rl", String(rps)];
      break;
    case "feroxbuster":
      if (!has(argv, "--rate-limit")) extra = ["--rate-limit", String(rps)];
      if (!has(argv, "-t", "--threads")) extra.push("-t", String(Math.max(1, inflight)));
      break;
    case "gobuster":
      if (!has(argv, "--delay")) extra = ["--delay", `${Math.round(1000 / rps)}ms`];
      if (!has(argv, "-t", "--threads")) extra.push("-t", String(Math.max(1, inflight)));
      break;
    case "sqlmap":
      if (!has(argv, "--delay")) extra = [`--delay=${(1 / rps).toFixed(2)}`];
      if (!has(argv, "--threads")) extra.push("--threads=1");
      break;
    case "dalfox":
      if (!has(argv, "--delay")) extra = ["--delay", String(Math.round(1000 / rps))];
      break;
    case "wpscan":
      if (!has(argv, "--throttle")) extra = ["--throttle", String(Math.round(1000 / rps))];
      break;
    case "nmap":
      // Packets, not requests: the quiet pace slows the timing template, the others cap the rate.
      if (!has(argv, "--max-rate") && !argv.some((a) => /^-T[0-5]$/.test(a))) extra = pace === "quiet" ? ["-T2"] : pace === "normal" ? ["--max-rate", "300"] : [];
      break;
    default:
      return { argv };
  }
  if (!extra.length) return { argv };
  // sqlmap and nmap take options anywhere; the others too. Added at the end, before nothing.
  return { argv: [...argv, ...extra], added: extra.join(" ") };
}
