import ipaddr from "ipaddr.js";
import { cdnOf } from "../cdn.js";
import { type ChildProcess, execFile, spawn } from "node:child_process";
import { spawnTied } from "../tied.js";
import { mkdirSync, readFileSync, existsSync, writeFileSync } from "node:fs";
import { delimiter, dirname, join, sep } from "node:path";
import { parseNmapXml } from "@penteos/parser-nmap";
import { type Actor, type RiskLevel, riskExceeds, type ScopeRuleAttributes, ulid } from "@penteos/schema";
import type { Engagement, IngestSummary, Run } from "../engagement.js";
import type { ActorPolicy, AskWhy, ScopeDecision } from "../scope/evaluate.js";
import { analyzeNmapArgs, NMAP_PRESETS } from "./nmap.js";
import { exploitationAllowed, setPhase } from "../plan.js";
import { formatRequest, formatResponse, type HttpResponse, paramsOf, parseRawRequest, requestUrl, sendHttp } from "../http.js";
import { harvestScript, type JsHarvest, mergeHarvests, scriptUrls } from "../webjs.js";
import { fillTemplate, guardedRoutes, looksSentAway, REDIRECT_CANARY, REDIRECT_PAYLOADS, redirectsToCanary, SESSION_COOKIES, traversalReached, TRAVERSAL_PAYLOADS } from "../webprobes.js";
import { type DnsIssue, lookupMail, lookupName, mailIssues, TAKEOVER_SERVICES, takeoverIssue } from "../dnscheck.js";
import { certificateIssues, CIPHERS, cookieIssues, corsIssue, headerIssues, peerCertificate, TLS_VERSION_SEVERITY, type TransportIssue, tryHandshake, WEAK_CIPHER_SEVERITY } from "../transport.js";
import { type DeepSignals, deepSignals, jsReferences, mergeSignals, recoverSources, safeSourcePath, sourceMapUrl } from "../webjs-deep.js";
import { offlineSandbox } from "../sandbox.js";
import { parseApiSpec, samplePath } from "../apispec.js";
import { INGEST_FORMAT, naturalKeyFor } from "@penteos/schema";
import WebSocket from "ws";
import {
  type AttackType,
  anomaliesOf,
  combinations,
  countCombinations,
  type FuzzResult,
  measure,
  type PayloadProcessing,
  type PayloadSource,
  parseTemplate,
  payloads as payloadsOf,
  processPayload,
  render,
} from "../fuzz.js";
import { parseTarget } from "../scope/target.js";
import { findTargetTokens, undeclaredTargets } from "./targets.js";
import { detectWildcards, dropWildcardNames } from "../dnswild.js";
import { browse, browserOpen, type BrowseAction, type BrowseResult } from "../browser/agent-browser.js";
import { argsForTool, manifestInvocation, manifestTargets, targetForTool, parseWithManifest, type ToolManifest, validateManifest, withDefaults, withOutputArgs } from "./manifest.js";
import { installCommand, ToolRegistry } from "./registry.js";
import { mb, runForIdentity, ToolboxError } from "./toolbox.js";
import { AUTO_INSTALL_DEFAULT, type AutoInstall, CAPABILITIES, type CapabilityId, type Gap, listGaps, openGap, PHASE_CAPABILITIES, updateGap } from "./capabilities.js";
import { builtinCommonPaths, builtinCrawl, builtinDns, builtinHttpProbe, builtinPortScan, builtinSubdomains } from "./builtins.js";
import { getPlan } from "../plan.js";
import { adaptNmap, canAskPassword, captureState, personAtDesktop, systemInstallArgv, which, withPassword } from "./system.js";
import { detectPackageManager } from "./registry.js";
import { describeRule, type ReplaceRule, validateRule } from "../proxy/intercept.js";

export interface ToolCaller {
  actor: Actor;
  policy: ActorPolicy;
  origin: Run["origin"];
}

/**
 * The host a target names, for the per-host execution limit: the hostname of a URL, the
 * domain, the IP. Ranges and CIDRs are their own key (one scan of a range counts once).
 */
function hostKeyOf(target: string): string {
  try {
    const t = parseTarget(target);
    if (t.type === "url") return t.host.toLowerCase();
    if (t.type === "domain") return t.fqdn;
    return target.trim().replace(/^\[|\](:\d+)?$/g, "").replace(/:(\d+)$/, "").toLowerCase();
  } catch {
    return target.trim().toLowerCase();
  }
}

/** Simultaneous executions by agents against one host: enough to work, not enough to knock it over. */
const AGENT_RUNS_PER_HOST = 2;

export interface Approval {
  id: string;
  createdAt: string;
  expiresAt: string;
  requestedBy: Actor;
  reason: string;
  warnings: string[];
  summary: string;
  /** Files of this machine (not of the target) that the command reads: the interface warns about them. */
  localFiles?: string[];
  /** A wildcard scope proposal: how many known subdomains it would bring in. */
  covers?: number;
  /** Why the scope engine asked (approvals that come from a scope decision). */
  why?: AskWhy;
  request:
    | { kind: "nmap"; argv: string[] }
    | { kind: "exec"; argv: string[]; targets: string[]; risk: RiskLevel }
    /** Penteos's own fallback for a capability (no tool for it is installed). */
    | { kind: "capability"; capability: CapabilityId; targets: string[]; options?: Record<string, unknown> }
    | { kind: "scope"; rule: ScopeRuleAttributes }
    | { kind: "install"; tool: string; command: string }
    /** The tools a phase usually needs, offered together once when it starts. */
    | { kind: "install_kit"; tools: string[]; phase: string }
    | { kind: "manifest"; manifest: ToolManifest; update: boolean }
    | { kind: "phase"; to: string; title?: string; summary: string }
    /**
     * One HTTP request, or a whole probe shown by its first request: `probe` says which, and its
     * full input, so approving it runs the probe (every attempt, every endpoint), not one request.
     */
    | { kind: "http"; origin: string; raw: string; risk: RiskLevel; probe?: ProbeRequest }
    | { kind: "fuzz"; input: FuzzInput }
    | { kind: "ws"; url: string; headers: Array<[string, string]>; risk: RiskLevel }
    | { kind: "proxy_rules"; rules: ReplaceRule[]; reason: string }
    /** The findings the agent considers ready for the report: the operator approves all, some or none. */
    | { kind: "findings"; findings: Array<{ id: string; title: string; severity: string; verdict?: string }> }
    /** A plugin the Maestro built: installed and enabled in this project only if approved. */
    | { kind: "plugin"; proposal: PluginProposal };
}

const MISSING_ROUTE = new Set([404, 405, 410, 501]);

/**
 * A server error is a lead, never a dead end: a 500 or 504 often means the input reached code that
 * was not ready for it (a path traversal, an unhandled type), and a CDN that cannot reach its origin
 * (Cloudflare 52x/530) may point at a dangling record someone else could claim. Each one becomes an
 * observation the round has to look at before it closes.
 */
export function leadFor(status: number, where: string): { title: string; sourceRule: string; detail: string } | undefined {
  if (status === 530 || status === 523 || status === 521) {
    return {
      title: `The CDN cannot reach the origin of ${where} (${status}): possible dangling record`,
      sourceRule: "lead:origin-unreachable",
      detail: `Answered ${status}: the CDN has the name but its origin does not answer or does not exist. Check the DNS records behind it (CNAME to a cloud service, an IP no longer yours): a dangling one can be claimed by someone else (subdomain takeover). Not "not applicable": investigate.`,
    };
  }
  if (status >= 500 && status !== 501) {
    return {
      title: `Server error on ${where} (${status}): investigate`,
      sourceRule: "lead:server-error",
      detail: `Answered ${status}. A server error is where input reached code that was not ready for it: vary the input (path segments, ../ and its encodings, types, lengths, missing fields) and compare. Promote what you find, or dismiss this with the reason once you looked.`,
    };
  }
  return undefined;
}
/** nuclei flags that choose which templates run: with none of them, it is a sweep of all of them. */
const NUCLEI_SELECTORS = new Set(["-t", "-templates", "-tags", "-id", "-s", "-severity", "-w", "-workflows", "-pt", "-type", "-tc", "-template-condition", "-a", "-author", "-nt", "-new-templates"]);

const STATIC_EXT = /\.(css|js|mjs|map|png|jpe?g|gif|svg|webp|avif|ico|woff2?|ttf|otf|eot|mp4|webm|mp3|wav|pdf|zip|gz)(\?|$)/i;
const STATIC_DIR = /\/(?:wp-content\/uploads|assets|static|_next\/static|dist|build|fonts|images?|img|css|js)\//i;
/** A public static file (stylesheet, script, image, font…), not an endpoint worth flagging as no-auth. */
function isStaticAsset(path: string): boolean {
  return STATIC_EXT.test(path) || STATIC_DIR.test(path);
}

/** Files every site publishes for anyone: crawlers, security contacts, app manifests. */
const PUBLIC_FILES = /^\/(?:robots\.txt|sitemap[^/]*\.xml|humans\.txt|ads\.txt|security\.txt|favicon\.ico|manifest\.(?:json|webmanifest)|site\.webmanifest|browserconfig\.xml|\.well-known\/.*)$/i;
/** Pages that exist to be reached without a session: signing in or up, and the legal pages. */
const PUBLIC_PAGES = /^(?:\/[a-z]{2}(?:-[a-z]{2})?)?\/(?:log-?in|sign-?in|sign-?up|register|registro|ingresar|iniciar-sesion|forgot-password|reset-password|recuperar[^/]*|auth\/(?:login|signin|register))\/?$|(?:terms|terminos|privacy|privacidad|politica|cookies|legal|aviso-legal|condiciones)[^/]*(?:\.html?)?$/i;
/** Public by design: answering without credentials is the point, not a gap. */
export function isPublicByDesign(path: string): boolean {
  const p = path.split("?")[0]!;
  // Under an API prefix a name like "cookies" or "terms" is data, not a page.
  if (/^\/(?:api|graphql|rest|v\d+)(?:\/|$)/i.test(p)) return false;
  return PUBLIC_FILES.test(p) || PUBLIC_PAGES.test(p);
}

export interface EnumerationInput {
  origin: string;
  /** Route with one placeholder: "/api/tenants/{id}". */
  template: string;
  /** A header to send ("Authorization: Bearer {{secret:x}}"): reach as that user. */
  header?: string;
  /** Identifiers to try instead of integers (slugs, codes). */
  values?: string[];
  maxRequests?: number;
  risk: RiskLevel;
}

/** How many records a route with an identifier opens, measured. */
export interface EnumerationResult {
  template: string;
  mode: "integers" | "values";
  requests: number;
  /** Identifiers that answered with a record (up to 25). */
  hits: string[];
  /** Integers: the highest id that answered, the share of ids that exist below it, and the estimate. */
  highest?: number;
  density?: number;
  estimate: number;
  /** True when every id up to the highest was tried (the count is exact). */
  exact: boolean;
  /** Field names of a record (never values). */
  fields: string[];
  /** What a missing record looks like (status and size), the reference the hits were told from. */
  missing: { status: number; size: number };
}

/** One endpoint's rate-limit verdict: what was sent, what came back, and whether anything pushed back. */
export interface RateLimitResult {
  request: string;
  /** "missing": the route does not exist (404/405/410/501); "inconclusive": it only failed (5xx). Neither says anything about limits. */
  verdict: "defended" | "no_defence" | "missing" | "inconclusive";
  attempts: number;
  statuses: number[];
  /** Fastest and slowest answer, in ms. */
  timeMs: [number, number];
  defence?: string;
}

export type ProbeRequest =
  | { tool: "webjs"; input: { url: string; scripts?: string[]; risk: RiskLevel; maxScripts?: number } }
  | { tool: "apiprobe"; input: { origin: string; paths?: string[]; header?: string; risk: RiskLevel; maxRequests?: number; fromOrigin?: string; basePath?: string } }
  | { tool: "apispec"; input: { url: string; risk: RiskLevel } }
  | { tool: "ratelimit"; input: { origin: string; raw: string; more?: string[]; attempts?: number; risk: RiskLevel } }
  | { tool: "enumeration"; input: EnumerationInput }
  | { tool: "versions"; input: { origin: string; slugs?: string[]; risk: RiskLevel } }
  | { tool: "browser"; input: { action: BrowseAction; risk: RiskLevel } }
  | { tool: "serveractions"; input: ServerActionsInput }
  | { tool: "transport"; input: { target: string; path?: string; risk: RiskLevel } }
  | { tool: "webprobe"; input: WebProbeInput };

export type WebProbeInput =
  | { check: "redirect"; origin: string; targets?: Array<{ path: string; param: string }>; risk: RiskLevel }
  | { check: "traversal"; origin: string; templates?: string[]; risk: RiskLevel }
  | { check: "guard"; origin: string; paths?: string[]; risk: RiskLevel };

export interface WebProbeHit {
  title: string;
  severity: "low" | "medium" | "high";
  detail: string;
  path: string;
}

export interface ServerActionsInput {
  origin: string;
  /** The page the actions belong to (they are posted to it); "/" by default. */
  page?: string;
  /** A session to call them with (a lower role's cookie, as {{secret:name}}); none by default. */
  header?: string;
  /** Only these action ids; all the ones the bundles revealed by default. */
  ids?: string[];
  risk: RiskLevel;
}

export interface ServerActionResult {
  id: string;
  name?: string;
  status: number;
  /** ran: the server executed it; protected: refused or sent to login; failed: errored on this input; missing: unknown id. */
  verdict: "ran" | "protected" | "failed" | "missing";
}

/**
 * "Allow during this session": the same tool against the same targets, up to the same risk,
 * no longer needs a new approval for the agent that asked. Never widens the scope.
 */
export interface Grant {
  id: string;
  tool: string;
  targets: string[];
  risk: RiskLevel;
  grantedTo: Actor;
  by: Actor;
  at: string;
}

export interface FuzzInput {
  origin: string;
  /** Raw request with positions marked §like this§. */
  template: string;
  attack: AttackType;
  /** One set for sniper and battering ram; one per position for pitchfork and cluster bomb. */
  sets: PayloadSource[];
  processing?: PayloadProcessing[];
  /** Text to look for in responses; /regex/flags for a regular expression. */
  grep?: string[];
  /** Regex with a group: the captured value goes into the results. */
  extract?: string;
  concurrency: number;
  delayMs: number;
  maxRequests: number;
  risk: RiskLevel;
}

/** What the operator sees on the card of a plugin the Maestro built. */
export interface PluginProposal {
  pluginId: string;
  name: string;
  version: string;
  description?: unknown;
  /** The draft exactly as tested: if it changes after the proposal, approving it is refused. */
  hash: string;
  /** Replaces an installed version. */
  update?: { from?: string };
  permissions: string[];
  sendsTo: string[];
  operations: Array<{ name: string; title: unknown; agent: boolean }>;
  menus: number;
  events: string[];
  entityTypes: string[];
  providers: string[];
  test: { operation: string; at: string; steps: number; requests: number };
  /** A code plugin: its files for the operator to review, and what changed against the installed version. */
  code?: { runtime: "node" | "python"; main: string; files: Array<{ path: string; size: number; lines: number }>; diff?: string };
  /** It worked against the real service: with what, what it asked and what came back. */
  live?: { operation: string; input: Record<string, unknown>; sample: string; requests: string[]; checks: string[] };
  /** The Maestro's own account of what it checked (shown to the operator). */
  evidence?: string;
}

export type RunOutcome =
  | { status: "plugin_installed"; pluginId: string; version: string }
  | { status: "scope_added"; ruleId: string }
  | { status: "phase_changed"; phase: string }
  | { status: "rules_set"; rules: ReplaceRule[] }
  | { status: "http"; run: Run; response?: HttpResponse; rawId?: string; error?: string }
  | { status: "harvest"; apiBases?: HarvestApiBase[]; pageOrigin?: string; run: Run; harvest?: JsHarvest; rawId?: string; error?: string }
  | { status: "apispec"; run: Run; routes?: Array<{ path: string; methods: string[]; requiresAuth?: boolean }>; title?: string; rawId?: string; error?: string }
  | { status: "ratelimit"; run: Run; attempts: number; defence?: string; results?: RateLimitResult[]; rawId?: string; error?: string }
  | { status: "serveractions"; run: Run; results?: ServerActionResult[]; rawId?: string; error?: string }
  | { status: "transport"; run: Run; issues?: TransportIssue[]; rawId?: string; error?: string }
  | { status: "dnscheck"; run: Run; issues?: DnsIssue[]; checked?: number; rawId?: string; error?: string }
  | { status: "webprobe"; run: Run; check: WebProbeInput["check"]; tried: number; hits?: WebProbeHit[]; rawId?: string; error?: string }
  | { status: "enumeration"; run: Run; result?: EnumerationResult; rawId?: string; sampleRawId?: string; error?: string }
  | { status: "versions"; run: Run; found?: Array<{ product: string; version: string; source: string; confidence: number; ecosystem?: string }>; rawId?: string; error?: string }
  | { status: "probe"; run: Run; basePath?: string; baseTrials?: Array<{ basePath: string; exist: number; of: number }>; results?: Array<{ path: string; noAuth?: number; size?: number; withHeader?: number }>; open?: string[]; modeStatus?: number; rawId?: string; error?: string }
  | { status: "ws"; sessionId?: string; entryId?: string; httpStatus?: number; error?: string }
  | { status: "manifest_saved"; tool: string }
  | { status: "findings_approved"; approved: string[]; left: string[] }
  | { status: "browser"; run: Run; result?: Omit<BrowseResult, "screenshot">; rawId?: string; screenshotRawId?: string; error?: string }
  | { status: "manual_install"; tool: string; command: string }
  | { status: "started"; run: Run; alreadyRunning?: boolean }
  | { status: "denied"; run: Run; code: string; reason: string }
  | { status: "pending_approval"; approval: Approval; duplicate?: boolean }
  /** Nothing could do the capability: the gap is recorded (and the tool proposed when the catalog has it). */
  | { status: "gap"; gap: Gap; approval?: Approval };

/** What a capability ran with: the tool, or Penteos's own fallback, and how good that is. */
export interface CapabilityRun {
  capability: CapabilityId;
  provider: string;
  quality: "full" | "degraded" | "blocked";
  outcome: RunOutcome;
  gap?: Gap;
  /** The install card proposed for the tool that would do it fully. */
  install?: Approval;
}

/**
 * How long a request waits for the operator. Long enough to survive a meeting or a lunch: an
 * approval that expires unseen stalls the work. When one expires the requester is told, so it can
 * ask again if it still needs it.
 */
const APPROVAL_TTL_MS = 8 * 60 * 60 * 1000;
/** Batches and scope proposals are bigger decisions: they wait a day. */
const APPROVAL_LONG_TTL_MS = 24 * 60 * 60 * 1000;

/** Combines the decisions for every target of one command: the strictest one wins. */
export function combineDecisions(decisions: ScopeDecision[]): ScopeDecision {
  const deny = decisions.find((d) => d.decision === "deny");
  if (deny) return deny;
  const ask = decisions.find((d) => d.decision === "ask");
  if (ask) {
    const warnings = decisions.flatMap((d) => ("warnings" in d ? d.warnings : []));
    return { ...ask, warnings: [...new Set(warnings)] } as ScopeDecision;
  }
  return decisions[0] ?? { decision: "deny", code: "INVALID_TARGET", reason: "no targets" };
}

function cleanEnv(toolboxBin?: string, extra: Record<string, string> = {}): NodeJS.ProcessEnv {
  const keep = ["PATH", "HOME", "LANG", "LC_ALL", "TERM", "USER", "LOGNAME", "SHELL", "TMPDIR", "HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "NO_PROXY", "no_proxy"];
  const env: NodeJS.ProcessEnv = Object.fromEntries(keep.filter((k) => process.env[k] !== undefined).map((k) => [k, process.env[k]]));
  // Penteos's own tools first: a tool that calls another finds the verified one.
  if (toolboxBin) env.PATH = [toolboxBin, env.PATH].filter(Boolean).join(delimiter);
  return { ...env, ...extra };
}

/** Same command line (a run may carry extra output flags Penteos appended, like -jsonl). */
function sameCommand(run: string, requested: string): boolean {
  const norm = (x: string) => x.trim().split(/\s+/).join(" ");
  const r = norm(run);
  const q = norm(requested);
  return r === q || r.startsWith(`${q} `);
}

/** Arguments that name files on this machine (cookie jars, wordlists, outputs…). */
export function localPaths(argv: string[]): string[] {
  const paths: string[] = [];
  for (const a of argv.slice(1)) {
    const v = a.includes("=") && !a.startsWith("/") ? a.slice(a.indexOf("=") + 1) : a;
    if (/^(\/|~\/|\.\.?\/)/.test(v) && !/^\/\//.test(v)) paths.push(v);
  }
  return [...new Set(paths)];
}

/** A path under an API base path ("/api" + "/users" = "/api/users"), unless it already is. */
function withBase(basePath: string, path: string): string {
  const b = basePath.replace(/\/+$/, "");
  if (!b || path === b || path.startsWith(`${b}/`)) return path;
  return `${b}${path}`;
}

/** One spelling of an origin, whatever its port notation: "https://x" and "https://x:443" are the same. */
export function canonicalOrigin(origin: string): string {
  try {
    const u = new URL(origin);
    const port = u.port || (u.protocol === "https:" ? "443" : u.protocol === "http:" ? "80" : "");
    return `${u.protocol}//${u.hostname.toLowerCase()}${port ? `:${port}` : ""}`;
  } catch {
    return origin.toLowerCase();
  }
}

/** An API root found in an app's code, and whether its calls could be registered there. */
export interface HarvestApiBase {
  base: string;
  origin: string;
  basePath: string;
  inScope: boolean;
  /** Relative API calls found in the code (they belong under this base). */
  calls: number;
}

const approvalStates = new WeakMap<Engagement, Record<string, Array<[string, unknown]>>>();

/**
 * Executes tools against targets. Every execution passes the scope check first, gets a Run
 * record, stores its output as raw artifacts and, for integrated tools, ingests the results.
 */
export class ToolRunner {
  /**
   * Requests, the decisions taken on them and the ones that lapsed. Saved with the engagement on
   * every change: a restart used to lose what was pending and show every decided request as
   * "expired".
   */
  private readonly approvals: Map<string, Approval>;
  /** Decisions already taken, so a conversation can show how each request ended. */
  private readonly decisions: Map<string, { approved: boolean; withdrawn?: boolean; by: Actor; at: string; summary: string; approval: Approval }>;
  private readonly processes = new Map<string, ReturnType<typeof spawn>>();
  /** Fuzzer jobs in progress (they run in this process, not as a child). */
  private readonly fuzzJobs = new Map<string, { cancelled: boolean }>();
  /** WebSocket connections opened from Penteos (the WebSocket repeater). */
  private readonly wsSessions = new Map<string, { ws: WebSocket; entryId: string; url: string; openedAt: string; by: Actor }>();
  /** Output of runs still in progress, so a viewer that opens late can catch up. */
  private readonly live = new Map<string, string>();

  /** A map loaded from the engagement and written back on every change, keeping the newest `max`. */
  private persisted<V>(part: string, max = Infinity): Map<string, V> {
    // One state object per engagement, shared by the three maps (they are saved together).
    let state = approvalStates.get(this.engagement);
    if (!state) {
      state = this.engagement.getState<Record<string, Array<[string, unknown]>>>("approvals") ?? {};
      approvalStates.set(this.engagement, state);
    }
    const all = state;
    const save = () => {
      try {
        this.engagement.setState("approvals", all);
      } catch {
        /* the engagement was closed */
      }
    };
    class Saved extends Map<string, V> {
      private ready = false;
      constructor(entries: Array<[string, V]>) {
        super(entries);
        this.ready = true;
      }
      override set(k: string, v: V): this {
        super.set(k, v);
        if (this.ready) {
          while (this.size > max) this.delete(this.keys().next().value!);
          all[part] = [...this.entries()];
          save();
        }
        return this;
      }
      override delete(k: string): boolean {
        const had = super.delete(k);
        if (had && this.ready) {
          all[part] = [...this.entries()];
          save();
        }
        return had;
      }
    }
    return new Saved((state[part] as Array<[string, V]> | undefined) ?? []);
  }

  constructor(
    private readonly engagement: Engagement,
    readonly registry: ToolRegistry = new ToolRegistry(),
  ) {
    // Here and not as field initializers: those run before the engagement is assigned.
    this.approvals = this.persisted("pending");
    this.decisions = this.persisted("decided", 1000);
    this.expired = this.persisted("expired", 500);
    // Expiry is checked on a clock too, not only when someone lists the approvals: whoever asked
    // must hear that the request lapsed.
    setInterval(() => {
      try {
        this.listApprovals();
      } catch {
        /* engagement closed */
      }
    }, 60_000).unref?.();
  }

  private workDir(): string {
    const dir = join(this.engagement.dir, "work");
    mkdirSync(dir, { recursive: true });
    return dir;
  }

  private check(targets: string[], risk: RiskLevel, policy: ActorPolicy): ScopeDecision {
    return combineDecisions(targets.map((t) => this.engagement.checkScope(t, risk, policy)));
  }

  /**
   * At most AGENT_RUNS_PER_HOST executions by agents at a time against one host:
   * an agent that hits the limit waits for one of them, it does not pile on.
   */
  private hostBusy(caller: ToolCaller, targets: string[]): Extract<ScopeDecision, { decision: "deny" }> | undefined {
    if (caller.actor.type !== "agent" || targets.length === 0) return undefined;
    const hosts = new Set(targets.map(hostKeyOf));
    const running = this.engagement.runs(200).filter((r) => r.status === "running" && r.actor.type === "agent");
    for (const host of hosts) {
      const busy = running.filter((r) => r.targets.some((t) => hostKeyOf(t) === host));
      if (busy.length >= AGENT_RUNS_PER_HOST) {
        return {
          decision: "deny",
          code: "HOST_BUSY",
          reason: `${host} already has ${busy.length} agent executions running (${busy.map((r) => r.id).join(", ")}); the limit is ${AGENT_RUNS_PER_HOST} per host. Wait for one with run_wait and try again.`,
        };
      }
    }
    return undefined;
  }

  private requestApproval(caller: ToolCaller, decision: Extract<ScopeDecision, { decision: "ask" }>, summary: string, request: Approval["request"]): RunOutcome {
    // The same request twice (an agent that did not notice it already asked): one card only.
    const key = JSON.stringify(request);
    const same = this.listApprovals().find((a) => a.requestedBy.id === caller.actor.id && JSON.stringify(a.request) === key);
    if (same) return { status: "pending_approval", approval: same, duplicate: true };
    // ...or something already approved and still running: point at that run.
    if (request.kind === "exec" || request.kind === "nmap") {
      const command = (request.kind === "nmap" ? ["nmap", ...request.argv] : request.argv).join(" ");
      const running = this.engagement.runs(50).find((r) => r.status === "running" && sameCommand(r.command ?? "", command));
      if (running) return { status: "started", run: running, alreadyRunning: true };
    }
    const local = request.kind === "exec" || request.kind === "nmap" ? localPaths(request.argv) : [];
    const warnings = decision.warnings;
    const now = Date.now();
    const approval: Approval = {
      id: ulid(),
      createdAt: new Date(now).toISOString(),
      expiresAt: new Date(now + APPROVAL_TTL_MS).toISOString(),
      requestedBy: caller.actor,
      reason: decision.reason,
      warnings,
      ...(local.length ? { localFiles: local } : {}),
      why: decision.why,
      summary,
      request,
    };
    this.approvals.set(approval.id, approval);
    this.engagement.audit(caller.actor, "approval.request", { approval: approval.id }, approval);
    this.engagement.events.emit("change", { type: "approval.changed" });
    return { status: "pending_approval", approval };
  }

  /** Exploitation by agents waits until a human moves the engagement to a phase that allows it. */
  private phaseGate(caller: ToolCaller, risk: RiskLevel, approvedBy?: Actor): Extract<ScopeDecision, { decision: "deny" }> | undefined {
    if (approvedBy || caller.policy.type !== "agent" || risk !== "exploitation") return undefined;
    const gate = exploitationAllowed(this.engagement);
    if (gate.allowed) return undefined;
    return {
      decision: "deny",
      code: "PHASE",
      reason: `The engagement is in the "${gate.phase?.title}" phase, which does not allow exploitation.${gate.next ? ` Close this phase with a summary and ask to move to "${gate.next.title}" with phase_request; the operator decides.` : ""}`,
    } as never;
  }

  private deny(caller: ToolCaller, tool: string, argv: string[], targets: string[], risk: RiskLevel, decision: Extract<ScopeDecision, { decision: "deny" }>): RunOutcome {
    const run = this.engagement.startRun({
      actor: caller.actor,
      origin: caller.origin,
      tool,
      command: [tool, ...argv].join(" "),
      targets,
      risk,
      policy: { result: "denied", ...(decision.ruleId ? { ruleId: decision.ruleId } : {}), reason: decision.reason },
      runner: "local",
      status: "denied",
    });
    return { status: "denied", run, code: decision.code, reason: decision.reason };
  }

  // -------------------------------------------------------------------------------------------
  // nmap (integrated)
  // -------------------------------------------------------------------------------------------

  /**
   * nmap command line from a preset (or explicit args) and targets. nmap takes no "host:port" or
   * URLs, so their ports become a -p list and only the hosts are passed.
   */
  nmapArgs(input: { preset?: string; targets?: string[]; args?: string[] }): string[] {
    const preset = NMAP_PRESETS[input.preset ?? "service-scan"];
    if (!input.args && !preset) throw new Error(`unknown nmap preset: ${input.preset}`);
    const base = input.args ?? preset!.args;
    const hosts: string[] = [];
    const ports = new Set<number>();
    for (const raw of input.targets ?? []) {
      const t = parseTarget(raw);
      if (t.type === "url") {
        hosts.push(t.host);
        ports.add(t.port);
      } else if (t.type === "domain") {
        hosts.push(t.fqdn);
        if (t.port) ports.add(t.port);
      } else {
        const host = raw.replace(/^\[|\](:\d+)?$/g, "").replace(/:(\d+)$/, "");
        hosts.push(t.port ? host : raw);
        if (t.port) ports.add(t.port);
      }
    }
    const hasPortFlag = base.some((a) => a === "-p" || /^-p[\dTU-]/.test(a));
    if (!ports.size || hasPortFlag) return [...base, ...new Set(hosts)];
    // Ports named in the targets replace a preset's --top-ports.
    const cleaned = base.filter((a, i) => a !== "--top-ports" && base[i - 1] !== "--top-ports");
    return [...cleaned, "-p", [...ports].sort((x, y) => x - y).join(","), ...new Set(hosts)];
  }



  /** Targets that are CDN addresses, or names that only resolve to CDN addresses (as far as the graph knows). */
  private cdnTargets(targets: string[]): Array<{ target: string; provider: string }> {
    const out: Array<{ target: string; provider: string }> = [];
    const domains = targets.some((t) => !ipaddr.isValid(t)) ? this.engagement.query({ kind: "domain", limit: 100000 }) : [];
    for (const target of targets) {
      if (ipaddr.isValid(target)) {
        const provider = cdnOf(target);
        if (provider) out.push({ target, provider });
        continue;
      }
      const domain = domains.find((d) => String(d.attributes.fqdn).toLowerCase() === target.toLowerCase());
      if (!domain) continue;
      const ips = this.engagement
        .edgesOf(domain.id)
        .filter((e) => e.type === "resolves_to" && e.from.id === domain.id)
        .map((e) => String(this.engagement.get(e.to.id)?.attributes.ip ?? ""))
        .filter(Boolean);
      const providers = ips.map(cdnOf);
      if (ips.length && providers.every(Boolean)) out.push({ target, provider: providers[0]! });
    }
    return out;
  }

  runNmap(argv: string[], caller: ToolCaller, approvedBy?: Actor): RunOutcome {
    const analysis = analyzeNmapArgs(argv);
    if (analysis.unchecked) {
      return this.deny(caller, "nmap", argv, [], analysis.risk, { decision: "deny", code: "UNCHECKED_TARGETS", reason: analysis.unchecked } as never);
    }
    const gated = this.phaseGate(caller, analysis.risk, approvedBy);
    if (gated) return this.deny(caller, "nmap", argv, analysis.targets, analysis.risk, gated);
    // An agent port-scanning a CDN measures the CDN. The operator may still do it by hand.
    const cdn = caller.actor.type === "agent" && !approvedBy ? this.cdnTargets(analysis.targets) : [];
    if (cdn.length) {
      return this.deny(caller, "nmap", argv, analysis.targets, analysis.risk, {
        decision: "deny",
        code: "CDN_TARGET",
        reason:
          `${cdn.map((c) => `${c.target} (${c.provider})`).join(", ")} only resolve to CDN edge addresses: a port scan there measures ${cdn[0]!.provider}, not the client's servers, and is slow. ` +
          "Map the web applications instead (httpx, crawling, http_send); scan services only on an origin IP if you find one. Run nmap again without those targets, or tell the operator if a scan of the CDN is really wanted.",
      } as never);
    }
    const decision = this.check(analysis.targets, analysis.risk, approvedBy ? { type: "human" } : caller.policy);
    if (decision.decision === "deny") return this.deny(caller, "nmap", argv, analysis.targets, analysis.risk, decision);
    if (decision.decision === "ask") {
      const grant = this.grantFor(caller, "nmap", analysis.targets, analysis.risk);
      if (grant) return this.runNmap(argv, { ...caller, policy: { type: "human" } }, grant.by);
      return this.requestApproval(caller, decision, `nmap ${argv.join(" ")}`, { kind: "nmap", argv });
    }
    const busy = this.hostBusy(caller, analysis.targets);
    if (busy) return this.deny(caller, "nmap", argv, analysis.targets, analysis.risk, busy);

    // What this nmap may do (root, the capture permission, or neither): a SYN scan without the
    // permission becomes a connect scan, and what only raw packets do is left out, said in the run.
    const nmapBin = this.registry.toolbox?.binaryPath("nmap") ?? which("nmap");
    const adapted = nmapBin ? adaptNmap(argv, captureState(nmapBin)) : { argv, changes: [] as string[] };
    const run = this.engagement.startRun({
      actor: caller.actor,
      origin: caller.origin,
      tool: "nmap",
      command: ["nmap", ...adapted.argv].join(" "),
      targets: analysis.targets,
      risk: analysis.risk,
      policy: {
        result: approvedBy ? "approved" : "allowed",
        ruleId: decision.ruleId,
        ...(adapted.changes.length ? { reason: `nmap without capture permission (it can be granted in Tools): ${adapted.changes.join(", ")}` } : {}),
      },
      runner: "local",
      attack: this.registry.get("nmap")?.attack ?? ["T1046"],
    });
    const xmlPath = join(this.workDir(), `${run.id}.xml`);
    // Without a TTY nmap prints nothing until it ends: ask for discoveries as they happen (-v)
    // and a progress line every few seconds, so the operator can follow the scan live.
    const progress = [
      ...(argv.some((a) => /^-v+$/.test(a)) ? [] : ["-v"]),
      ...(argv.includes("--stats-every") ? [] : ["--stats-every", "3s"]),
    ];
    this.spawnTracked(run, nmapBin ?? "nmap", [...adapted.argv, ...progress, "-oX", xmlPath], () => this.ingestNmapXml(run.id, xmlPath));
    return { status: "started", run };
  }

  /** Ingests an nmap XML file produced by a run (runner or integrated terminal). */
  ingestNmapXml(runId: string, xmlPath: string): IngestSummary | undefined {
    if (!existsSync(xmlPath)) return undefined;
    const content = readFileSync(xmlPath, "utf8");
    if (!content.includes("<nmaprun")) return undefined;
    const rawId = this.engagement.putRaw(content, { type: "file", mime: "application/xml", runId, originalName: `${runId}.xml` });
    const batch = parseNmapXml(content, { rawIds: [rawId], runId });
    const run = this.engagement.getRun(runId);
    return this.engagement.ingest(batch, run?.actor ?? { type: "system", id: "runner" });
  }

  // -------------------------------------------------------------------------------------------
  // HTTP requests (the request editor, for humans and agents)
  // -------------------------------------------------------------------------------------------

  async runHttp(input: { origin: string; raw: string; risk: RiskLevel }, caller: ToolCaller, approvedBy?: Actor): Promise<RunOutcome> {
    const shown = parseRawRequest(input.raw);
    const url = requestUrl(input.origin, shown);
    const label = `${shown.method} ${url.href}`;
    const fail = (code: string, reason: string) => this.deny(caller, "http", [shown.method, url.href], [url.href], input.risk, { decision: "deny", code, reason } as never);
    const gated = this.phaseGate(caller, input.risk, approvedBy);
    if (gated) return this.deny(caller, "http", [shown.method, url.href], [url.href], input.risk, gated);
    const resolved = this.engagement.resolveSecrets([input.raw]);
    if (resolved.missing.length) return fail("UNKNOWN_SECRET", `Unknown secret(s): ${resolved.missing.join(", ")}. Save them first with secret_save.`);

    const decision = this.check([url.href], input.risk, approvedBy ? { type: "human" } : caller.policy);
    if (decision.decision === "deny") return this.deny(caller, "http", [shown.method, url.href], [url.href], input.risk, decision);
    if (decision.decision === "ask") {
      const grant = this.grantFor(caller, "http", [url.origin], input.risk);
      if (grant) return this.runHttp(input, { ...caller, policy: { type: "human" } }, grant.by);
      return this.requestApproval(caller, decision, label, { kind: "http", ...input });
    }
    const busy = this.hostBusy(caller, [url.href]);
    if (busy) return this.deny(caller, "http", [shown.method, url.href], [url.href], input.risk, busy);

    const run = this.engagement.startRun({
      actor: caller.actor,
      origin: caller.origin,
      tool: "http",
      command: label,
      targets: [url.href],
      risk: input.risk,
      policy: { result: approvedBy ? "approved" : "allowed", ...(decision.ruleId ? { ruleId: decision.ruleId } : {}) },
      runner: "local",
      attack: ["T1595"],
    });
    const req = parseRawRequest(resolved.argv[0]!);
    // Sent to the URL of the RESOLVED request: secrets in the path or query used to go out literally.
    const target = requestUrl(input.origin, req);
    if (target.origin !== url.origin) {
      const done = this.engagement.finishRun(run.id, { status: "failed", summary: { error: "a secret changed the request's host" } });
      return { status: "http", run: done, error: "a saved secret changed the destination host of the request: not sent (scope is checked on the host you write, not on a secret)" } as never;
    }
    try {
      const response = await sendHttp(target, req);
      const rawId = this.engagement.putRaw(`${formatRequest(req, url)}\r\n\r\n${formatResponse(response)}`, { type: "http_exchange", mime: "message/http", runId: run.id });
      const params = paramsOf(url, req);
      const ingested = this.engagement.ingest(
        {
          format: INGEST_FORMAT,
          source: { parser: "http@0.1.0", tool: "http" },
          rawIds: [rawId],
          observedAt: new Date().toISOString(),
          items: [
            {
              op: "upsert",
              kind: "webapp",
              key: { origin: url.origin },
              ...(() => {
                const tech = response.headers
                  .filter(([k]) => /^(server|x-powered-by)$/i.test(k))
                  .map(([, v]) => ({ name: v.trim(), confidence: 0.9 }));
                return tech.length ? { attributes: { technologies: tech } } : {};
              })(),
              confidence: 1,
            },
            {
              op: "upsert",
              kind: "endpoint",
              key: { origin: url.origin, path: url.pathname },
              attributes: { methods: [req.method], statusesSeen: [response.status], ...(params.length ? { params } : {}) },
              confidence: 1,
            },
          ],
        } as never,
        caller.actor,
      );
      if (response.status === 429 || response.status === 423) this.noteDefence(url.origin, url.pathname, `${req.method} ${url.pathname} answered ${response.status}`, caller.actor);
      const lead = leadFor(response.status, `${req.method} ${url.pathname}`);
      if (lead) this.engagement.ingest({ format: INGEST_FORMAT, source: { parser: "lead@0.1.0", tool: "http" }, rawIds: [rawId], observedAt: new Date().toISOString(), items: [{ op: "observe", ...lead, affects: [{ kind: "endpoint", key: { origin: url.origin, path: url.pathname } }], severityHint: "info", rawId }] } as never, caller.actor);
      const done = this.engagement.finishRun(run.id, { status: "finished", rawIds: [rawId], summary: { http: { status: response.status, size: response.size, timeMs: response.timeMs }, ingested } });
      this.engagement.noteReachability(url.hostname, true);
      return { status: "http", run: done, response, rawId };
    } catch (e) {
      this.engagement.noteReachability(url.hostname, false, (e as Error).message);
      const done = this.engagement.finishRun(run.id, { status: "failed", summary: { error: (e as Error).message } });
      return { status: "http", run: done, error: (e as Error).message };
    }
  }

  // -------------------------------------------------------------------------------------------
  // JavaScript harvesting
  // -------------------------------------------------------------------------------------------

  /**
   * Fetches a page (or explicit scripts) and pulls from its JavaScript the endpoints it calls, the
   * hosts of other environments, its routes and any credentials left in the code. Endpoints land in
   * the graph for later testing; out-of-scope hosts, secrets and source maps become observations so
   * the operator and the Maestro see them. Only in-scope URLs are fetched.
   */
  async harvestScripts(input: { url: string; scripts?: string[]; risk: RiskLevel; maxScripts?: number }, caller: ToolCaller, approvedBy?: Actor): Promise<RunOutcome> {
    let page: URL;
    try {
      page = new URL(input.url);
    } catch {
      return { status: "http", run: this.engagement.startRun({ actor: caller.actor, origin: caller.origin, tool: "webjs", command: `harvest ${input.url}`, targets: [], risk: input.risk, policy: { result: "denied", reason: "bad url" }, runner: "local" }), error: `not a URL: ${input.url}` };
    }
    const label = `harvest JS ${page.href}`;
    const decision = this.check([page.href], input.risk, approvedBy ? { type: "human" } : caller.policy);
    if (decision.decision === "deny") return this.deny(caller, "webjs", [page.href], [page.href], input.risk, decision);
    if (decision.decision === "ask") {
      const grant = this.grantFor(caller, "webjs", [page.origin], input.risk);
      if (grant) return this.harvestScripts(input, { ...caller, policy: { type: "human" } }, grant.by);
      return this.requestApproval(caller, decision, label, { kind: "http", origin: page.origin, raw: `GET ${page.pathname} HTTP/1.1\r\nHost: ${page.host}`, risk: input.risk, probe: { tool: "webjs", input } });
    }
    const run = this.engagement.startRun({ actor: caller.actor, origin: caller.origin, tool: "webjs", command: label, targets: [page.href], risk: input.risk, policy: { result: approvedBy ? "approved" : "allowed", ...(decision.ruleId ? { ruleId: decision.ruleId } : {}) }, runner: "local", attack: ["T1595"] });
    const fetchOk = async (u: URL): Promise<{ body: string; headers: Array<[string, string]> } | undefined> => {
      try {
        const r = await sendHttp(u, { method: "GET", path: u.pathname + u.search, headers: [["Host", u.host]], body: "" });
        return r.status < 400 ? { body: r.body, headers: r.headers } : undefined;
      } catch {
        return undefined;
      }
    };
    const get = async (u: URL): Promise<string | undefined> => (await fetchOk(u))?.body;
    const inScope = (u: URL) => this.check([u.href], "passive", { type: "human" }).decision !== "deny";
    try {
      const html = await get(page);
      // The scripts to read: the ones given, else the <script src> of the page, plus the page
      // itself when it looks like a bundle rather than HTML.
      let urls = (input.scripts ?? (html ? scriptUrls(html, page.href) : [])).map((u) => new URL(u, page.href));
      if (!urls.length && /\.(m?js)(\?|$)/i.test(page.pathname)) urls = [page];
      const skippedOffScope = urls.filter((u) => !inScope(u)).map((u) => u.host);
      // Every script, not only the page's: each one read is searched for the chunks and manifests it
      // names (Next.js, Vite, webpack), followed while they stay in scope; politely (the WAF) and
      // within limits. Each file is kept in the project (work/js/<host>/), with its source map's
      // original files when the site serves them, so it can be searched later.
      const maxFiles = Math.min(input.maxScripts ?? 200, 400);
      const MAX_BYTES = 60 * 1024 * 1024;
      const jsDir = join(this.workDir(), "js", page.host.replace(/[^A-Za-z0-9.-]/g, "_"));
      const save = (rel: string, content: string) => {
        try {
          const file = join(jsDir, rel);
          if (!file.startsWith(jsDir + sep)) return undefined;
          mkdirSync(dirname(file), { recursive: true });
          writeFileSync(file, content, { mode: 0o600 });
          return file;
        } catch {
          return undefined;
        }
      };
      const queue = [...urls.filter(inScope), ...(html ? jsReferences(html, page.href).map((u) => new URL(u)) : [])];
      const seen = new Set<string>();
      const harvests: JsHarvest[] = [];
      const signals: DeepSignals[] = [];
      const read: string[] = [];
      const maps: string[] = [];
      let bytes = 0;
      while (queue.length && read.length < maxFiles && bytes < MAX_BYTES) {
        const u = queue.shift()!;
        if (seen.has(u.href)) continue;
        seen.add(u.href);
        if (!inScope(u)) {
          skippedOffScope.push(u.host);
          continue;
        }
        const got = u.href === page.href && html ? { body: html, headers: [] as Array<[string, string]> } : await fetchOk(u);
        if (!got) continue;
        bytes += got.body.length;
        read.push(u.href);
        const rel = safeSourcePath(`bundles${u.pathname}`);
        save(rel, got.body);
        harvests.push(harvestScript(got.body));
        signals.push(deepSignals(got.body, rel));
        for (const next of jsReferences(got.body, u.href)) if (!seen.has(next)) queue.push(new URL(next));
        const map = sourceMapUrl(got.body, got.headers, u.href) ?? `${u.href.split("?")[0]}.map`;
        if (!maps.includes(map)) maps.push(map);
        if (queue.length) await new Promise((r) => setTimeout(r, 120));
      }
      if (html && !read.includes(page.href)) harvests.push(harvestScript(html)); // inline scripts too
      // Source maps: the original code, file by file, when the site serves them.
      const recovered: string[] = [];
      let mapsServed = 0;
      for (const m of maps.slice(0, maxFiles)) {
        if (bytes >= MAX_BYTES) break;
        let mu: URL;
        try {
          mu = new URL(m);
        } catch {
          continue;
        }
        if (!inScope(mu)) continue;
        const got = await fetchOk(mu);
        const sources = got ? recoverSources(got.body) : undefined;
        if (!got || !sources) continue;
        mapsServed++;
        bytes += got.body.length;
        for (const src of sources) {
          const rel = `sources/${src.path}`;
          if (!save(rel, src.content)) continue;
          recovered.push(rel);
          // The application's own code is read; the libraries' (node_modules) only kept.
          if (!/(^|\/)node_modules\//.test(src.path)) {
            harvests.push(harvestScript(src.content));
            signals.push(deepSignals(src.content, rel));
          } else signals.push(deepSignals(src.content, rel));
        }
        await new Promise((r) => setTimeout(r, 120));
      }
      const deep = mergeSignals(signals);
      if (read.length || recovered.length) save("index.json", JSON.stringify({ page: page.href, scripts: read, sourceMaps: maps.slice(0, mapsServed ? undefined : 0), recovered: recovered.length, at: new Date().toISOString() }, null, 2));
      const h = mergeHarvests(harvests);
      const rawId = this.engagement.putRaw(`# harvest ${page.href}\nscripts read:\n${read.join("\n")}\n\nendpoints:\n${h.endpoints.map((e) => `${e.origin ?? ""}${e.path}`).join("\n")}\n\nhosts:\n${h.hosts.join("\n")}\n\nroutes:\n${h.routes.join("\n")}\n\nsecrets:\n${h.secrets.map((x) => `${x.kind}: ${x.value}`).join("\n")}`, { type: "stdout", mime: "text/plain", runId: run.id });

      const items: unknown[] = [];
      // Endpoints: only for origins already in scope (the page's, or a named host that is in scope).
      for (const e of h.endpoints) {
        const origin = e.origin ?? page.origin;
        if (!inScope(new URL(origin))) continue;
        items.push({ op: "upsert", kind: "webapp", key: { origin }, confidence: 0.7 });
        items.push({ op: "upsert", kind: "endpoint", key: { origin, path: e.path }, attributes: { methods: [] }, confidence: 0.6 });
      }
      // The app's API: its relative calls (not the screens the router defines) live under an API base
      // the code may name ("https://backend.x", "/api"…) but cannot be trusted to name right. Nothing
      // is registered on a guess: the calls are remembered, and web_probe_endpoints (fromOrigin) finds
      // the base by measuring before sweeping them.
      const screens = new Set(h.routes);
      const apiCalls = [...new Set(h.endpoints.filter((e) => !e.origin && !screens.has(e.path)).map((e) => e.path))].slice(0, 3000);
      const apiBases: HarvestApiBase[] = [];
      for (const b of h.apiBases.slice(0, 8)) {
        try {
          const u = new URL(b, page.href);
          apiBases.push({ base: `${u.origin}${u.pathname.replace(/\/+$/, "")}`, origin: u.origin, basePath: u.pathname.replace(/\/+$/, ""), inScope: inScope(u), calls: apiCalls.length });
        } catch {
          /* not a URL */
        }
      }
      if (apiCalls.length) {
        const all = this.engagement.getState<Record<string, string[]>>("apiCalls") ?? {};
        all[canonicalOrigin(page.origin)] = apiCalls;
        this.engagement.setState("apiCalls", all);
      }
      const secretHosts = [...new Set([...h.hosts, ...skippedOffScope])].filter((host) => this.check([`https://${host}`], "passive", { type: "human" }).decision === "deny");
      if (secretHosts.length) {
        items.push({ op: "observe", title: `JavaScript names ${secretHosts.length} host(s) out of scope: ${secretHosts.slice(0, 8).join(", ")}`, sourceRule: "webjs:hosts", affects: [{ kind: "webapp", key: { origin: page.origin } }], severityHint: "info", detail: secretHosts.join(", ") });
      }
      for (const sec of h.secrets.slice(0, 20)) {
        items.push({ op: "observe", title: `Possible ${sec.kind} in client JavaScript`, sourceRule: "webjs:secret", affects: [{ kind: "webapp", key: { origin: page.origin } }], severityHint: "medium", detail: `${sec.kind}: ${this.engagement.redact(sec.value)}` });
      }
      const app = [{ kind: "webapp", key: { origin: page.origin } }];
      if (recovered.length) {
        const own = recovered.filter((r) => !/(^|\/)node_modules\//.test(r));
        items.push({ op: "observe", title: `Source code exposed through source maps: ${recovered.length} original files recovered (${own.length} of the application's own)`, sourceRule: "webjs:sources-exposed", affects: app, severityHint: "medium", detail: `The site serves its source maps with the original code inside. Copied to ${jsDir}/sources (search it: comments, internal names, routes, logic). Application files include: ${own.slice(0, 15).join(", ")}` });
      } else if (h.sourceMaps.length) {
        items.push({ op: "observe", title: `Source maps referenced (${h.sourceMaps.length}), not served`, sourceRule: "webjs:sourcemap", affects: app, severityHint: "info", detail: h.sourceMaps.join(", ") });
      }
      const byKind = new Map<string, string[]>();
      for (const c of deep.config) byKind.set(c.kind, [...(byKind.get(c.kind) ?? []), c.value]);
      for (const [kind, values] of byKind) items.push({ op: "observe", title: `Client JavaScript ships ${kind} configuration`, sourceRule: "webjs:config", affects: app, severityHint: "low", detail: `${[...new Set(values)].slice(0, 6).map((v) => this.engagement.redact(v)).join(", ")}. Check what it allows (an error tracker accepting events, a bucket listing, a backend reachable directly).` });
      if (deep.internalAddresses.length) items.push({ op: "observe", title: `JavaScript names internal addresses: ${deep.internalAddresses.slice(0, 5).join(", ")}`, sourceRule: "webjs:internal", affects: app, severityHint: "low", detail: deep.internalAddresses.join(", ") });
      for (const l of deep.messageListeners.filter((x) => !x.checksOrigin).slice(0, 5)) items.push({ op: "observe", title: `Message listener without an origin check in ${l.file}`, sourceRule: "lead:postmessage", affects: app, severityHint: "medium", detail: `window.addEventListener("message", …) with no check of event.origin nearby: any page that frames or opens this one can send it messages. Read what the handler does with the data (${jsDir}/${l.file}).` });
      if (deep.redirectParams.length) items.push({ op: "observe", title: `Redirect parameters in the code: ${deep.redirectParams.slice(0, 6).join(", ")}`, sourceRule: "lead:redirect", affects: app, severityHint: "info", detail: "Parameters that say where to go next: test each one for open redirect (an external URL, //host, /\\host, encoded forms) on the screens and endpoints that take it." });
      if (deep.clientFields.length) items.push({ op: "observe", title: `Fields the browser computes and sends: ${deep.clientFields.slice(0, 6).join(", ")}`, sourceRule: "lead:client-trust", affects: app, severityHint: "info", detail: "Values the client computes (IP, time zone, device, fingerprint, risk) can be sent with anything. Find the requests that carry them and check whether the server trusts them (fraud signals, limits, geofencing)." });
      if (deep.sinks.length) items.push({ op: "observe", title: `DOM sinks in the application's code: ${[...new Set(deep.sinks.map((x) => x.kind))].join(", ")}`, sourceRule: "webjs:sinks", affects: app, severityHint: "info", detail: deep.sinks.slice(0, 20).map((x) => `${x.kind} in ${x.file}`).join("; ") });
      // What the web probes start from: where to try redirects, which screens to ask for unsigned in.
      {
        const all = this.engagement.getState<Record<string, { redirectParams: string[]; routes: string[] }>>("jsLeads") ?? {};
        const prev = all[canonicalOrigin(page.origin)] ?? { redirectParams: [], routes: [] };
        all[canonicalOrigin(page.origin)] = { redirectParams: [...new Set([...prev.redirectParams, ...deep.redirectParams])].slice(0, 40), routes: [...new Set([...prev.routes, ...h.routes])].slice(0, 400) };
        this.engagement.setState("jsLeads", all);
      }
      if (deep.serverActions.length) {
        const all = this.engagement.getState<Record<string, Array<{ id: string; name?: string; file: string }>>>("serverActions") ?? {};
        all[canonicalOrigin(page.origin)] = deep.serverActions;
        this.engagement.setState("serverActions", all);
        const named = deep.serverActions.filter((a) => a.name).map((a) => a.name!);
        items.push({ op: "observe", title: `${deep.serverActions.length} Next.js server action(s) in the bundles${named.length ? `: ${named.slice(0, 6).join(", ")}` : ""}`, sourceRule: "lead:server-actions", affects: app, severityHint: "info", detail: "Server actions are endpoints: each one runs on the server when called with its id (Next-Action header). Probe them without a session and with a lower role (web_probe_server_actions)." });
      }
      const ingested = items.length ? this.engagement.ingest({ format: INGEST_FORMAT, source: { parser: "webjs@0.1.0", tool: "webjs" }, rawIds: [rawId], observedAt: new Date().toISOString(), items } as never, caller.actor) : undefined;
      const summary = { endpoints: h.endpoints.length, hosts: h.hosts.length, routes: h.routes.length, secrets: h.secrets.length, sourceMaps: h.sourceMaps.length, scriptsRead: read.length, sourceFilesRecovered: recovered.length, serverActions: deep.serverActions.length, savedIn: jsDir, ...(ingested ? { ingested } : {}) };
      const done = this.engagement.finishRun(run.id, { status: "finished", rawIds: [rawId], summary });
      this.engagement.noteReachability(page.hostname, true);
      // Remembered: when an out-of-scope API base is included later, the agent is told to sweep it.
      if (apiBases.length) {
        const known = this.engagement.getState<Array<HarvestApiBase & { pageOrigin: string }>>("apiBases") ?? [];
        const merged = new Map(known.map((b) => [b.base, b]));
        for (const b of apiBases) merged.set(b.base, { ...b, pageOrigin: page.origin });
        this.engagement.setState("apiBases", [...merged.values()].slice(-20));
      }
      return { status: "harvest", run: done, harvest: h, apiBases, pageOrigin: page.origin, rawId };
    } catch (e) {
      this.engagement.noteReachability(page.hostname, false, (e as Error).message);
      const done = this.engagement.finishRun(run.id, { status: "failed", summary: { error: (e as Error).message } });
      return { status: "harvest", run: done, error: (e as Error).message };
    }
  }

  // -------------------------------------------------------------------------------------------
  // API sweep
  // -------------------------------------------------------------------------------------------

  /**
   * Probes a set of endpoints of one in-scope origin to map the authentication boundary: each is
   * requested without credentials (and, if a header is given, with it, to test an invalid or
   * other-tenant token). The ones that answer where their siblings refuse are the authorization
   * gaps - a route that forgot its check. Anomalies become observations; coverage lands on each
   * endpoint. Paths come from the argument or, if none, from what the graph already knows for that app.
   */
  async probeEndpoints(input: { origin: string; paths?: string[]; header?: string; risk: RiskLevel; maxRequests?: number; fromOrigin?: string; basePath?: string }, caller: ToolCaller, approvedBy?: Actor): Promise<RunOutcome> {
    let base: URL;
    try {
      base = new URL(input.origin);
    } catch {
      return { status: "harvest", run: this.engagement.startRun({ actor: caller.actor, origin: caller.origin, tool: "apiprobe", command: `probe ${input.origin}`, targets: [], risk: input.risk, policy: { result: "denied", reason: "bad origin" }, runner: "local" }), error: `not an origin: ${input.origin}` };
    }
    // Known endpoints: of this origin, or the calls another app's code makes to this API (fromOrigin:
    // the single-page app whose bundle names them). Origins compare in one form ("https://x" = ":443").
    const from = input.fromOrigin ? canonicalOrigin(input.fromOrigin) : canonicalOrigin(base.origin);
    const savedCalls = input.fromOrigin ? (this.engagement.getState<Record<string, string[]>>("apiCalls") ?? {})[from] : undefined;
    const known = savedCalls?.length
      ? savedCalls
      : this.engagement
          .query({ kind: "webapp", limit: 500 })
          .filter((a) => canonicalOrigin(String(a.attributes.origin)) === from)
          .flatMap((a) => this.engagement.query({ kind: "endpoint", limit: 50_000 }).filter((e) => e.attributes.webappId === a.id).map((e) => String(e.attributes.pathTemplate)));
    // An app's calls under an API whose base path is not given: Penteos finds it by measuring.
    const discover = Boolean(input.fromOrigin) && input.basePath === undefined && !input.paths?.length;
    const limit = input.maxRequests ?? (input.fromOrigin ? 1500 : 150);
    const calls = [...new Set(input.paths?.length ? input.paths : known)].filter((p) => p.startsWith("/"));
    let paths = input.paths?.length || discover ? calls.slice(0, limit) : calls.map((p) => withBase(input.basePath ?? "", p)).slice(0, limit);
    if (!paths.length) return { status: "harvest", run: this.engagement.startRun({ actor: caller.actor, origin: caller.origin, tool: "apiprobe", command: `probe ${base.origin}`, targets: [], risk: input.risk, policy: { result: "denied", reason: "no paths" }, runner: "local" }), error: "no endpoints to probe: pass paths, or harvest/map the app first" };
    const label = `probe ${paths.length} endpoints on ${base.origin}`;
    const decision = this.check([base.href], input.risk, approvedBy ? { type: "human" } : caller.policy);
    if (decision.decision === "deny") return this.deny(caller, "apiprobe", [base.href], [base.href], input.risk, decision);
    if (decision.decision === "ask") {
      const grant = this.grantFor(caller, "apiprobe", [base.origin], input.risk);
      if (grant) return this.probeEndpoints(input, { ...caller, policy: { type: "human" } }, grant.by);
      return this.requestApproval(caller, decision, label, { kind: "http", origin: base.origin, raw: `GET ${paths[0]} HTTP/1.1\r\nHost: ${base.host}\r\n\r\n[+ ${paths.length - 1} more endpoints]`, risk: input.risk, probe: { tool: "apiprobe", input } });
    }
    const resolvedHeader = input.header ? this.engagement.resolveSecrets([input.header]) : undefined;
    if (resolvedHeader?.missing.length) return this.deny(caller, "apiprobe", [base.href], [base.href], input.risk, { decision: "deny", code: "UNKNOWN_SECRET", reason: `Unknown secret(s): ${resolvedHeader.missing.join(", ")}` } as never);
    const headerLine = resolvedHeader?.argv[0];
    const run = this.engagement.startRun({ actor: caller.actor, origin: caller.origin, tool: "apiprobe", command: label, targets: [base.href], risk: input.risk, policy: { result: approvedBy ? "approved" : "allowed", ...(decision.ruleId ? { ruleId: decision.ruleId } : {}) }, runner: "local", attack: ["T1595"] });
    const probe = async (path: string, withHeader: boolean): Promise<{ status: number; size: number } | undefined> => {
      try {
        const u = new URL(samplePath(path), base.origin);
        const headers: Array<[string, string]> = [["Host", u.host]];
        if (withHeader && headerLine) {
          const i = headerLine.indexOf(":");
          if (i > 0) headers.push([headerLine.slice(0, i).trim(), headerLine.slice(i + 1).trim()]);
        }
        const r = await sendHttp(u, { method: "GET", path: u.pathname + u.search, headers, body: "" });
        return { status: r.status, size: r.size };
      } catch {
        return undefined;
      }
    };
    // The API's base path, measured: a sample of the app's calls under each candidate base; the base
    // under which they exist (not a 404, and not the same answer an invented path gets) wins.
    let basePath: string | undefined;
    const baseTrials: Array<{ basePath: string; exist: number; of: number }> = [];
    if (discover) {
      // Spread over the whole list: an app's calls come mixed with its screens, in any order.
      const plain = calls.filter((p) => !/[:{]/.test(p));
      const pool = plain.length >= 8 ? plain : calls;
      const step = Math.max(1, Math.floor(pool.length / 30));
      const sample = pool.filter((_, i) => i % step === 0).slice(0, 30);
      const remembered = (this.engagement.getState<Array<{ origin: string; basePath: string }>>("apiBases") ?? []).filter((b) => canonicalOrigin(b.origin) === canonicalOrigin(base.origin)).map((b) => b.basePath);
      const candidates = [...new Set([...remembered, "/api", "", "/api/v1", "/v1", "/api/v2", "/rest"].map((c) => c.replace(/\/+$/, "")))];
      for (const c of candidates) {
        const control = await probe(withBase(c, `/penteos-${Math.random().toString(36).slice(2, 10)}`), false);
        let exist = 0;
        for (const p of sample) {
          const r = await probe(withBase(c, p), false);
          if (r && r.status !== 404 && !(control && r.status === control.status && r.size === control.size)) exist++;
        }
        baseTrials.push({ basePath: c || "/", exist, of: sample.length });
      }
      const best = [...baseTrials].sort((a, b) => b.exist - a.exist || a.basePath.length - b.basePath.length)[0];
      if (!best || best.exist === 0) {
        const done = this.engagement.finishRun(run.id, { status: "failed", summary: { error: "no API base found", baseTrials } });
        return { status: "probe", run: done, baseTrials, error: `none of the base paths tried (${baseTrials.map((t) => t.basePath).join(", ")}) has the app's calls: every sample answered 404 or the same as an invented path. Pass basePath if you know it, or paths.` };
      }
      basePath = best.basePath === "/" ? "" : best.basePath;
      paths = calls.map((p) => withBase(basePath!, p)).slice(0, limit);
    }
    try {
      // What the API's own contract declares, when it was read (web_read_api_spec): a route it says
      // needs credentials and answers without them is a gap whatever its siblings do.
      const declared = new Map<string, boolean>();
      const app = this.engagement.query({ kind: "webapp", limit: 500 }).find((a) => canonicalOrigin(String(a.attributes.origin)) === canonicalOrigin(base.origin));
      if (app) for (const ep of this.engagement.query({ kind: "endpoint", limit: 50_000 })) if (ep.attributes.webappId === app.id && typeof ep.attributes.requiresAuth === "boolean") declared.set(String(ep.attributes.pathTemplate), ep.attributes.requiresAuth as boolean);
      const results: Array<{ path: string; noAuth?: number; size?: number; withHeader?: number }> = new Array(paths.length);
      let next = 0;
      // A few requests at a time: quick on hundreds of routes, gentle on the server.
      await Promise.all(
        Array.from({ length: Math.min(4, paths.length) }, async () => {
          while (next < paths.length) {
            const i = next++;
            const path = paths[i]!;
            const na = await probe(path, false);
            const wh = headerLine ? await probe(path, true) : undefined;
            results[i] = { path, ...(na ? { noAuth: na.status, size: na.size } : {}), ...(wh ? { withHeader: wh.status } : {}) };
          }
        }),
      );
      // The expected answer without auth is the most common status; anything that answers with data
      // where the rest refuse (2xx among 401/403, or just differs toward success) is the gap.
      const statuses = results.map((r) => r.noAuth).filter((s): s is number => s !== undefined);
      const mode = statuses.sort((a, b) => statuses.filter((x) => x === b).length - statuses.filter((x) => x === a).length)[0];
      const refusing = mode === 401 || mode === 403;
      // A route the contract declares public is meant to answer: not a gap.
      // A static asset (a stylesheet, script, image, font…) answering without auth is public by
      // design, not an exposure: it would only flood the results. So are robots.txt, the sign-in
      // and sign-up pages and the legal pages.
      const open = results.filter((r) => r?.noAuth !== undefined && r.noAuth >= 200 && r.noAuth < 300 && declared.get(r.path) !== false && !isStaticAsset(r.path) && !isPublicByDesign(r.path) && (refusing || r.noAuth !== mode || declared.get(r.path) === true));
      const items: unknown[] = [];
      for (const r of results.filter(Boolean)) {
        if (r?.noAuth !== undefined) items.push({ op: "upsert", kind: "endpoint", key: { origin: base.origin, path: r.path.split("?")[0] }, attributes: { statusesSeen: [r.noAuth] }, confidence: 0.8 });
      }
      for (const [i, r] of open.slice(0, 30).entries()) {
        const contract = declared.get(r.path) === true;
        // What it answered, kept for evidence and for measuring its impact (the first ones).
        let bodyRaw: string | undefined;
        if (i < 10) {
          try {
            const u = new URL(samplePath(r.path), base.origin);
            const res = await sendHttp(u, { method: "GET", path: u.pathname + u.search, headers: [["Host", u.host], ["Accept", "application/json, */*"]], body: "" });
            bodyRaw = this.engagement.putRaw(`GET ${u.pathname}${u.search} HTTP/1.1\nHost: ${u.host}\n\n${formatResponse(res)}`, { type: "http_exchange", mime: "text/plain", runId: run.id });
          } catch {
            /* the observation stands without it */
          }
        }
        items.push({ op: "observe", title: `Endpoint answers without authentication: ${r.path}`, sourceRule: "apiprobe:no-auth", affects: [{ kind: "endpoint", key: { origin: base.origin, path: r.path.split("?")[0] } }], severityHint: refusing || contract ? "high" : "medium", detail: `GET ${samplePath(r.path)} returned ${r.noAuth} (${r.size} bytes) with no credentials${contract ? ", although the API's own contract says it requires authentication" : `, while most endpoints return ${mode}`}. Verify it exposes data or an action that should require authentication.`, ...(bodyRaw ? { rawId: bodyRaw } : {}) });
      }
      // Server errors met while sweeping: leads to vary the input on (the first few).
      for (const r of results.filter((x) => x?.noAuth !== undefined && leadFor(x.noAuth, "")).slice(0, 5)) {
        items.push({ op: "observe", ...leadFor(r.noAuth!, `GET ${r.path}`)!, affects: [{ kind: "endpoint", key: { origin: base.origin, path: r.path.split("?")[0] } }], severityHint: "info" });
      }
      const rawId = this.engagement.putRaw(`# api probe ${base.origin}\nmode no-auth status: ${mode}\n\n${results.map((r) => `${r.noAuth ?? "ERR"}\t${r.withHeader !== undefined ? r.withHeader + "\t" : ""}${r.path}`).join("\n")}`, { type: "stdout", mime: "text/plain", runId: run.id });
      const ingested = items.length ? this.engagement.ingest({ format: INGEST_FORMAT, source: { parser: "apiprobe@0.1.0", tool: "apiprobe" }, rawIds: [rawId], observedAt: new Date().toISOString(), items } as never, caller.actor) : undefined;
      const done = this.engagement.finishRun(run.id, { status: "finished", rawIds: [rawId], summary: { probed: results.length, modeStatus: mode ?? null, withoutAuth: open.length, ...(ingested ? { ingested } : {}) } });
      this.engagement.noteReachability(base.hostname, true);
      return { status: "probe", run: done, results, open: open.map((r) => r.path), modeStatus: mode, rawId, ...(basePath !== undefined ? { basePath: basePath || "/", baseTrials } : {}) };
    } catch (e) {
      this.engagement.noteReachability(base.hostname, false, (e as Error).message);
      const done = this.engagement.finishRun(run.id, { status: "failed", summary: { error: (e as Error).message } });
      return { status: "probe", run: done, error: (e as Error).message };
    }
  }

  // -------------------------------------------------------------------------------------------
  // API contracts
  // -------------------------------------------------------------------------------------------

  /**
   * Reads an API's published contract (OpenAPI 3 / Swagger 2 JSON) from an in-scope URL and puts
   * every route in the graph with its methods, parameters and declared authentication, so the
   * whole surface can be swept (web_probe_endpoints) instead of a handful of routes. A contract
   * served without credentials is itself recorded as an observation.
   */
  async readApiSpec(input: { url: string; risk: RiskLevel }, caller: ToolCaller, approvedBy?: Actor): Promise<RunOutcome> {
    const url = new URL(input.url);
    const label = `read API contract ${url.href}`;
    const decision = this.check([url.href], input.risk, approvedBy ? { type: "human" } : caller.policy);
    if (decision.decision === "deny") return this.deny(caller, "apispec", [url.href], [url.href], input.risk, decision);
    if (decision.decision === "ask") {
      const grant = this.grantFor(caller, "apispec", [url.origin], input.risk);
      if (grant) return this.readApiSpec(input, { ...caller, policy: { type: "human" } }, grant.by);
      return this.requestApproval(caller, decision, label, { kind: "http", origin: url.origin, raw: `GET ${url.pathname}${url.search} HTTP/1.1`, risk: input.risk, probe: { tool: "apispec", input } });
    }
    const run = this.engagement.startRun({ actor: caller.actor, origin: caller.origin, tool: "apispec", command: label, targets: [url.href], risk: input.risk, policy: { result: approvedBy ? "approved" : "allowed", ...(decision.ruleId ? { ruleId: decision.ruleId } : {}) }, runner: "local", attack: ["T1595"] });
    try {
      const res = await sendHttp(url, { method: "GET", path: url.pathname + url.search, headers: [["Host", url.host], ["Accept", "application/json"]], body: "" });
      if (res.status >= 400) throw new Error(`the contract URL answered ${res.status}`);
      const spec = parseApiSpec(res.body);
      const rawId = this.engagement.putRaw(res.body, { type: "stdout", mime: "application/json", runId: run.id });
      const routes = new Map<string, { methods: Set<string>; params: Map<string, string>; requiresAuth?: boolean }>();
      for (const e of spec.endpoints) {
        const cur = routes.get(e.path) ?? { methods: new Set<string>(), params: new Map<string, string>() };
        cur.methods.add(e.method);
        for (const p of e.params) cur.params.set(p.name, p.location);
        if (e.requiresAuth !== undefined) cur.requiresAuth = cur.requiresAuth === true || e.requiresAuth;
        routes.set(e.path, cur);
      }
      const items: unknown[] = [{ op: "upsert", kind: "webapp", key: { origin: url.origin }, confidence: 1 }];
      for (const [path, r] of routes) {
        items.push({
          op: "upsert",
          kind: "endpoint",
          key: { origin: url.origin, path },
          attributes: { methods: [...r.methods], params: [...r.params].map(([name, location]) => ({ name, location })), ...(r.requiresAuth !== undefined ? { requiresAuth: r.requiresAuth } : {}) },
          confidence: 0.9,
        });
      }
      items.push({ op: "observe", title: `API contract published without authentication (${routes.size} routes)`, sourceRule: "apispec:exposed", affects: [{ kind: "webapp", key: { origin: url.origin } }], severityHint: "low", detail: `${url.href} serves the full ${spec.title ? `"${spec.title}" ` : ""}contract (${spec.endpoints.length} operations on ${routes.size} routes) to anyone. Library template: exposed-api-documentation.` });
      const ingested = this.engagement.ingest({ format: INGEST_FORMAT, source: { parser: "apispec@0.1.0", tool: "apispec" }, rawIds: [rawId], observedAt: new Date().toISOString(), items } as never, caller.actor);
      const done = this.engagement.finishRun(run.id, { status: "finished", rawIds: [rawId], summary: { routes: routes.size, operations: spec.endpoints.length, ingested } });
      return { status: "apispec", run: done, routes: [...routes].map(([path, r]) => ({ path, methods: [...r.methods], ...(r.requiresAuth !== undefined ? { requiresAuth: r.requiresAuth } : {}) })), ...(spec.title ? { title: spec.title } : {}), rawId };
    } catch (e) {
      const done = this.engagement.finishRun(run.id, { status: "failed", summary: { error: (e as Error).message } });
      return { status: "apispec", run: done, error: (e as Error).message };
    }
  }

  // -------------------------------------------------------------------------------------------
  // The agents' browser
  // -------------------------------------------------------------------------------------------

  /**
   * One action in the engagement's headless browser: open a URL,
   * click, fill a field, read the page or take a screenshot. Every request it makes goes through
   * Penteos's proxy (scope applies there too); here the URL it opens is checked like any target,
   * the action is a run, and screenshots are raw artifacts to cite as evidence.
   */
  async browse(input: { action: BrowseAction; risk: RiskLevel }, caller: ToolCaller, approvedBy?: Actor): Promise<RunOutcome> {
    const a = input.action;
    const where = a.action === "visit" ? new URL(a.url).href : undefined;
    const label = a.action === "visit" ? `browser open ${where}` : a.action === "click" ? `browser click ${a.selector ?? `«${a.text ?? ""}»`}` : a.action === "fill" ? `browser fill ${a.selector}${a.submit ? " and submit" : ""}` : `browser ${a.action}`;
    if (where) {
      const decision = this.check([where], input.risk, approvedBy ? { type: "human" } : caller.policy);
      if (decision.decision === "deny") return this.deny(caller, "browser", [where], [where], input.risk, decision);
      if (decision.decision === "ask") {
        const grant = this.grantFor(caller, "browser", [new URL(where).origin], input.risk);
        if (grant) return this.browse(input, { ...caller, policy: { type: "human" } }, grant.by);
        const u = new URL(where);
        return this.requestApproval(caller, decision, label, { kind: "http", origin: u.origin, raw: `GET ${u.pathname}${u.search} HTTP/1.1\r\nHost: ${u.host}`, risk: input.risk, probe: { tool: "browser", input } });
      }
    } else if (!browserOpen(this.engagement.info.id)) {
      throw new Error("the browser has no page open yet: start with action visit");
    }
    const gated = this.phaseGate(caller, input.risk, approvedBy);
    if (gated) return this.deny(caller, "browser", [label], where ? [where] : [], input.risk, gated);
    // Credentials typed into a form go as {{secret:name}}: resolved for the page only, never recorded.
    let action = a;
    if (a.action === "fill") {
      const resolved = this.engagement.resolveSecrets([a.value]);
      if (resolved.missing.length) throw new Error(`Unknown secret(s): ${resolved.missing.join(", ")}. Save them first with secret_save.`);
      action = { ...a, value: resolved.argv[0]! };
    }
    const run = this.engagement.startRun({ actor: caller.actor, origin: caller.origin, tool: "browser", command: label, targets: where ? [where] : [], risk: input.risk, policy: { result: approvedBy ? "approved" : "allowed" }, runner: "local", attack: ["T1594"] });
    try {
      const r = await browse(this.engagement.info.id, action);
      const { screenshot, ...rest } = r;
      const report = this.engagement.redact(JSON.stringify(rest, null, 1));
      const rawIds = [this.engagement.putRaw(report, { type: "stdout", mime: "application/json", runId: run.id })];
      const screenshotRawId = screenshot ? this.engagement.putRaw(screenshot, { type: "screenshot", mime: "image/png", runId: run.id, originalName: "screenshot.png" }) : undefined;
      if (screenshotRawId) rawIds.push(screenshotRawId);
      const done = this.engagement.finishRun(run.id, { status: "finished", rawIds, summary: { url: r.page.url, title: r.page.title, requests: r.requests.length, dialogs: r.dialogs.length } });
      return { status: "browser", run: done, result: rest, rawId: rawIds[0]!, ...(screenshotRawId ? { screenshotRawId } : {}) };
    } catch (e) {
      const done = this.engagement.finishRun(run.id, { status: "failed", summary: { error: (e as Error).message } });
      return { status: "browser", run: done, error: (e as Error).message };
    }
  }

  // -------------------------------------------------------------------------------------------
  // Rate limiting
  // -------------------------------------------------------------------------------------------

  /**
   * Open redirect, path traversal in path parameters and session guards that only check a cookie
   * exists (webprobes.ts says how each is read). Candidates come from what was learned before - the
   * redirect parameters and screens the JavaScript names, the endpoint templates in the graph - or
   * are given. Politely paced; every exchange that shows something is kept as evidence.
   */
  async webProbe(input: WebProbeInput, caller: ToolCaller, approvedBy?: Actor): Promise<RunOutcome> {
    const base = new URL(input.origin);
    const origin = base.origin;
    const leads = this.engagement.getState<Record<string, { redirectParams: string[]; routes: string[] }>>("jsLeads")?.[canonicalOrigin(origin)] ?? { redirectParams: [], routes: [] };
    const endpoints = this.engagement.query({ kind: "endpoint", limit: 20000 }).filter((e) => e.naturalKey.startsWith(`${canonicalOrigin(origin)}|`));
    const label = `${input.check} probe ${origin}`;
    const decision = this.check([base.href], input.risk, approvedBy ? { type: "human" } : caller.policy);
    if (decision.decision === "deny") return this.deny(caller, "webprobe", [base.href], [base.href], input.risk, decision);
    if (decision.decision === "ask") {
      const grant = this.grantFor(caller, "webprobe", [origin], input.risk);
      if (grant) return this.webProbe(input, { ...caller, policy: { type: "human" } }, grant.by);
      return this.requestApproval(caller, decision, label, { kind: "http", origin, raw: `${input.check} checks on ${origin} (GET requests with test values)`, risk: input.risk, probe: { tool: "webprobe", input } });
    }
    const run = this.engagement.startRun({ actor: caller.actor, origin: caller.origin, tool: "webprobe", command: label, targets: [base.href], risk: input.risk, policy: { result: approvedBy ? "approved" : "allowed", ...(decision.ruleId ? { ruleId: decision.ruleId } : {}) }, runner: "local", attack: ["T1190"] });
    const get = async (path: string, headers: Array<[string, string]> = []) => {
      const u = new URL(path, origin);
      const r = await sendHttp(u, { method: "GET", path: path.startsWith("/") ? path : u.pathname + u.search, headers: [["Host", u.host], ...headers], body: "" });
      await new Promise((res) => setTimeout(res, 100));
      return { r, exchange: `GET ${path} HTTP/1.1\nHost: ${u.host}${headers.map(([k, v]) => `\n${k}: ${v}`).join("")}\n\n${formatResponse(r).slice(0, 3000)}` };
    };
    const hits: Array<WebProbeHit & { exchange: string }> = [];
    const log: string[] = [`# ${label}`];
    let tried = 0;
    try {
      if (input.check === "redirect") {
        const paths = new Set(["/", "/login", "/logout", "/auth/login", "/signin", ...endpoints.map((e) => String(e.attributes.pathTemplate ?? "")).filter((p) => /log-?in|log-?out|sign|auth|sso|oauth|callback|redirect|return/i.test(p) && !/[{:]/.test(p))]);
        const params = new Set([...leads.redirectParams.filter((p) => p.length > 1), "redirect", "redirectUrl", "returnUrl", "next", "callbackUrl", "url", "returnTo"]);
        const targets = input.targets?.length ? input.targets : [...paths].slice(0, 8).flatMap((path) => [...params].slice(0, 10).map((param) => ({ path, param })));
        for (const t of targets.slice(0, 80)) {
          for (const payload of REDIRECT_PAYLOADS) {
            const path = `${t.path}${t.path.includes("?") ? "&" : "?"}${encodeURIComponent(t.param)}=${payload.includes("%") ? payload : encodeURIComponent(payload)}`;
            tried++;
            const { r, exchange } = await get(path);
            if (redirectsToCanary(r.status, r.headers, r.body, new URL(path, origin).href)) {
              log.push(`REDIRECT ${path} → ${r.status}`);
              hits.push({ title: `Open redirect: ${t.param} on ${t.path}`, severity: "medium", path: t.path, detail: `GET ${path} sends the browser to ${REDIRECT_CANARY} (${r.status}). Links on the client's own domain can take users to any site (phishing, stolen OAuth codes when used in a login flow).`, exchange });
              break;
            }
          }
        }
      } else if (input.check === "traversal") {
        const templates = input.templates?.length ? input.templates : [...new Set(endpoints.map((e) => String(e.attributes.pathTemplate ?? "")).filter((p) => /\{[^}]+\}|:[A-Za-z_]/.test(p)))].slice(0, 25);
        for (const tpl of templates) {
          const normal = fillTemplate(tpl, "penteos-probe-1");
          if (!normal) continue;
          tried++;
          const b = await get(normal);
          const answer = (x: typeof b.r) => ({ status: x.status, size: x.body.length, type: x.headers.find(([k]) => k.toLowerCase() === "content-type")?.[1] ?? "" });
          const baseline = answer(b.r);
          log.push(`${normal}: ${baseline.status} ${baseline.size}B ${baseline.type}`);
          for (const payload of TRAVERSAL_PAYLOADS) {
            const path = fillTemplate(tpl, payload)!;
            tried++;
            const v = await get(path);
            const ans = answer(v.r);
            log.push(`  ${path}: ${ans.status} ${ans.size}B ${ans.type}`);
            if (traversalReached(baseline, ans)) {
              hits.push({ title: `Path parameter of ${tpl} walks out of its route (${payload})`, severity: "medium", path: tpl, detail: `A normal value answers ${baseline.status} (${baseline.size} bytes, ${baseline.type || "no type"}); ${payload} in its place answers ${ans.status} (${ans.size} bytes, ${ans.type || "no type"}). The parameter reaches other routes of the server: find which (add the route after the payload: ${path}health, …) and whether they need authentication.`, exchange: `${b.exchange}\n\n----\n\n${v.exchange}` });
              break;
            }
          }
        }
      } else {
        const fromRoutes = guardedRoutes([...leads.routes, ...endpoints.map((e) => String(e.attributes.pathTemplate ?? ""))]);
        const paths = input.paths?.length ? input.paths : fromRoutes.length ? fromRoutes : ["/dashboard", "/admin", "/account"];
        const seenCookies = this.engagement.getState<string[]>("cookieNames") ?? [];
        const names = [...new Set([...seenCookies, ...SESSION_COOKIES])].slice(0, 30);
        const fake = `penteos-invented-${ulid().toLowerCase()}`;
        for (const path of paths.slice(0, 20)) {
          tried += 2;
          const none = await get(path);
          if (!looksSentAway(none.r.status, none.r.headers)) {
            log.push(`${path}: ${none.r.status} without a cookie (not guarded, or not a screen)`);
            continue;
          }
          const withFake = await get(path, [["Cookie", names.map((n) => `${n}=${fake}`).join("; ")]]);
          log.push(`${path}: ${none.r.status} without a cookie, ${withFake.r.status} with invented ones`);
          if (withFake.r.status >= 200 && withFake.r.status < 300) {
            hits.push({ title: `${path} is served with an invented session cookie`, severity: "medium", path, detail: `Without a cookie ${path} sends to the login (${none.r.status}); with made-up session cookies it answers ${withFake.r.status} (${withFake.r.body.length} bytes). The guard checks that a cookie exists, not that the session is valid. If the page renders data on the server, that data is exposed; if it only draws the shell, the risk is latent (any server-rendered route added later is open).`, exchange: `${none.exchange}\n\n----\n\n${withFake.exchange}` });
          }
        }
      }
      const rawId = this.engagement.putRaw(log.join("\n"), { type: "stdout", mime: "text/plain", runId: run.id });
      const items = hits.flatMap((h) => {
        const ex = this.engagement.putRaw(h.exchange, { type: "http_exchange", mime: "message/http", runId: run.id });
        const key = { origin, path: h.path.split("?")[0] };
        // The endpoint may not be in the graph yet (a screen known only from the JavaScript).
        return [
          { op: "upsert", kind: "endpoint", key, attributes: { methods: ["GET"] }, confidence: 0.9 },
          { op: "observe", title: h.title, sourceRule: `webprobe:${input.check}`, affects: [{ kind: "endpoint", key }], severityHint: h.severity, detail: h.detail, rawId: ex },
        ];
      });
      const ingested = items.length ? this.engagement.ingest({ format: INGEST_FORMAT, source: { parser: "webprobe@0.1.0", tool: "webprobe" }, rawIds: [rawId], observedAt: new Date().toISOString(), items } as never, caller.actor) : undefined;
      const done = this.engagement.finishRun(run.id, { status: "finished", rawIds: [rawId], summary: { check: input.check, tried, hits: hits.length, ...(ingested ? { ingested } : {}) } });
      return { status: "webprobe", run: done, check: input.check, tried, hits: hits.map(({ exchange: _x, ...h }) => h), rawId };
    } catch (e) {
      const done = this.engagement.finishRun(run.id, { status: "failed", summary: { error: (e as Error).message } });
      return { status: "webprobe", run: done, check: input.check, tried, hits: hits.map(({ exchange: _x, ...h }) => h), error: (e as Error).message };
    }
  }

  /**
   * DNS-only checks (passive: lookups, nothing sent to the target's servers but the resolvers):
   * mail spoofing for a domain (SPF, DMARC, DKIM), or subdomain takeover for names (a CNAME chain
   * ending at a claimable service, or at nothing). For takeover, a name in scope for active work is
   * also asked over HTTP(S), since the service's own "does not exist" page is the proof.
   */
  async checkDns(input: { kind: "mail"; domain: string } | { kind: "takeover"; names?: string[] }, caller: ToolCaller): Promise<RunOutcome> {
    const passiveOk = (name: string) => this.check([name], "passive", caller.policy).decision !== "deny";
    const names =
      input.kind === "mail"
        ? [input.domain.replace(/^[a-z][a-z0-9+.-]*:\/\//i, "").replace(/[:/].*$/, "").toLowerCase()]
        : (input.names?.length ? input.names : this.engagement.query({ kind: "domain", limit: 5000 }).map((d) => String(d.attributes.fqdn))).map((n) => n.replace(/^[a-z][a-z0-9+.-]*:\/\//i, "").replace(/[:/].*$/, "").toLowerCase());
    const allowed = [...new Set(names)].filter(passiveOk).slice(0, 300);
    if (!allowed.length) {
      const decision = this.check([names[0] ?? ""], "passive", caller.policy);
      return this.deny(caller, "dnscheck", names, names, "passive", decision.decision === "deny" ? decision : { decision: "deny", code: "OUT_OF_SCOPE", reason: "no name in scope" } as never);
    }
    const label = input.kind === "mail" ? `mail DNS ${allowed[0]}` : `takeover DNS ×${allowed.length}`;
    const run = this.engagement.startRun({ actor: caller.actor, origin: caller.origin, tool: "dnscheck", command: label, targets: allowed, risk: "passive", policy: { result: "allowed" }, runner: "local", attack: ["T1590.002"] });
    const issues: Array<DnsIssue & { name: string }> = [];
    const log: string[] = [`# ${label}`];
    try {
      if (input.kind === "mail") {
        const r = await lookupMail(allowed[0]!);
        log.push(`SPF: ${r.spf ?? "none"}${r.spfCount > 1 ? ` (+${r.spfCount - 1} more)` : ""}`, `DMARC: ${r.dmarc ?? "none"}`, `DKIM selectors found: ${r.dkimSelectors.join(", ") || "none of the common ones"}`, `MX: ${r.mx.join(", ") || "none"}`);
        for (const i of mailIssues(r)) issues.push({ ...i, name: r.domain });
      } else {
        for (const name of allowed) {
          const rec = await lookupName(name);
          const svc = rec.cnames.length ? TAKEOVER_SERVICES.find((s) => s.cname.test(rec.cnames[rec.cnames.length - 1]!)) : undefined;
          // The service's own "not found" page is the proof; asked only where active work is in scope.
          if (svc?.body && rec.resolves && this.check([`https://${name}/`], "active", caller.policy).decision !== "deny") {
            for (const scheme of ["https", "http"]) {
              try {
                const u = new URL(`${scheme}://${name}/`);
                rec.body = (await sendHttp(u, { method: "GET", path: "/", headers: [["Host", u.host]], body: "" })).body.slice(0, 20_000);
                break;
              } catch {
                /* next scheme */
              }
            }
          }
          if (rec.cnames.length) log.push(`${name} → ${rec.cnames.join(" → ")} (${rec.resolves ? "resolves" : "DOES NOT RESOLVE"})${svc ? ` [${svc.service}]` : ""}`);
          const issue = takeoverIssue(rec);
          if (issue) issues.push({ ...issue, name });
        }
        log.push(`${allowed.length} name(s) checked, ${allowed.filter((n) => log.some((l) => l.startsWith(`${n} →`))).length} with a CNAME`);
      }
      const rawId = this.engagement.putRaw(log.join("\n"), { type: "stdout", mime: "text/plain", runId: run.id });
      const items = issues.map((i) => ({ op: "observe", title: i.title, sourceRule: `dns:${i.key}`, affects: [{ kind: "domain", key: { fqdn: i.name } }], severityHint: i.severity, detail: i.detail, rawId }));
      const ingested = items.length ? this.engagement.ingest({ format: INGEST_FORMAT, source: { parser: "dnscheck@0.1.0", tool: "dnscheck" }, rawIds: [rawId], observedAt: new Date().toISOString(), items } as never, caller.actor) : undefined;
      const done = this.engagement.finishRun(run.id, { status: "finished", rawIds: [rawId], summary: { checked: allowed.length, issues: issues.length, ...(ingested ? { ingested } : {}) } });
      return { status: "dnscheck", run: done, issues, checked: allowed.length, rawId };
    } catch (e) {
      const done = this.engagement.finishRun(run.id, { status: "failed", summary: { error: (e as Error).message } });
      return { status: "dnscheck", run: done, issues, error: (e as Error).message };
    }
  }

  /**
   * The connection itself: TLS versions and weak ciphers still accepted (hand-built handshakes, as
   * sslscan does: OpenSSL 3 cannot even offer 3DES or RC4), the certificate, plain HTTP turned away
   * or not, HSTS, cookie flags, CSP, framing and CORS. Each problem is an observation with the
   * evidence; a handful of handshakes and requests, nothing past the server's first answer.
   */
  async checkTransport(input: { target: string; path?: string; risk: RiskLevel }, caller: ToolCaller, approvedBy?: Actor): Promise<RunOutcome> {
    const raw = /^[a-z][a-z0-9+.-]*:\/\//i.test(input.target) ? input.target : `https://${input.target}`;
    const given = new URL(raw);
    const host = given.hostname.replace(/^\[|\]$/g, "");
    const port = given.protocol === "https:" ? Number(given.port || 443) : 443;
    const https = new URL(`https://${given.host.replace(/:\d+$/, "")}${port !== 443 ? `:${port}` : ""}${input.path ?? "/"}`);
    const plain = new URL(`http://${host}${input.path ?? "/"}`);
    const label = `transport ${https.origin}`;
    const decision = this.check([https.href], input.risk, approvedBy ? { type: "human" } : caller.policy);
    if (decision.decision === "deny") return this.deny(caller, "transport", [https.href], [https.href], input.risk, decision);
    if (decision.decision === "ask") {
      const grant = this.grantFor(caller, "transport", [https.origin], input.risk);
      if (grant) return this.checkTransport(input, { ...caller, policy: { type: "human" } }, grant.by);
      return this.requestApproval(caller, decision, label, { kind: "http", origin: https.origin, raw: `TLS handshakes (SSLv3, TLS 1.0/1.1/1.2, weak ciphers) to ${host}:${port}\r\nGET ${https.pathname} over HTTPS and plain HTTP, with test Origin headers`, risk: input.risk, probe: { tool: "transport", input } });
    }
    const run = this.engagement.startRun({ actor: caller.actor, origin: caller.origin, tool: "transport", command: label, targets: [https.href], risk: input.risk, policy: { result: approvedBy ? "approved" : "allowed", ...(decision.ruleId ? { ruleId: decision.ruleId } : {}) }, runner: "local", attack: ["T1595.002"] });
    const log: string[] = [`# ${label}`];
    const issues: TransportIssue[] = [];
    try {
      // TLS versions and weak cipher families.
      const modern = await tryHandshake(host, port, "TLSv1.2", CIPHERS.broad);
      log.push(`TLSv1.2 (broad ciphers): ${modern.accepted ? "accepted" : modern.error ?? "refused"}`);
      for (const v of ["SSLv3", "TLSv1.0", "TLSv1.1"] as const) {
        const r = await tryHandshake(host, port, v, CIPHERS.broad);
        log.push(`${v}: ${r.accepted ? `ACCEPTED (cipher 0x${r.cipher!.toString(16).padStart(4, "0")})` : r.error ?? "refused"}`);
        if (r.accepted) issues.push({ key: `tls:${v}`, severity: TLS_VERSION_SEVERITY[v], title: `${v} accepted`, detail: `${host}:${port} completes a ${v} handshake. ${v === "SSLv3" ? "SSLv3 is broken (POODLE)." : "TLS 1.0 and 1.1 are deprecated (RFC 8996) and fail PCI DSS."}` });
      }
      for (const fam of ["3DES", "RC4", "NULL or EXPORT"] as const) {
        let hit: { v: string; cipher: number } | undefined;
        for (const v of ["TLSv1.2", "TLSv1.0"] as const) {
          const r = await tryHandshake(host, port, v, CIPHERS[fam]);
          if (r.accepted) {
            hit = { v, cipher: r.cipher! };
            break;
          }
        }
        log.push(`${fam} ciphers: ${hit ? `ACCEPTED (${hit.v}, 0x${hit.cipher.toString(16).padStart(4, "0")})` : "refused"}`);
        if (hit) issues.push({ key: `cipher:${fam}`, severity: WEAK_CIPHER_SEVERITY[fam], title: `${fam} ciphers accepted`, detail: `${host}:${port} agrees to cipher 0x${hit.cipher.toString(16).padStart(4, "0")} over ${hit.v}. ${fam === "3DES" ? "3DES is vulnerable to SWEET32." : fam === "RC4" ? "RC4 is broken." : "These give no real encryption."}` });
      }
      const cert = await peerCertificate(host, port);
      log.push(`certificate: ${cert.cert?.subject?.CN ?? "?"}, valid to ${cert.cert?.valid_to ?? "?"}, ${cert.authorized ? "trusted" : `not trusted (${cert.error ?? "?"})`}`);
      issues.push(...certificateIssues(host, cert));
      // Plain HTTP: turned away to HTTPS, or served as it is - only when port 80 is in scope too.
      const get = (u: URL, extra: Array<[string, string]> = []) => sendHttp(u, { method: "GET", path: u.pathname + u.search, headers: [["Host", u.host], ...extra], body: "" });
      if (this.check([plain.href], input.risk, approvedBy ? { type: "human" } : caller.policy).decision === "deny") log.push(`plain HTTP: not checked (${plain.origin} is not in scope)`);
      else try {
        const r = await get(plain);
        const loc = r.headers.find(([k]) => k.toLowerCase() === "location")?.[1] ?? "";
        const toHttps = r.status >= 300 && r.status < 400 && /^https:\/\//i.test(new URL(loc, plain.href).href);
        log.push(`plain HTTP: ${r.status}${loc ? ` → ${loc}` : ""}`);
        if (!toHttps && r.status < 400) issues.push({ key: "http:served", severity: "medium", title: "Served over plain HTTP without redirecting to HTTPS", detail: `GET ${plain.href} answered ${r.status}${loc ? ` → ${loc}` : ""}: the site works unencrypted, so sessions and data can be read or changed on the network.` });
        issues.push(...cookieIssues(r.headers.filter(([k]) => k.toLowerCase() === "set-cookie").map(([, v]) => v), false).map((i) => ({ ...i, key: `http:${i.key}` })));
      } catch (e) {
        log.push(`plain HTTP: ${(e as Error).message}`);
      }
      // HTTPS: headers, cookies, CORS.
      const r = await get(https);
      const type = r.headers.find(([k]) => k.toLowerCase() === "content-type")?.[1] ?? "";
      log.push(`HTTPS ${https.pathname}: ${r.status} ${type}`);
      issues.push(...headerIssues(r.headers, /html/i.test(type)), ...cookieIssues(r.headers.filter(([k]) => k.toLowerCase() === "set-cookie").map(([, v]) => v), true));
      for (const o of ["https://penteos-cors-check.invalid", "null"]) {
        const c = await get(https, [["Origin", o]]);
        const issue = corsIssue(o, c.headers);
        log.push(`CORS Origin ${o}: ${c.headers.filter(([k]) => /^access-control-allow-(origin|credentials)$/i.test(k)).map(([k, v]) => `${k}: ${v}`).join(", ") || "no CORS headers"}`);
        if (issue) issues.push(issue);
      }
      const rawId = this.engagement.putRaw(`${log.join("\n")}\n\n# HTTPS response\n${formatResponse(r).slice(0, 4000)}`, { type: "stdout", mime: "text/plain", runId: run.id });
      const seen = new Set<string>();
      const items = issues
        .filter((i) => (seen.has(i.key) ? false : (seen.add(i.key), true)))
        .map((i) => ({ op: "observe", title: `${i.title} (${https.host})`, sourceRule: `transport:${i.key}`, affects: [{ kind: "webapp", key: { origin: https.origin } }], severityHint: i.severity, detail: i.detail, rawId }));
      const ingested = items.length ? this.engagement.ingest({ format: INGEST_FORMAT, source: { parser: "transport@0.1.0", tool: "transport" }, rawIds: [rawId], observedAt: new Date().toISOString(), items } as never, caller.actor) : undefined;
      const done = this.engagement.finishRun(run.id, { status: "finished", rawIds: [rawId], summary: { issues: items.length, ...(ingested ? { ingested } : {}) } });
      return { status: "transport", run: done, issues, rawId };
    } catch (e) {
      const done = this.engagement.finishRun(run.id, { status: "failed", summary: { error: (e as Error).message } });
      return { status: "transport", run: done, issues, error: (e as Error).message };
    }
  }

  /**
   * Next.js server actions are endpoints in disguise: the browser posts to the page with the
   * action's id in a Next-Action header, and the server runs the function. The bundles name them
   * (web_harvest_scripts); this calls each one with no arguments, without a session (or with a
   * lower role's), and says which ran, which refused, which failed on the input and which are gone.
   * Calling an action may change data (it is what they are for): intrusive, approved like one.
   */
  async probeServerActions(input: ServerActionsInput, caller: ToolCaller, approvedBy?: Actor): Promise<RunOutcome> {
    let base: URL;
    try {
      base = new URL(input.page ?? "/", input.origin);
    } catch {
      throw new Error(`not a URL: ${input.origin}`);
    }
    const known = this.engagement.getState<Record<string, Array<{ id: string; name?: string }>>>("serverActions")?.[canonicalOrigin(base.origin)] ?? [];
    const actions = (input.ids?.length ? input.ids.map((id) => known.find((a) => a.id === id) ?? { id }) : known).slice(0, 300);
    if (!actions.length) throw new Error("no server actions known for this origin: run web_harvest_scripts on its pages first (or pass ids)");
    const label = `server actions ${base.origin}${base.pathname} ×${actions.length}${input.header ? " (with a session)" : ""}`;
    const decision = this.check([base.href], input.risk, approvedBy ? { type: "human" } : caller.policy);
    if (decision.decision === "deny") return this.deny(caller, "serveractions", [base.href], [base.href], input.risk, decision);
    if (decision.decision === "ask") {
      const grant = this.grantFor(caller, "serveractions", [base.origin], input.risk);
      if (grant) return this.probeServerActions(input, { ...caller, policy: { type: "human" } }, grant.by);
      return this.requestApproval(caller, decision, label, { kind: "http", origin: base.origin, raw: `POST ${base.pathname} HTTP/1.1\r\nHost: ${base.host}\r\nNext-Action: ${actions[0]!.id}\r\n\r\n[]\r\n\r\n[+ ${actions.length - 1} more actions, each called once with no arguments]`, risk: input.risk, probe: { tool: "serveractions", input } });
    }
    const run = this.engagement.startRun({ actor: caller.actor, origin: caller.origin, tool: "serveractions", command: label, targets: [base.href], risk: input.risk, policy: { result: approvedBy ? "approved" : "allowed", ...(decision.ruleId ? { ruleId: decision.ruleId } : {}) }, runner: "local", attack: ["T1190"] });
    const resolved = input.header ? this.engagement.resolveSecrets([input.header]) : undefined;
    if (resolved?.missing.length) throw new Error(`Unknown secret(s): ${resolved.missing.join(", ")}. Save them first with secret_save.`);
    const extra = resolved ? (() => {
      const h = resolved.argv[0]!;
      const i = h.indexOf(":");
      return i > 0 ? [[h.slice(0, i).trim(), h.slice(i + 1).trim()] as [string, string]] : [];
    })() : [];
    const results: ServerActionResult[] = [];
    const lines = [`# ${label}`];
    try {
      for (const a of actions) {
        const res = await sendHttp(base, { method: "POST", path: base.pathname + base.search, headers: [["Host", base.host], ["Next-Action", a.id], ["Accept", "text/x-component"], ["Content-Type", "text/plain;charset=UTF-8"], ...extra], body: "[]" });
        const body = res.body.slice(0, 2000);
        const verdict: ServerActionResult["verdict"] =
          res.status === 404 || /server action not found|failed to find server action/i.test(body) ? "missing"
          : res.status === 401 || res.status === 403 || /x-action-redirect/i.test(res.headers.map(([k]) => k).join(" ")) && /login|sign-?in|auth/i.test(res.headers.map(([, v]) => v).join(" ")) || /unauthori[sz]ed|forbidden|no autorizado|not authenticated|sesi[oó]n/i.test(body) ? "protected"
          : res.status >= 500 ? "failed"
          : "ran";
        results.push({ id: a.id, ...(a.name ? { name: a.name } : {}), status: res.status, verdict });
        lines.push(`${a.id}\t${a.name ?? ""}\t${res.status}\t${verdict}\t${body.replace(/\s+/g, " ").slice(0, 200)}`);
        await new Promise((r) => setTimeout(r, 150));
      }
      const rawId = this.engagement.putRaw(lines.join("\n"), { type: "stdout", mime: "text/plain", runId: run.id });
      const ran = results.filter((r) => r.verdict === "ran");
      const items: unknown[] = [];
      for (const r of ran.slice(0, 40)) {
        items.push({ op: "observe", title: `Server action ${r.name ?? r.id.slice(0, 12)} runs ${input.header ? "with a lower role's session" : "without a session"} (${r.status})`, sourceRule: "serveractions:ran", affects: [{ kind: "webapp", key: { origin: base.origin } }], severityHint: "medium", detail: `POST ${base.pathname} with Next-Action: ${r.id} and no arguments answered ${r.status}${input.header ? " with the session given" : " with no session"}. Read what it returned (rawId) and what the action does: if it reads or changes data it should not for this caller, it is a finding.`, rawId });
      }
      for (const r of results.filter((x) => x.verdict === "failed").slice(0, 10)) {
        items.push({ op: "observe", ...leadFor(r.status, `server action ${r.name ?? r.id.slice(0, 12)}`)!, affects: [{ kind: "webapp", key: { origin: base.origin } }], severityHint: "info", rawId });
      }
      if (items.length) this.engagement.ingest({ format: INGEST_FORMAT, source: { parser: "serveractions@0.1.0", tool: "serveractions" }, rawIds: [rawId], observedAt: new Date().toISOString(), items } as never, caller.actor);
      const done = this.engagement.finishRun(run.id, { status: "finished", rawIds: [rawId], summary: { actions: results.length, ran: ran.length, protected: results.filter((r) => r.verdict === "protected").length, failed: results.filter((r) => r.verdict === "failed").length, missing: results.filter((r) => r.verdict === "missing").length } });
      return { status: "serveractions", run: done, results, rawId };
    } catch (e) {
      const done = this.engagement.finishRun(run.id, { status: "failed", summary: { error: (e as Error).message, results } });
      return { status: "serveractions", run: done, results, error: (e as Error).message };
    }
  }

  /**
   * A defence seen on an endpoint (a 429 or 423 from any request: the rate-limit probe, a fuzz, a
   * single request) settles an earlier "no rate limiting" there, which was measured with too few
   * attempts. Unreviewed ones become false positives with the reason; one already behind a finding
   * keeps its place and gets the note, and the finding is the one to correct.
   */
  private noteDefence(origin: string, path: string, how: string, by: Actor): void {
    try {
      const endpoint = this.engagement.findByKey("endpoint", naturalKeyFor("endpoint", { origin, path }));
      if (!endpoint) return;
      const stale = this.engagement
        .query({ kind: "observation", limit: 5000 })
        .filter((o) => o.attributes.sourceRule === "ratelimit:none" && (o.attributes.affects as Array<{ id: string }>).some((a) => a.id === endpoint.id) && !String(o.attributes.triageReason ?? "").startsWith("A later request"));
      for (const o of stale) {
        const reason = `A later request met the limit: ${how}. The earlier test stopped before reaching it.`;
        const linked = Boolean(o.attributes.findingId);
        this.engagement.editEntity(o.id, linked || (o.attributes.triage ?? "new") !== "new" ? { triageReason: reason } : { triage: "false_positive", triageReason: reason }, by);
      }
    } catch {
      /* a note, never a reason for the run to fail */
    }
  }

  /**
   * Sends the same request (a login, a password reset, an OTP check) a bounded number of times and
   * looks for any defence: a 429 or 423, a lockout or captcha message, an answer that changes, or a
   * delay that grows. Stops at the first sign of one. None after all the attempts is an observation
   * on that endpoint. Several endpoints of one origin go in one call and one approval (`more`), and
   * each gets an explicit verdict, so nobody has to try again by other means to be sure.
   * Intrusive by default: repeated logins can lock a real account.
   */
  async probeRateLimit(input: { origin: string; raw: string; more?: string[]; attempts?: number; risk: RiskLevel }, caller: ToolCaller, approvedBy?: Actor): Promise<RunOutcome> {
    // Limits commonly start between 10 and 20 attempts: fewer can only say "none seen yet".
    const attempts = Math.min(Math.max(input.attempts ?? 20, 15), 40);
    const raws = [input.raw, ...(input.more ?? [])].slice(0, 5);
    const resolved = this.engagement.resolveSecrets(raws);
    if (resolved.missing.length) throw new Error(`Unknown secret(s): ${resolved.missing.join(", ")}. Save them first with secret_save.`);
    const shownAll = raws.map((r) => parseRawRequest(r));
    const urls = shownAll.map((r) => requestUrl(input.origin, r));
    const url = urls[0]!;
    const label = `rate limit ${shownAll.map((r, i) => `${r.method} ${urls[i]!.pathname}`).join(", ")} on ${url.origin} ×${attempts}`;
    const hrefs = urls.map((u) => u.href);
    const decision = this.check(hrefs, input.risk, approvedBy ? { type: "human" } : caller.policy);
    if (decision.decision === "deny") return this.deny(caller, "ratelimit", [shownAll[0]!.method, ...hrefs], hrefs, input.risk, decision);
    if (decision.decision === "ask") {
      const grant = this.grantFor(caller, "ratelimit", [url.origin], input.risk);
      if (grant) return this.probeRateLimit(input, { ...caller, policy: { type: "human" } }, grant.by);
      return this.requestApproval(caller, decision, label, { kind: "http", origin: input.origin, raw: raws.join("\n\n---\n\n"), risk: input.risk, probe: { tool: "ratelimit", input } });
    }
    const busy = this.hostBusy(caller, hrefs);
    if (busy) return this.deny(caller, "ratelimit", [shownAll[0]!.method, ...hrefs], hrefs, input.risk, busy);
    const run = this.engagement.startRun({ actor: caller.actor, origin: caller.origin, tool: "ratelimit", command: label, targets: hrefs, risk: input.risk, policy: { result: approvedBy ? "approved" : "allowed", ...(decision.ruleId ? { ruleId: decision.ruleId } : {}) }, runner: "local", attack: ["T1110"] });
    const results: RateLimitResult[] = [];
    const items: unknown[] = [];
    const lines: string[] = [`# ${label}`];
    try {
      for (let k = 0; k < raws.length; k++) {
        const req = parseRawRequest(resolved.argv[k]!);
        // The resolved request's URL (secrets in the path or query), on the host that was checked.
        const u = requestUrl(input.origin, req);
        if (u.origin !== urls[k]!.origin) throw new Error("a saved secret changed the destination host of the request");
        const tries: Array<{ status: number; size: number; timeMs: number }> = [];
        let defence: string | undefined;
        for (let i = 0; i < attempts; i++) {
          const r = await sendHttp(u, req);
          tries.push({ status: r.status, size: r.size, timeMs: r.timeMs });
          // A route that does not exist accepts nothing: no point repeating it.
          if (i === 0 && MISSING_ROUTE.has(r.status)) break;
          if (r.status === 429 || r.status === 423) defence = `HTTP ${r.status} after ${i + 1} attempts`;
          else if (/too many|rate.?limit|demasiad|bloquead|locked|captcha|try again later|intente m[aá]s tarde/i.test(r.body)) defence = `lockout or captcha message after ${i + 1} attempts`;
          else if (i > 0 && r.status !== tries[0]!.status) defence = `the answer changed from ${tries[0]!.status} to ${r.status} after ${i + 1} attempts`;
          else if (i >= 3 && r.timeMs > Math.max(2000, tries[0]!.timeMs * 4)) defence = `answers slowed from ${tries[0]!.timeMs} ms to ${r.timeMs} ms`;
          if (defence) break;
        }
        const path = u.pathname;
        const statuses = [...new Set(tries.map((t) => t.status))];
        const times = tries.map((t) => t.timeMs);
        const missing = statuses.every((s) => MISSING_ROUTE.has(s));
        const inconclusive = !missing && !defence && statuses.every((s) => s >= 500);
        const result: RateLimitResult = {
          request: `${req.method} ${path}`,
          verdict: defence ? "defended" : missing ? "missing" : inconclusive ? "inconclusive" : "no_defence",
          attempts: tries.length,
          statuses,
          timeMs: [Math.min(...times), Math.max(...times)],
          ...(defence ? { defence } : {}),
        };
        results.push(result);
        if (defence && /^HTTP 42[39]|lockout/.test(defence)) this.noteDefence(u.origin, path, `${req.method} ${path}: ${defence}`, caller.actor);
        if (!missing) items.push({ op: "upsert", kind: "endpoint", key: { origin: u.origin, path }, attributes: { methods: [req.method], statusesSeen: statuses }, confidence: 0.9 });
        if (result.verdict === "no_defence") {
          items.push({ op: "observe", title: `No rate limiting on ${req.method} ${path}: ${tries.length} attempts accepted`, sourceRule: "ratelimit:none", affects: [{ kind: "endpoint", key: { origin: u.origin, path } }], severityHint: "medium", detail: `${tries.length} identical requests answered ${statuses.join("/")} in ${result.timeMs[0]}-${result.timeMs[1]} ms, with no 429, lockout, captcha or growing delay. Online guessing of passwords or codes is not slowed down.` });
        }
        lines.push("", `## ${req.method} ${path}`, ...tries.map((t, i) => `${i + 1}\t${t.status}\t${t.size} B\t${t.timeMs} ms`), defence ? `defence: ${defence}` : missing ? "route does not exist: nothing to measure" : inconclusive ? "only server errors: inconclusive" : `no defence after ${tries.length} attempts`);
      }
      const rawId = this.engagement.putRaw(lines.join("\n"), { type: "stdout", mime: "text/plain", runId: run.id });
      const ingested = this.engagement.ingest({ format: INGEST_FORMAT, source: { parser: "ratelimit@0.2.0", tool: "ratelimit" }, rawIds: [rawId], observedAt: new Date().toISOString(), items } as never, caller.actor);
      const first = results[0]!;
      const done = this.engagement.finishRun(run.id, { status: "finished", rawIds: [rawId], summary: { attempts: first.attempts, defence: first.defence ?? null, results, ingested } });
      return { status: "ratelimit", run: done, attempts: first.attempts, ...(first.defence ? { defence: first.defence } : {}), results, rawId };
    } catch (e) {
      const done = this.engagement.finishRun(run.id, { status: "failed", summary: { error: (e as Error).message, results } });
      return { status: "ratelimit", run: done, attempts: results[0]?.attempts ?? 0, results, error: (e as Error).message };
    }
  }

  /**
   * How far a route with an identifier reaches, measured instead of guessed: read-only GETs on
   * identifiers, told apart from what a missing record looks like (two invented ids). Integers:
   * the first ones, then doubling until records stop, a binary search for the highest, and a
   * random sample below it for the density (every id when the budget allows: exact count).
   */
  async measureEnumeration(input: EnumerationInput, caller: ToolCaller, approvedBy?: Actor): Promise<RunOutcome> {
    const fail = (error: string) => ({ status: "enumeration" as const, run: this.engagement.startRun({ actor: caller.actor, origin: caller.origin, tool: "enumeration", command: `enumerate ${input.template}`, targets: [], risk: input.risk, policy: { result: "denied", reason: error }, runner: "local" }), error });
    let base: URL;
    try {
      base = new URL(input.origin);
    } catch {
      return fail(`not an origin: ${input.origin}`);
    }
    const template = input.template.replace(/:([A-Za-z_][A-Za-z0-9_]*)/g, "{$1}");
    const holes = template.match(/\{[^}/]+\}/g) ?? [];
    if (!template.startsWith("/") || holes.length !== 1) return fail(`the template needs exactly one placeholder, like /api/tenants/{id} (got ${input.template})`);
    const budget = Math.min(Math.max(input.maxRequests ?? 120, 20), 500);
    const label = `enumerate ${template} on ${base.origin} (≤${budget} GET)`;
    const decision = this.check([base.href], input.risk, approvedBy ? { type: "human" } : caller.policy);
    if (decision.decision === "deny") return this.deny(caller, "enumeration", [base.href], [base.href], input.risk, decision);
    if (decision.decision === "ask") {
      const grant = this.grantFor(caller, "enumeration", [base.origin], input.risk);
      if (grant) return this.measureEnumeration(input, { ...caller, policy: { type: "human" } }, grant.by);
      return this.requestApproval(caller, decision, label, { kind: "http", origin: base.origin, raw: `GET ${template.replace(holes[0]!, "1")} HTTP/1.1\r\nHost: ${base.host}\r\n\r\n[+ up to ${budget - 1} more identifiers]`, risk: input.risk, probe: { tool: "enumeration", input } });
    }
    const busy = this.hostBusy(caller, [base.href]);
    if (busy) return this.deny(caller, "enumeration", [base.href], [base.href], input.risk, busy);
    const resolvedHeader = input.header ? this.engagement.resolveSecrets([input.header]) : undefined;
    if (resolvedHeader?.missing.length) return fail(`unknown secret(s): ${resolvedHeader.missing.join(", ")}`);
    const headerLine = resolvedHeader?.argv[0];
    const run = this.engagement.startRun({ actor: caller.actor, origin: caller.origin, tool: "enumeration", command: label, targets: [base.href], risk: input.risk, policy: { result: approvedBy ? "approved" : "allowed", ...(decision.ruleId ? { ruleId: decision.ruleId } : {}) }, runner: "local", attack: ["T1595"] });

    const log: string[] = [`# ${label}`, "id\tstatus\tbytes\trecord"];
    let used = 0;
    let sample: { id: string; body: string } | undefined;
    const escape = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    // The same answer with the identifier taken out: a missing record looks the same for any id.
    const shape = (body: string, id: string) => body.slice(0, 20_000).replace(new RegExp(`(?<![\\w-])${escape(id)}(?![\\w-])`, "g"), "<id>");
    const get = async (id: string) => {
      used++;
      const u = new URL(template.replace(holes[0]!, encodeURIComponent(id)), base.origin);
      const headers: Array<[string, string]> = [["Host", u.host], ["Accept", "application/json, */*"]];
      if (headerLine) {
        const i = headerLine.indexOf(":");
        if (i > 0) headers.push([headerLine.slice(0, i).trim(), headerLine.slice(i + 1).trim()]);
      }
      const r = await sendHttp(u, { method: "GET", path: u.pathname + u.search, headers, body: "" });
      return { status: r.status, size: r.size, body: r.body };
    };
    try {
      const missingIds = ["2147480" + String(Math.floor(Math.random() * 900) + 100), `penteos-${Math.random().toString(36).slice(2, 9)}`];
      const missing: Array<{ status: number; size: number; shape: string }> = [];
      for (const id of missingIds) {
        const r = await get(id);
        missing.push({ status: r.status, size: r.size, shape: shape(r.body, id) });
        log.push(`${id}\t${r.status}\t${r.size}\t(invented)`);
      }
      const tried = new Map<string, boolean>();
      const test = async (id: string): Promise<boolean | undefined> => {
        if (tried.has(id)) return tried.get(id);
        if (used >= budget) return undefined;
        const r = await get(id);
        const s = shape(r.body, id);
        const empty = /^\s*(null|\{\s*\}|\[\s*\]|"")?\s*$/.test(r.body);
        const hit = r.status >= 200 && r.status < 300 && !empty && !missing.some((m) => m.status === r.status && m.shape === s);
        tried.set(id, hit);
        if (hit && !sample) sample = { id, body: r.body };
        log.push(`${id}\t${r.status}\t${r.size}\t${hit ? "yes" : "no"}`);
        return hit;
      };

      let result: EnumerationResult;
      const fieldsOf = (body: string): string[] => {
        try {
          const doc = JSON.parse(body) as unknown;
          const obj = Array.isArray(doc) ? doc[0] : doc && typeof doc === "object" && "data" in (doc as object) && typeof (doc as { data: unknown }).data === "object" ? (doc as { data: unknown }).data : doc;
          return obj && typeof obj === "object" ? Object.keys(obj as object).slice(0, 40) : [];
        } catch {
          return [];
        }
      };
      if (input.values?.length) {
        for (const v of input.values.slice(0, budget - used)) await test(v);
        const hits = [...tried].filter(([, h]) => h).map(([id]) => id);
        result = { template, mode: "values", requests: used, hits: hits.slice(0, 25), estimate: hits.length, exact: true, fields: sample ? fieldsOf(sample.body) : [], missing: { status: missing[0]!.status, size: missing[0]!.size } };
      } else {
        const hitInts = () => [...tried].filter(([id, h]) => h && /^\d+$/.test(id)).map(([id]) => Number(id));
        const highest = () => Math.max(0, ...hitInts());
        const testInt = (n: number) => test(String(n));
        for (let n = 1; n <= 10; n++) await testInt(n);
        // Doubling until records stop (two neighbours checked too: ids have holes).
        let hi: number | undefined;
        for (let k = Math.max(16, highest() * 2); k < 2 ** 31 && used < budget - 20; k *= 2) {
          const hit = (await testInt(k)) || (await testInt(k - 1)) || (await testInt(Math.floor(k * 0.9)));
          if (hit === undefined) break;
          if (!hit) {
            hi = k;
            break;
          }
        }
        // Binary search for the highest id between the last record and the first silence.
        if (hi !== undefined) {
          let lo = highest();
          while (hi - lo > 1 && used < budget - 20) {
            const mid = Math.floor((lo + hi) / 2);
            const atMid = await testInt(mid);
            const next = atMid === false && mid + 1 < hi ? await testInt(mid + 1) : false;
            if (atMid === undefined || next === undefined) break;
            if (atMid) lo = mid;
            else if (next) lo = mid + 1;
            else hi = mid;
          }
        }
        const top = highest();
        // Density below the highest: every id when the budget allows, else a random sample.
        const untried = (n: number) => !tried.has(String(n));
        let exact = false;
        if (top > 0 && top - hitInts().length <= budget - used) {
          for (let n = 1; n <= top; n++) if (untried(n)) await testInt(n);
          exact = [...Array(top).keys()].every((i) => tried.has(String(i + 1)));
        }
        let density: number;
        if (exact) density = hitInts().filter((n) => n <= top).length / Math.max(1, top);
        else {
          const pool: number[] = [];
          for (let guard = 0; pool.length < Math.min(40, budget - used) && guard < 5000; guard++) {
            const n = 1 + Math.floor(Math.random() * Math.max(1, top));
            if (untried(n) && !pool.includes(n)) pool.push(n);
          }
          let hits = 0;
          let measured = 0;
          for (const n of pool) {
            const h = await testInt(n);
            if (h === undefined) break;
            measured++;
            if (h) hits++;
          }
          density = measured >= 5 ? hits / measured : hitInts().length / Math.max(1, [...tried.keys()].filter((id) => /^\d+$/.test(id) && Number(id) <= top).length);
        }
        const estimate = exact ? hitInts().filter((n) => n <= top).length : Math.round(top * density);
        result = { template, mode: "integers", requests: used, hits: hitInts().sort((a, b) => a - b).slice(0, 25).map(String), highest: top, density: Math.round(density * 100) / 100, estimate, exact, fields: sample ? fieldsOf(sample.body) : [], missing: { status: missing[0]!.status, size: missing[0]!.size } };
        if (hi === undefined && top > 0) log.push(`# records still answering at the last id tried: the highest is a lower bound`);
      }
      const rawId = this.engagement.putRaw(log.join("\n"), { type: "stdout", mime: "text/plain", runId: run.id });
      const sampleRawId = sample ? this.engagement.putRaw(sample.body, { type: "stdout", mime: "application/json", runId: run.id }) : undefined;
      const items: unknown[] = [];
      if (result.estimate > 0) {
        // The endpoint must exist before an observation can point at it.
        items.push({ op: "upsert", kind: "endpoint", key: { origin: base.origin, path: template }, attributes: { statusesSeen: [200] }, confidence: 0.9 });
        items.push({
          op: "observe",
          title: `${result.exact ? "" : "~"}${result.estimate} record(s) reachable at ${template}`,
          sourceRule: "enum:measured",
          affects: [{ kind: "endpoint", key: { origin: base.origin, path: template } }],
          severityHint: "info",
          detail: `${result.mode === "integers" ? `Highest id ${result.highest}, density ${result.density}` : `${result.hits.length} of ${input.values!.length} values`}; ${result.requests} GET${headerLine ? " with the given header" : " without credentials"}. A missing record answers ${result.missing.status} (${result.missing.size} bytes).`,
          rawId,
        });
      }
      const ingested = items.length ? this.engagement.ingest({ format: INGEST_FORMAT, source: { parser: "enumeration@0.1.0", tool: "enumeration" }, rawIds: [rawId], observedAt: new Date().toISOString(), items } as never, caller.actor) : undefined;
      const done = this.engagement.finishRun(run.id, { status: "finished", rawIds: [rawId, ...(sampleRawId ? [sampleRawId] : [])], summary: { estimate: result.estimate, exact: result.exact, highest: result.highest ?? null, requests: result.requests, ...(ingested ? { ingested } : {}) } });
      this.engagement.noteReachability(base.hostname, true);
      return { status: "enumeration", run: done, result, rawId, ...(sampleRawId ? { sampleRawId } : {}) };
    } catch (e) {
      this.engagement.noteReachability(base.hostname, false, (e as Error).message);
      const done = this.engagement.finishRun(run.id, { status: "failed", summary: { error: (e as Error).message, requests: used } });
      return { status: "enumeration", run: done, error: (e as Error).message };
    }
  }

  /**
   * The exact version of the technologies on a web app, from reliable sources rather than a guess:
   * response headers (Server, X-Powered-By, X-Generator), the generator meta, WordPress plugin and
   * theme files (readme.txt "Stable tag", style.css "Version"), and version comments in the scripts.
   * Read-only GETs; the versions found become technology entities for vuln_lookup.
   */
  async detectVersions(input: { origin: string; slugs?: string[]; risk: RiskLevel }, caller: ToolCaller, approvedBy?: Actor): Promise<RunOutcome> {
    const fail = (error: string) => ({ status: "versions" as const, run: this.engagement.startRun({ actor: caller.actor, origin: caller.origin, tool: "versions", command: `detect versions ${input.origin}`, targets: [], risk: input.risk, policy: { result: "denied", reason: error }, runner: "local" }), error });
    let base: URL;
    try {
      base = new URL(input.origin);
    } catch {
      return fail(`not an origin: ${input.origin}`);
    }
    const decision = this.check([base.href], input.risk, approvedBy ? { type: "human" } : caller.policy);
    if (decision.decision === "deny") return this.deny(caller, "versions", [base.href], [base.href], input.risk, decision);
    if (decision.decision === "ask") {
      const grant = this.grantFor(caller, "versions", [base.origin], input.risk);
      if (grant) return this.detectVersions(input, { ...caller, policy: { type: "human" } }, grant.by);
      return this.requestApproval(caller, decision, `detect versions on ${base.origin}`, { kind: "http", origin: base.origin, raw: `GET / HTTP/1.1\r\nHost: ${base.host}\r\n\r\n[+ version files]`, risk: input.risk, probe: { tool: "versions", input } });
    }
    const run = this.engagement.startRun({ actor: caller.actor, origin: caller.origin, tool: "versions", command: `detect versions ${base.origin}`, targets: [base.href], risk: input.risk, policy: { result: approvedBy ? "approved" : "allowed", ...(decision.ruleId ? { ruleId: decision.ruleId } : {}) }, runner: "local", attack: ["T1592.002"] });

    const found = new Map<string, { product: string; version: string; source: string; confidence: number; ecosystem?: string }>();
    let distro: string | undefined;
    const add = (product: string | undefined, version: string | undefined, source: string, confidence: number, ecosystem?: string) => {
      if (!product || !version || !/\d/.test(version)) return;
      const key = `${product.toLowerCase()}|${ecosystem ?? ""}`;
      const prev = found.get(key);
      if (!prev || confidence > prev.confidence) found.set(key, { product: product.trim(), version: version.trim(), source, confidence, ...(ecosystem ? { ecosystem } : {}) });
    };
    const get = async (path: string) => {
      try {
        const u = new URL(path, base.origin);
        const r = await sendHttp(u, { method: "GET", path: u.pathname + u.search, headers: [["Host", u.host], ["Accept", "*/*"]], body: "" });
        return r;
      } catch {
        return undefined;
      }
    };
    const log: string[] = [`# version detection ${base.origin}`];
    try {
      const home = await get("/");
      if (home) {
        for (const [h, v] of home.headers) {
          const hl = h.toLowerCase();
          if (hl === "server") {
            for (const m of v.matchAll(/([A-Za-z][\w.+-]*?)\/(\d[\w.]*)/g)) add(m[1], m[2], "Server header", 0.85);
            // The distro in the Server banner ("nginx/1.18.0 (Ubuntu)") enables backport-aware CVE matching.
            const d = /\((ubuntu|debian|red ?hat|centos|rocky|alma|fedora|alpine|amazon|suse|oracle)\b[^)]*\)/i.exec(v);
            if (d) distro = d[1]!.toLowerCase().replace(/\s+/g, "");
          }
          else if (hl === "x-powered-by") { const php = /php\/(\d[\w.]*)/i.exec(v); if (php) add("PHP", php[1], "X-Powered-By", 0.85); const asp = /asp\.net|aspnet/i.test(v); if (asp) add("ASP.NET", v.replace(/[^\d.]/g, "") || "?", "X-Powered-By", 0.6); }
          else if (hl === "x-generator") { const m = /([A-Za-z][\w .-]*?)[\s/]+v?(\d[\w.]*)/.exec(v); if (m) add(m[1], m[2], "X-Generator", 0.85); }
          else if (hl === "x-aspnet-version") add("ASP.NET", v, "X-AspNet-Version", 0.85);
          else if (hl === "x-drupal-cache" || /drupal/i.test(v)) add("Drupal", "?", "header", 0.3);
        }
        const body = home.body.slice(0, 400_000);
        for (const m of body.matchAll(/<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)["']/gi)) {
          const g = m[1]!.trim();
          const mm = /^([A-Za-z][\w .-]*?)[\s/]+v?(\d[\w.]*)/.exec(g);
          if (mm) add(mm[1], mm[2], "generator meta", 0.92, /wordpress/i.test(mm[1]!) ? "WordPress" : undefined);
        }
        for (const [re, name] of [[/jQuery\s+v?(\d[\w.]*)/i, "jquery"], [/jquery[.-](\d+\.\d[\w.]*)\.(?:min\.)?js/i, "jquery"], [/react(?:-dom)?["'@\s/-]+v?(\d+\.\d[\w.]*)/i, "react"], [/Vue\.js\s+v(\d[\w.]*)/i, "vue"], [/bootstrap[^\d]{0,12}(\d+\.\d[\w.]*)/i, "bootstrap"], [/angular[^\d]{0,12}(\d+\.\d[\w.]*)/i, "angular"]] as const) {
          const m = re.exec(body);
          if (m) add(name, m[1], "inline script", 0.65, "npm");
        }
        // WordPress plugin/theme slugs referenced in the page → read their real version.
        const slugs = new Set<string>(input.slugs ?? []);
        for (const m of body.matchAll(/\/wp-content\/plugins\/([a-z0-9][a-z0-9-]*)\//gi)) slugs.add(m[1]!.toLowerCase());
        for (const m of body.matchAll(/\/wp-content\/themes\/([a-z0-9][a-z0-9-]*)\//gi)) slugs.add(`theme:${m[1]!.toLowerCase()}`);
        for (const slug of [...slugs].slice(0, 15)) {
          const theme = slug.startsWith("theme:");
          const name = theme ? slug.slice(6) : slug;
          const r = await get(theme ? `/wp-content/themes/${name}/style.css` : `/wp-content/plugins/${name}/readme.txt`);
          if (r && r.status === 200) {
            const m = theme ? /^[\s*]*Version:\s*(\d[\w.]*)/im.exec(r.body) : /Stable tag:\s*(\d[\w.]*)/i.exec(r.body);
            if (m) add(name, m[1], theme ? "style.css" : "readme.txt", 0.95, "WordPress");
            log.push(`${theme ? "style.css" : "readme.txt"} ${name}: ${m ? m[1] : "no version line"}`);
          }
        }
      }
      // Exposed dependency manifests: exact versions of the stack.
      for (const path of ["/composer.json", "/package.json"]) {
        const r = await get(path);
        if (r && r.status === 200 && /json/.test(r.headers.find(([h]) => h.toLowerCase() === "content-type")?.[1] ?? "")) {
          try {
            const j = JSON.parse(r.body.slice(0, 300_000)) as Record<string, Record<string, string>>;
            const eco = path.includes("composer") ? "Packagist" : "npm";
            const deps = { ...(j.require ?? {}), ...(j.dependencies ?? {}) };
            for (const [dep, range] of Object.entries(deps).slice(0, 25)) {
              const ver = /(\d+\.\d[\w.]*)/.exec(String(range))?.[1];
              if (ver && !/^(php|ext-|node|npm)$/i.test(dep)) add(dep, ver, path.slice(1), 0.9, eco);
            }
          } catch {
            /* not usable JSON */
          }
        }
      }
      const items = [...found.values()].map((f) => ({ op: "upsert", kind: "technology", key: { where: base.origin, product: f.product, version: f.version }, attributes: { where: base.origin, product: f.product, version: f.version, ...(f.ecosystem ? { ecosystem: f.ecosystem } : {}), ...(distro ? { distro } : {}), source: f.source, confidence: f.confidence }, confidence: f.confidence }));
      const rawId = this.engagement.putRaw([...log, "", ...[...found.values()].map((f) => `${f.product} ${f.version} (${f.source}, ${Math.round(f.confidence * 100)}%)`)].join("\n"), { type: "stdout", mime: "text/plain", runId: run.id });
      const ingested = items.length ? this.engagement.ingest({ format: INGEST_FORMAT, source: { parser: "versions@0.1.0", tool: "versions" }, rawIds: [rawId], observedAt: new Date().toISOString(), items } as never, caller.actor) : undefined;
      const done = this.engagement.finishRun(run.id, { status: "finished", rawIds: [rawId], summary: { found: found.size, ...(ingested ? { ingested } : {}) } });
      this.engagement.noteReachability(base.hostname, true);
      return { status: "versions", run: done, found: [...found.values()], rawId };
    } catch (e) {
      this.engagement.noteReachability(base.hostname, false, (e as Error).message);
      const done = this.engagement.finishRun(run.id, { status: "failed", summary: { error: (e as Error).message } });
      return { status: "versions", run: done, error: (e as Error).message };
    }
  }

  // -------------------------------------------------------------------------------------------
  // WebSocket repeater
  // -------------------------------------------------------------------------------------------

  async openWs(input: { url: string; headers: Array<[string, string]>; risk: RiskLevel }, caller: ToolCaller, approvedBy?: Actor): Promise<RunOutcome> {
    const url = new URL(input.url);
    if (!/^wss?:$/.test(url.protocol)) throw new Error("the URL must start with ws:// or wss://");
    const httpUrl = new URL(url.href.replace(/^ws/, "http"));
    const label = `WebSocket ${url.href}`;
    const deny = (code: string, reason: string) => this.deny(caller, "websocket", [url.href], [httpUrl.href], input.risk, { decision: "deny", code, reason } as never);
    const gated = this.phaseGate(caller, input.risk, approvedBy);
    if (gated) return this.deny(caller, "websocket", [url.href], [httpUrl.href], input.risk, gated);
    const resolved = this.engagement.resolveSecrets(input.headers.map(([k, v]) => `${k}: ${v}`));
    if (resolved.missing.length) return deny("UNKNOWN_SECRET", `Unknown secret(s): ${resolved.missing.join(", ")}`);
    const decision = this.check([httpUrl.href], input.risk, approvedBy ? { type: "human" } : caller.policy);
    if (decision.decision === "deny") return this.deny(caller, "websocket", [url.href], [httpUrl.href], input.risk, decision);
    if (decision.decision === "ask") {
      const grant = this.grantFor(caller, "ws", [httpUrl.origin], input.risk);
      if (grant) return this.openWs(input, { ...caller, policy: { type: "human" } }, grant.by);
      return this.requestApproval(caller, decision, label, { kind: "ws", ...input });
    }

    const run = this.engagement.startRun({
      actor: caller.actor,
      origin: caller.origin,
      tool: "websocket",
      command: label,
      targets: [httpUrl.href],
      risk: input.risk,
      policy: { result: approvedBy ? "approved" : "allowed", ...(decision.ruleId ? { ruleId: decision.ruleId } : {}) },
      runner: "local",
      attack: ["T1595"],
    });
    const headers = Object.fromEntries(
      resolved.argv.map((l) => [l.slice(0, l.indexOf(":")).trim(), l.slice(l.indexOf(":") + 1).trim()]).filter(([k]) => k && !/^(host|upgrade|connection|sec-websocket-(key|version|extensions))$/i.test(k)),
    );
    const started = Date.now();
    return new Promise<RunOutcome>((resolve) => {
      // No compression: what is recorded is exactly what travelled.
      const ws = new WebSocket(url.href, { headers, rejectUnauthorized: false, perMessageDeflate: false, handshakeTimeout: 15_000 });
      const sessionId = ulid();
      const entryId = ulid();
      let upgraded: { status: number; headers: Array<[string, string]> } | undefined;
      const record = (status: number | undefined, error?: string) => {
        const lines = [`GET ${url.pathname}${url.search} HTTP/1.1`, `Host: ${url.host}`, ...input.headers.map(([k, v]) => `${k}: ${v}`)].join("\r\n");
        const rawId = this.engagement.putRaw(`${lines}\r\n\r\n${status ? `HTTP/1.1 ${status}\r\n${(upgraded?.headers ?? []).map(([k, v]) => `${k}: ${v}`).join("\r\n")}` : `[no response: ${error}]`}`, { type: "http_exchange", mime: "message/http", runId: run.id });
        this.engagement.addProxyEntry({
          id: entryId,
          at: new Date(started).toISOString(),
          source: "repeater",
          method: "GET",
          url: httpUrl.href,
          host: url.host,
          path: `${url.pathname}${url.search}`,
          ...(status ? { status } : {}),
          reqSize: 0,
          resSize: 0,
          durationMs: Date.now() - started,
          inScope: true,
          blocked: false,
          reason: "WebSocket",
          rawId,
          ...(error ? { error } : {}),
          static: false,
          edited: false,
        });
      };
      ws.on("upgrade", (res) => {
        upgraded = { status: res.statusCode ?? 101, headers: Object.entries(res.headers).flatMap(([k, v]) => (Array.isArray(v) ? v.map((x) => [k, x] as [string, string]) : v === undefined ? [] : [[k, String(v)] as [string, string]])) };
      });
      ws.on("unexpected-response", (_req, res) => {
        record(res.statusCode, `the server answered ${res.statusCode} instead of accepting the WebSocket`);
        this.engagement.finishRun(run.id, { status: "failed", summary: { websocket: { status: res.statusCode } } });
        ws.terminate();
        resolve({ status: "ws", entryId, httpStatus: res.statusCode, error: `the server answered ${res.statusCode} instead of accepting the WebSocket` });
      });
      ws.on("open", () => {
        record(upgraded?.status ?? 101);
        this.wsSessions.set(sessionId, { ws, entryId, url: url.href, openedAt: new Date().toISOString(), by: caller.actor });
        this.engagement.finishRun(run.id, { status: "finished", summary: { websocket: { status: 101, sessionId, entryId } } });
        resolve({ status: "ws", sessionId, entryId, httpStatus: 101 });
      });
      // Recording must never throw out of a socket event (the project may be closing).
      const safe = (f: () => void) => {
        try {
          f();
        } catch {
          /* engagement closed */
        }
      };
      ws.on("message", (data: Buffer | ArrayBuffer | Buffer[], isBinary: boolean) => {
        const payload = Array.isArray(data) ? Buffer.concat(data) : Buffer.from(data as Buffer);
        safe(() => this.engagement.addWsMessage({ entryId, direction: "in", opcode: isBinary ? 2 : 1, payload }));
      });
      ws.on("close", (code: number, reason: Buffer) => {
        if (this.wsSessions.delete(sessionId)) safe(() => this.engagement.addWsMessage({ entryId, direction: "in", opcode: 8, payload: Buffer.from(`[close ${code}] ${reason.toString("utf8")}`.trim()) }));
      });
      ws.on("error", (e: Error) => {
        if (this.wsSessions.has(sessionId)) return;
        if (!upgraded) {
          record(undefined, e.message);
          this.engagement.finishRun(run.id, { status: "failed", summary: { error: e.message } });
          resolve({ status: "ws", entryId, error: e.message });
        }
      });
    });
  }

  /** Sends a message on an open WebSocket session; {{secret:name}} is substituted. */
  sendWs(sessionId: string, message: { text?: string; base64?: string }): void {
    const s = this.wsSessions.get(sessionId);
    if (!s || s.ws.readyState !== WebSocket.OPEN) throw new Error("that WebSocket connection is no longer open");
    if (message.base64 !== undefined) {
      const payload = Buffer.from(message.base64, "base64");
      s.ws.send(payload, { binary: true });
      this.engagement.addWsMessage({ entryId: s.entryId, direction: "out", opcode: 2, payload });
      return;
    }
    const text = message.text ?? "";
    const missing = this.engagement.resolveSecrets([text]);
    if (missing.missing.length) throw new Error(`Unknown secret(s): ${missing.missing.join(", ")}`);
    s.ws.send(missing.argv[0]!);
    // Recorded with the reference, not the value.
    this.engagement.addWsMessage({ entryId: s.entryId, direction: "out", opcode: 1, payload: Buffer.from(text, "utf8") });
  }

  closeWs(sessionId: string): boolean {
    const s = this.wsSessions.get(sessionId);
    if (!s) return false;
    s.ws.close(1000, "closed from Penteos");
    return true;
  }

  /** Closes every WebSocket opened from Penteos, without recording (shutdown). */
  closeAllWs(): void {
    for (const [id, s] of this.wsSessions) {
      this.wsSessions.delete(id);
      s.ws.terminate();
    }
  }

  wsList(): Array<{ sessionId: string; entryId: string; url: string; openedAt: string; open: boolean }> {
    return [...this.wsSessions.entries()].map(([sessionId, s]) => ({ sessionId, entryId: s.entryId, url: s.url, openedAt: s.openedAt, open: s.ws.readyState === WebSocket.OPEN }));
  }

  // -------------------------------------------------------------------------------------------
  // Fuzzer (Intruder-style)
  // -------------------------------------------------------------------------------------------

  /** Validates the attack and starts it in the background; results arrive as they are sent. */
  runFuzz(input: FuzzInput, caller: ToolCaller, approvedBy?: Actor): RunOutcome {
    const { parts, defaults } = parseTemplate(input.template);
    if (defaults.length === 0) throw new Error("mark at least one position with § (for example id=§1§)");
    const needed = input.attack === "sniper" || input.attack === "battering_ram" ? 1 : defaults.length;
    if (input.sets.length < needed) throw new Error(`this attack needs ${needed} payload list${needed === 1 ? "" : "s"} (one per position)`);
    const sets = input.sets.slice(0, needed).map((src, i) => payloadsOf(src).map((p) => processPayload(p, input.processing?.[i])));
    const total = countCombinations(input.attack, defaults.length, sets);
    if (total === 0) throw new Error("the payload lists are empty");
    if (total > input.maxRequests) throw new Error(`the attack would send ${total} requests and the maximum is ${input.maxRequests}: shorten the lists or raise the maximum`);

    const base = parseRawRequest(render(parts, defaults));
    const baseUrl = requestUrl(input.origin, base);
    const label = `fuzz ${input.attack} ${base.method} ${baseUrl.href} · ${total} pedidos`;
    const deny = (code: string, reason: string) => this.deny(caller, "fuzz", [base.method, baseUrl.href], [baseUrl.href], input.risk, { decision: "deny", code, reason } as never);
    const gated = this.phaseGate(caller, input.risk, approvedBy);
    if (gated) return this.deny(caller, "fuzz", [base.method, baseUrl.href], [baseUrl.href], input.risk, gated);
    const missing = this.engagement.resolveSecrets([input.template]).missing;
    if (missing.length) return deny("UNKNOWN_SECRET", `Unknown secret(s): ${missing.join(", ")}`);
    const decision = this.check([baseUrl.href], input.risk, approvedBy ? { type: "human" } : caller.policy);
    if (decision.decision === "deny") return this.deny(caller, "fuzz", [base.method, baseUrl.href], [baseUrl.href], input.risk, decision);
    if (decision.decision === "ask") {
      const grant = this.grantFor(caller, "fuzz", [baseUrl.origin], input.risk);
      if (grant) return this.runFuzz(input, { ...caller, policy: { type: "human" } }, grant.by);
      return this.requestApproval(caller, decision, label, { kind: "fuzz", input });
    }
    const busy = this.hostBusy(caller, [baseUrl.href]);
    if (busy) return this.deny(caller, "fuzz", [base.method, baseUrl.href], [baseUrl.href], input.risk, busy);

    const run = this.engagement.startRun({
      actor: caller.actor,
      origin: caller.origin,
      tool: "fuzz",
      command: label,
      targets: [baseUrl.href],
      risk: input.risk,
      policy: { result: approvedBy ? "approved" : "allowed", ...(decision.ruleId ? { ruleId: decision.ruleId } : {}) },
      runner: "local",
      attack: ["T1595.003"],
    });
    const job = { cancelled: false };
    this.fuzzJobs.set(run.id, job);
    void this.fuzzLoop(run, input, parts, defaults, sets, total, job).finally(() => this.fuzzJobs.delete(run.id));
    return { status: "started", run };
  }

  private async fuzzLoop(run: Run, input: FuzzInput, parts: string[], defaults: string[], sets: string[][], total: number, job: { cancelled: boolean }): Promise<void> {
    const KEEP_ALL_RAW = 20_000;
    const grep = (input.grep ?? []).filter(Boolean).map((g) => {
      const m = /^\/(.+)\/([a-z]*)$/.exec(g);
      try {
        return { name: g, test: m ? ((re: RegExp) => (t: string) => re.test(t))(new RegExp(m[1]!, m[2]!.replace("g", ""))) : (t: string) => t.toLowerCase().includes(g.toLowerCase()) };
      } catch {
        return { name: g, test: (t: string) => t.includes(g) };
      }
    });
    let extract: RegExp | undefined;
    try {
      extract = input.extract ? new RegExp(input.extract) : undefined;
    } catch {
      extract = undefined;
    }
    const baseOrigin = requestUrl(input.origin, parseRawRequest(render(parts, defaults))).origin;
    const times: number[] = [];
    let baseline: FuzzResult | undefined;
    let done = 0;
    let anomalies = 0;
    let lastEmit = 0;
    let limited = false;
    const pending: FuzzResult[] = [];
    const flush = () => {
      if (pending.length) this.engagement.addFuzzResults(run.id, pending.splice(0));
    };
    const progress = (force = false) => {
      const now = Date.now();
      if (!force && now - lastEmit < 300) return;
      lastEmit = now;
      flush();
      this.engagement.emit({ type: "fuzz.progress", runId: run.id, done, total: total + 1, anomalies });
    };

    const one = async (index: number, values: string[], payloadList: string[], position?: number): Promise<FuzzResult> => {
      const started = Date.now();
      const base: FuzzResult = { index, payloads: payloadList, ...(position !== undefined ? { position } : {}), length: 0, words: 0, lines: 0, timeMs: 0, matches: [], anomalies: [] };
      try {
        const text = this.engagement.resolveSecrets([render(parts, values)]).argv[0]!;
        const req = parseRawRequest(text);
        // Compressed responses could not be measured or searched: ask for plain ones.
        req.headers = req.headers.filter(([k]) => k.toLowerCase() !== "accept-encoding");
        const url = requestUrl(input.origin, req);
        if (url.origin !== baseOrigin && this.engagement.checkScope(url.href, input.risk, { type: "human" }).decision === "deny") {
          return { ...base, error: "out of scope: not sent", anomalies: ["error"] };
        }
        const res = await sendHttp(url, req, 30_000);
        if ((res.status === 429 || res.status === 423) && !limited) {
          limited = true;
          this.noteDefence(url.origin, url.pathname, `a fuzz of ${req.method} ${url.pathname} was answered ${res.status} at request ${index + 1}`, run.actor);
        }
        const m = measure(res.body);
        const matches = grep.filter((g) => g.test(res.body)).map((g) => g.name);
        const captured = extract ? extract.exec(res.body) : null;
        return { ...base, status: res.status, ...m, timeMs: res.timeMs, matches, ...(captured ? { extracted: (captured[1] ?? captured[0]).slice(0, 300) } : {}), rawId: `${formatRequest(req, url)}\r\n\r\n${formatResponse(res)}` };
      } catch (e) {
        return { ...base, timeMs: Date.now() - started, error: (e as Error).message.slice(0, 200) };
      }
    };
    const finalize = (r: FuzzResult): FuzzResult => {
      const sorted = [...times].sort((a, b) => a - b);
      const median = sorted.length ? sorted[Math.floor(sorted.length / 2)]! : 0;
      // Errors, grep matches and slowness are anomalies on their own; being different from the
      // rest is judged when the results are read (it depends on the whole attack).
      const anomalyList = r.index === 0 ? [] : anomaliesOf(r, undefined, median);
      const exchange = r.rawId;
      const keep = exchange && (r.index < KEEP_ALL_RAW || anomalyList.length > 0);
      const rawId = keep ? this.engagement.putRaw(exchange, { type: "http_exchange", mime: "message/http", runId: run.id }) : undefined;
      const { rawId: _drop, ...rest } = r;
      return { ...rest, anomalies: anomalyList, ...(rawId ? { rawId } : {}) };
    };

    try {
      // The baseline first: the request as written, with the original values.
      const b = finalize(await one(0, defaults, ["(original)"]));
      baseline = b;
      times.push(b.timeMs);
      pending.push(b);
      done = 1;
      progress(true);

      const iterator = combinations(input.attack, defaults, sets);
      let index = 0;
      const next = (): { index: number; c: ReturnType<typeof iterator.next>["value"] } | undefined => {
        const n = iterator.next();
        if (n.done) return undefined;
        index++;
        return { index, c: n.value };
      };
      const worker = async () => {
        while (!job.cancelled && !this.engagement.info.stopWork?.active) {
          const item = next();
          if (!item || !item.c) return;
          const r = finalize(await one(item.index, item.c.values, item.c.payloads, item.c.position));
          times.push(r.timeMs);
          if (times.length > 400) times.splice(0, times.length - 400);
          if (r.anomalies.length) anomalies++;
          pending.push(r);
          done++;
          progress();
          if (input.delayMs > 0) await new Promise((res) => setTimeout(res, input.delayMs));
        }
      };
      await Promise.all(Array.from({ length: Math.max(1, Math.min(input.concurrency, 20)) }, worker));
    } finally {
      flush();
      progress(true);
      const stopped = job.cancelled || Boolean(this.engagement.info.stopWork?.active);
      this.engagement.finishRun(run.id, {
        status: stopped ? "cancelled" : "finished",
        summary: { fuzz: { total: total + 1, sent: done, anomalies, baseline: baseline ? { status: baseline.status, length: baseline.length } : null } },
      });
    }
  }

  // -------------------------------------------------------------------------------------------
  // Any installed tool (level 3)
  // -------------------------------------------------------------------------------------------

  async runExec(input: { argv: string[]; targets: string[]; risk: RiskLevel }, caller: ToolCaller, approvedBy?: Actor): Promise<RunOutcome> {
    const [tool, ...rawArgs0] = input.argv;
    if (!tool) throw new Error("empty command");

    // A tool Penteos knows (built-in or added manifest): its own target rules, risk floor,
    // verified binary and output mapping apply.
    const manifest = this.registry.forBinary(tool);
    if (manifest?.name === "nmap") return this.runNmap(rawArgs0, caller, approvedBy);
    let rawArgs = rawArgs0;
    if (manifest) {
      // A name tool (dnsx, subfinder, dig) given a URL gets its host, before anything is checked:
      // the scope decision below is about what the command will really reach.
      rawArgs = argsForTool(manifest, rawArgs0);
      input = { ...input, argv: [tool, ...rawArgs], targets: input.targets.map((t) => targetForTool(manifest, t)) };
    }
    let args = rawArgs;
    let binary = tool;
    if (manifest) {
      const found = manifestTargets(manifest, rawArgs);
      if (found.unchecked && !approvedBy && caller.policy.type === "agent") {
        const ask = { decision: "ask" as const, ruleId: "", reason: `Targets cannot be verified: ${found.unchecked}`, warnings: [], why: { code: "unverifiable" as const, targets: String(found.unchecked) } };
        return this.requestApproval(caller, ask, input.argv.join(" "), { kind: "exec", ...input });
      }
      input = {
        argv: input.argv,
        targets: [...new Set([...input.targets, ...found.targets])],
        risk: riskExceeds(manifest.risk, input.risk) ? manifest.risk : input.risk,
      };
      // An agent sweeping every template against names that only resolve to a CDN measures the CDN's
      // WAF and rate limit: hours of 429s and a "WAF detected". Same rule as nmap on a CDN.
      if (manifest?.name === "nuclei" && caller.actor.type === "agent" && !approvedBy && !rawArgs.some((a) => NUCLEI_SELECTORS.has(a.split("=")[0]!))) {
        const hosts = [...new Set(input.targets.map((t) => { try { return /^[a-z]+:\/\//i.test(t) ? new URL(t).hostname : t; } catch { return t; } }))];
        const cdn = this.cdnTargets(hosts);
        if (cdn.length && cdn.length === hosts.length) {
          return this.deny(caller, tool, rawArgs, input.targets, input.risk, {
            decision: "deny",
            code: "CDN_TARGET",
            reason:
              `${cdn.map((c) => `${c.target} (${c.provider})`).join(", ")} only resolve to CDN edge addresses: a sweep of every nuclei template there mostly measures ${cdn[0]!.provider}'s WAF and rate limit (429s for hours). ` +
              "Choose what to check: specific templates (-t, -id), tags for the stack you identified (-tags nextjs,cloudflare…), or -s critical,high, at -rl 5 or less; for one known CVE use vuln_confirm. Tell the operator if a full sweep is really wanted.",
          } as never);
        }
      }
      const status = await this.registry.binaryFor(manifest);
      if (!status.installed) {
        const how = installCommand(manifest);
        const catalog = status.catalog;
        return this.deny(caller, tool, rawArgs, input.targets, input.risk, {
          decision: "deny",
          code: "TOOL_NOT_INSTALLED",
          reason: catalog
            ? `${manifest.name} is not installed${status.mismatch ? ` (${status.mismatch})` : ""}. Penteos can install it without root from its verified catalog (${manifest.name} ${catalog.version}, ${mb(catalog.size)}): propose it with tool_propose_install and keep working on something else meanwhile; do not retry this command until it is installed.`
            : `${manifest.name} is not installed${status.mismatch ? ` (${status.mismatch})` : ""}.${how ? ` Install: ${how}` : ""}`,
        } as never);
      }
      if (status.managed) this.registry.toolbox?.markUsed(manifest.name);
      binary = status.binary ?? tool;
      args = withOutputArgs(manifest, withDefaults(manifest, rawArgs));
    }
    const args0 = rawArgs;
    const gated = this.phaseGate(caller, input.risk, approvedBy);
    if (gated) return this.deny(caller, tool, args0, input.targets, input.risk, gated);
    const { missing } = this.engagement.resolveSecrets(input.argv);
    if (missing.length) {
      return this.deny(caller, tool, args0, input.targets, input.risk, {
        decision: "deny",
        code: "UNKNOWN_SECRET",
        reason: `Unknown secret(s): ${missing.join(", ")}. Save them first with secret_save, or check secret_list.`,
      } as never);
    }
    const undeclared = undeclaredTargets(findTargetTokens(args0), input.targets);
    if (undeclared.length > 0) {
      return this.deny(caller, tool, args0, input.targets, input.risk, {
        decision: "deny",
        code: "UNDECLARED_TARGETS",
        reason: `The command contains targets that were not declared: ${undeclared.join(", ")}`,
      } as never);
    }
    // No targets from an agent: local analysis. With an offline sandbox it runs at once with no
    // network (it cannot touch anything); without one, a human confirms it touches nothing.
    const sandbox = input.targets.length === 0 && caller.policy.type === "agent" && !approvedBy ? offlineSandbox() : undefined;
    if (input.targets.length === 0 && caller.policy.type === "agent" && !approvedBy && !sandbox) {
      const ask = { decision: "ask" as const, ruleId: "", reason: "No targets declared: a human must confirm this command does not touch any target", warnings: [], why: { code: "no_targets" as const } };
      return this.requestApproval(caller, ask, input.argv.join(" "), { kind: "exec", ...input });
    }
    const decision = input.targets.length === 0
      ? ({ decision: "allow", ruleId: "", warnings: [] } as const)
      : this.check(input.targets, input.risk, approvedBy ? { type: "human" } : caller.policy);
    if (decision.decision === "deny") return this.deny(caller, tool, args0, input.targets, input.risk, decision);
    if (decision.decision === "ask") {
      const grant = this.grantFor(caller, manifest?.name ?? tool, input.targets, input.risk);
      if (grant) return this.runExec(input, caller, grant.by);
      return this.requestApproval(caller, decision, input.argv.join(" "), { kind: "exec", ...input });
    }
    const busy = this.hostBusy(caller, input.targets);
    if (busy) return this.deny(caller, tool, args0, input.targets, input.risk, busy);

    const run = this.engagement.startRun({
      actor: caller.actor,
      origin: caller.origin,
      tool: manifest?.name ?? tool,
      command: [tool, ...args].join(" "),
      ...(manifest?.attack.length ? { attack: manifest.attack } : {}),
      targets: input.targets,
      risk: input.risk,
      policy: { result: approvedBy ? "approved" : "allowed", ...(decision.ruleId ? { ruleId: decision.ruleId } : {}), ...(sandbox ? { reason: "offline sandbox: no network" } : {}) },
      runner: "local",
    });
    const mapping = manifest?.output ? manifest : undefined;
    // A DNS brute force over a zone with a wildcard would record every word of the list as a host.
    const wild = manifest?.name === "dnsx" && !sandbox ? await detectWildcards(input.targets.filter((t) => /[a-z]/i.test(t) && !t.includes("/"))) : undefined;
    const launch = sandbox ? sandbox.wrap(binary, args, this.workDir()) : { command: binary, args };
    this.spawnTracked(run, launch.command, launch.args, (output, rawIds) => {
      if (!mapping || !output.trim()) return undefined;
      const { batch, skipped } = parseWithManifest(mapping, output, {
        rawIds,
        runId: run.id,
        vars: { ...(input.targets[0] ? { target: input.targets[0] } : {}), targets: input.targets },
      });
      const clean = wild?.size ? dropWildcardNames(batch, wild).batch : batch;
      if (clean.items.length === 0) return undefined;
      const summary = this.engagement.ingest(clean, caller.actor);
      return skipped ? { ...summary, skipped } : summary;
    });
    return { status: "started", run };
  }

  // -------------------------------------------------------------------------------------------
  // Installing tools and teaching Penteos new ones (always through a human)
  // -------------------------------------------------------------------------------------------

  proposeInstall(name: string, reason: string, by: Actor): Approval {
    // One proposal per tool: asking again hands back the one already waiting (no stacking, no loops).
    const pending = this.listApprovals().find((a) => (a.request.kind === "install" && a.request.tool === name) || (a.request.kind === "install_kit" && a.request.tools.includes(name)));
    if (pending) return pending;
    const box = this.registry.toolbox;
    const entry = box?.entry(name);
    const asset = box?.asset(name);
    if (entry && asset) {
      return this.addApproval(by, reason, `Install ${name} ${entry.version} (${mb(asset.size)}, verified, no root)`, { kind: "install", tool: name, command: `catalog:${name}@${entry.version}` });
    }
    const manifest = this.registry.get(name);
    if (!manifest) throw new Error(`tool not found: ${name}. Write a manifest first (tool_propose_manifest)`);
    const command = installCommand(manifest);
    if (!command) throw new Error(`${name} has no install recipe in its manifest`);
    return this.addApproval(by, reason, `Install ${name}: ${command}`, { kind: "install", tool: name, command });
  }

  /** Set by whoever runs plugins: installs an approved proposal (the runner knows nothing about plugins). */
  pluginInstall?: (proposal: PluginProposal, by: Actor, options?: { trust?: "free" | "isolated" }) => Promise<RunOutcome>;

  proposePlugin(proposal: PluginProposal, reason: string, by: Actor): Approval {
    // A newer proposal of the same plugin replaces the one still waiting.
    for (const a of this.listApprovals()) {
      if (a.request.kind === "plugin" && a.request.proposal.pluginId === proposal.pluginId) this.approvals.delete(a.id);
    }
    return this.addApproval(by, reason, `${proposal.update ? "Update" : "Install"} the plugin ${proposal.name} ${proposal.version}`, { kind: "plugin", proposal });
  }

  proposeManifest(input: unknown, reason: string, by: Actor): Approval {
    const manifest = validateManifest(input);
    const update = Boolean(this.registry.get(manifest.name));
    return this.addApproval(by, reason, `${update ? "Update" : "Integrate"} ${manifest.name}: ${manifest.description}`, { kind: "manifest", manifest, update });
  }

  /** Runs a recipe that installs without root (go install); the rest is shown to the operator. */
  install(name: string, by: Actor): RunOutcome {
    const box = this.registry.toolbox;
    if (box?.asset(name)) return this.installFromCatalog(name, by);
    const manifest = this.registry.get(name);
    if (!manifest?.install) throw new Error(`${name} has no install recipe`);
    // Homebrew (macOS) installs without root: the command runs as it is, seen as a run, when a
    // person started Penteos from the desktop (never from the test suite or a server).
    if (manifest.install.method === "system" && personAtDesktop() && detectPackageManager() === "brew" && manifest.install.packages.brew) {
      return this.installWithBrew(name, manifest.install.packages.brew, by);
    }
    if (manifest.install.method === "system" && process.platform === "darwin" && !detectPackageManager()) {
      throw new Error(`${name} installs with Homebrew on macOS, and Homebrew is not installed: install it from https://brew.sh, then ask again (no password is needed after that)`);
    }
    // The system's package, with the desktop's password window: one exact command, seen as a run.
    if (manifest.install.method === "system" && canAskPassword()) {
      const pm = detectPackageManager();
      const pkg = pm ? manifest.install.packages[pm] : undefined;
      const argv = pm && pkg ? systemInstallArgv(pm, pkg) : undefined;
      if (argv) return this.installWithSystem(name, argv, by);
    }
    if (manifest.install.method !== "go") {
      const command = installCommand(manifest);
      if (!command) throw new Error(`no install recipe for ${name} on this system; install it manually`);
      return { status: "manual_install", tool: name, command };
    }
    const run = this.engagement.startRun({
      actor: by,
      origin: "runner",
      tool: "go",
      command: `go install ${manifest.install.package}`,
      targets: [],
      risk: "passive",
      policy: { result: "approved" },
      runner: "local",
    });
    this.spawnTracked(run, "go", ["install", "-v", manifest.install.package], () => {
      this.registry.invalidate();
      return undefined;
    });
    return { status: "started", run };
  }

  // -------------------------------------------------------------------------------------------
  // Capabilities: the tool if it is there, Penteos's own way if
  // not, and a gap recorded by Penteos for whatever could not be done fully.
  // -------------------------------------------------------------------------------------------

  /** Penteos's own fallbacks that are running, to cancel them. */
  private readonly builtinJobs = new Map<string, AbortController>();

  async runCapability(input: { capability: CapabilityId; targets: string[]; options?: Record<string, unknown> }, caller: ToolCaller, approvedBy?: Actor): Promise<CapabilityRun> {
    const def = CAPABILITIES[input.capability];
    if (!def) throw new Error(`unknown capability: ${input.capability}`);
    const targets = [...new Set(input.targets.map((t) => t.trim()).filter(Boolean))];
    if (!targets.length) throw new Error("pass at least one target");

    // 1. A tool for it, installed (the system's or Penteos's own).
    const status = await this.registry.status();
    for (const tool of def.providers) {
      const st = status.find((s) => s.name === tool && s.installed);
      if (!st) continue;
      let outcome: RunOutcome;
      if (tool === "nmap") {
        const preset = typeof input.options?.preset === "string" ? input.options.preset : "quick";
        outcome = this.runNmap(this.nmapArgs({ preset, targets }), caller, approvedBy);
      } else {
        const manifest = this.registry.get(tool);
        if (!manifest?.invoke) continue;
        outcome = await this.runExec({ argv: [tool, ...manifestInvocation(manifest, targets)], targets, risk: manifest.risk }, caller, approvedBy);
      }
      return { capability: def.id, provider: tool, quality: "full", outcome };
    }

    // The tool that would do it fully, proposed once (one card per tool, whoever asks again).
    const install = this.proposeMissing(def.id, caller);
    const phase = getPlan(this.engagement).current;
    const record = (severity: "degraded" | "blocked") =>
      openGap(this.engagement, { capability: def.id, severity, tools: def.providers.length ? def.providers : [], ...(phase ? { phase } : {}), targets, requestedBy: caller.actor, policy: caller.policy, ...(input.options ? { options: input.options } : {}) }).gap;

    // 2. Penteos's own way.
    if (def.builtin) {
      const outcome = await this.runBuiltin(def.id, targets, caller, input.options, approvedBy);
      // A fallback as good as the tool leaves nothing pending; a lesser one leaves a gap to resume.
      const gap = def.builtin.quality === "degraded" && def.providers.length && (outcome.status === "started" || outcome.status === "pending_approval") ? record("degraded") : undefined;
      return { capability: def.id, provider: `penteos:${def.builtin.name}`, quality: def.builtin.quality, outcome, ...(gap ? { gap } : {}), ...(install ? { install } : {}) };
    }

    // 3. Nothing can do it: the gap, and the tool proposed.
    const gap = record("blocked");
    return { capability: def.id, provider: "none", quality: "blocked", outcome: { status: "gap", gap, ...(install ? { approval: install } : {}) }, gap, ...(install ? { install } : {}) };
  }

  /** Proposes installing the first provider the verified catalog has, unless one is waiting already. */
  private proposeMissing(capability: CapabilityId, caller: ToolCaller): Approval | undefined {
    const box = this.registry.toolbox;
    const tool = CAPABILITIES[capability].providers.find((t) => box?.asset(t));
    if (!tool) return undefined;
    // With the project's permission, no card: it installs now (and what it left resumes by itself).
    if (this.autoInstallAllows([tool])) {
      this.installFromCatalog(tool, { type: "system", id: "auto-install" });
      return undefined;
    }
    try {
      return this.proposeInstall(tool, `For «${CAPABILITIES[capability].title.en}»: today it is done with Penteos's own method or not at all.`, caller.actor);
    } catch {
      return undefined;
    }
  }

  autoInstall(): AutoInstall {
    return { ...AUTO_INSTALL_DEFAULT, ...(this.engagement.getMeta<Partial<AutoInstall>>("toolbox.autoInstall") ?? {}) };
  }

  /** Whether the project lets these tools install without asking: on, and within its size limit. */
  private autoInstallAllows(tools: string[]): boolean {
    const box = this.registry.toolbox;
    const policy = this.autoInstall();
    if (!box || !policy.enabled) return false;
    const already = box.installed().reduce((n, t) => n + t.bytes, 0);
    const adding = tools.reduce((n, t) => n + (box.asset(t)?.size ?? Infinity), 0);
    return (already + adding) / 1e6 <= policy.maxMB;
  }

  /**
   * When a phase starts: the catalog tools its usual work needs and this machine lacks, offered
   * together ONCE (or installed at once with the project's permission). Tools whose job Penteos's
   * own method does as well are left out: nothing to gain.
   */
  async proposePhaseKit(phase: string, by: Actor): Promise<{ tools: string[]; approval?: Approval; installed?: boolean }> {
    const box = this.registry.toolbox;
    if (!box) return { tools: [] };
    const status = await this.registry.status();
    const has = (t: string) => Boolean(status.find((s) => s.name === t)?.installed);
    const tools: string[] = [];
    for (const id of PHASE_CAPABILITIES[phase] ?? []) {
      const def = CAPABILITIES[id];
      if (def.providers.some(has) || def.builtin?.quality === "full") continue;
      const tool = def.providers.find((t) => box.asset(t));
      if (tool && !tools.includes(tool)) tools.push(tool);
    }
    // Already asked for on their own: not again.
    const waiting = new Set(this.listApprovals().flatMap((a) => (a.request.kind === "install" ? [a.request.tool] : a.request.kind === "install_kit" ? a.request.tools : [])));
    const wanted = tools.filter((t) => !waiting.has(t));
    if (!wanted.length) return { tools: [] };
    if (this.autoInstallAllows(wanted)) {
      for (const t of wanted) this.installFromCatalog(t, { type: "system", id: "auto-install" });
      return { tools: wanted, installed: true };
    }
    const size = wanted.reduce((n, t) => n + (box.asset(t)?.size ?? 0), 0);
    const title = getPlan(this.engagement).phases.find((p) => p.id === phase)?.title ?? phase;
    const approval = this.addApproval(by, `Tools usually needed in «${title}» that are not on this machine. Penteos keeps working in the meantime.`, `For «${title}», install: ${wanted.map((t) => `${t} ${box.entry(t)!.version}`).join(", ")} · ${mb(size)} (verified, no root)`, { kind: "install_kit", tools: wanted, phase });
    return { tools: wanted, approval };
  }

  /**
   * Penteos's own fallback for a capability, behind the same checks as any tool: phase, scope,
   * risk, approval, a host already busy. It runs in the core as a run the operator sees, writes the
   * output of the tool it stands in for, and that tool's mapping puts it in the graph.
   */
  async runBuiltin(capability: CapabilityId, targets: string[], caller: ToolCaller, options?: Record<string, unknown>, approvedBy?: Actor): Promise<RunOutcome> {
    const def = CAPABILITIES[capability];
    const b = def.builtin;
    if (!b) throw new Error(`${capability} has no fallback of its own`);
    const tool = `penteos-${b.name}`;
    const risk = def.risk;
    const gated = this.phaseGate(caller, risk, approvedBy);
    if (gated) return this.deny(caller, tool, targets, targets, risk, gated);
    const decision = this.check(targets, risk, approvedBy ? { type: "human" } : caller.policy);
    if (decision.decision === "deny") return this.deny(caller, tool, targets, targets, risk, decision);
    if (decision.decision === "ask") {
      const grant = this.grantFor(caller, tool, targets, risk);
      if (grant) return this.runBuiltin(capability, targets, caller, options, grant.by);
      return this.requestApproval(caller, decision, `${def.title.en} (Penteos's own method): ${targets.join(" ")}`, { kind: "capability", capability, targets, ...(options ? { options } : {}) });
    }
    const busy = this.hostBusy(caller, targets);
    if (busy) return this.deny(caller, tool, targets, targets, risk, busy);

    const run = this.engagement.startRun({
      actor: caller.actor,
      origin: caller.origin,
      tool,
      command: `${tool} ${targets.join(" ")}`,
      targets,
      risk,
      policy: { result: approvedBy ? "approved" : "allowed", ...(decision.ruleId ? { ruleId: decision.ruleId } : {}) },
      runner: "local",
    });
    const abort = new AbortController();
    this.builtinJobs.set(run.id, abort);
    this.live.set(run.id, "");
    const say = (line: string) => {
      const before = this.live.get(run.id) ?? "";
      const chunk = `${line}\n`;
      this.live.set(run.id, before + chunk);
      this.engagement.events.emit("change", { type: "run.output", id: run.id, chunk, offset: before.length });
    };
    const limits = { signal: abort.signal };
    const work: Promise<string> =
      b.name === "dns" ? builtinDns(targets, say, limits)
      : b.name === "ct" ? builtinSubdomains(targets, say, limits)
      : b.name === "http-probe" ? builtinHttpProbe(targets, say, limits)
      : b.name === "crawl" ? builtinCrawl(targets, say, limits)
      : b.name === "common-paths" ? builtinCommonPaths(targets, say, limits)
      : builtinPortScan(targets, say, limits);
    void work
      .then((output) => {
        const rawIds = output.trim() ? [this.engagement.putRaw(Buffer.from(output), { type: "stdout", mime: b.writes === "nmap" ? "application/xml" : "application/x-ndjson", runId: run.id })] : [];
        let summary: Record<string, unknown> = { capability, quality: b.quality };
        if (output.trim()) {
          try {
            const batch =
              b.writes === "nmap"
                ? parseNmapXml(output, { rawIds, runId: run.id })
                : parseWithManifest(this.registry.get(b.writes)!, output, { rawIds, runId: run.id, vars: { target: targets[0]!, targets } }).batch;
            summary = { ...summary, ingested: this.engagement.ingest(batch, caller.actor) };
          } catch (e) {
            summary = { ...summary, ingestError: (e as Error).message };
          }
        }
        this.finishBuiltin(run.id, this.cancelled.delete(run.id) ? "cancelled" : "finished", rawIds, summary);
      })
      .catch((e: Error) => {
        say(`error: ${e.message}`);
        this.finishBuiltin(run.id, this.cancelled.delete(run.id) ? "cancelled" : "failed", [], { capability, error: e.message });
      });
    return { status: "started", run };
  }

  private finishBuiltin(runId: string, status: Run["status"], rawIds: string[], summary: Record<string, unknown>): void {
    this.builtinJobs.delete(runId);
    const log = this.live.get(runId) ?? "";
    this.live.delete(runId);
    // The run's own log (what it said while working) is kept next to the tool-format output.
    const logId = log.trim() ? [this.engagement.putRaw(Buffer.from(log), { type: "stdout", mime: "text/plain", runId })] : [];
    this.engagement.finishRun(runId, { status, rawIds: [...logId, ...rawIds], summary });
  }

  /**
   * Takes up again the open gaps a tool can now fill (it was just installed, or appeared on the
   * system): each one runs its capability on its targets, as whoever asked for it, behind the same
   * checks. The requester hears about it ("gap.resumed").
   */
  async resumeGaps(only?: string): Promise<Array<{ gap: Gap; outcome: RunOutcome }>> {
    const status = await this.registry.status(true);
    const installed = new Set(status.filter((s) => s.installed).map((s) => s.name));
    const done: Array<{ gap: Gap; outcome: RunOutcome }> = [];
    for (const gap of listGaps(this.engagement)) {
      if (gap.status !== "open") continue;
      const tool = gap.tools.find((t) => installed.has(t) && (!only || t === only));
      if (!tool) continue;
      updateGap(this.engagement, gap.id, { status: "resolving" });
      const caller: ToolCaller = { actor: gap.requestedBy, policy: gap.policy, origin: "runner" };
      let outcome: RunOutcome;
      try {
        outcome = (await this.runCapability({ capability: gap.capability, targets: gap.targets, ...(gap.options ? { options: gap.options } : {}) }, caller)).outcome;
      } catch (e) {
        updateGap(this.engagement, gap.id, { status: "open" });
        continue;
      }
      const runId = outcome.status === "started" ? outcome.run.id : undefined;
      // Running: this run closes the gap. Waiting for the operator (the tool is riskier than the
      // agent's ceiling): it stays "resolving" tied to that card, and the decision settles it.
      // Refused: it stays open.
      if (runId) updateGap(this.engagement, gap.id, { status: "resolved", resolvedRun: runId });
      else if (outcome.status === "pending_approval") updateGap(this.engagement, gap.id, { status: "resolving", approvalId: outcome.approval.id });
      else updateGap(this.engagement, gap.id, { status: "open" });
      this.engagement.events.emit("change", { type: "gap.resumed", id: gap.id, capability: gap.capability, tool, ...(runId ? { runId } : {}), status: outcome.status, requestedBy: gap.requestedBy });
      done.push({ gap, outcome });
    }
    return done;
  }

  /** Long work of the core itself (no process of its own) as a run: its lines live, its end recorded. */
  trackJob(tool: string, command: string, by: Actor, work: (say: (line: string) => void) => Promise<Record<string, unknown>>): RunOutcome {
    const run = this.engagement.startRun({ actor: by, origin: "runner", tool, command, targets: [], risk: "passive", policy: { result: "approved" }, runner: "local" });
    this.live.set(run.id, "");
    const say = (line: string) => {
      const before = this.live.get(run.id) ?? "";
      const chunk = `${line}\n`;
      this.live.set(run.id, before + chunk);
      this.engagement.events.emit("change", { type: "run.output", id: run.id, chunk, offset: before.length });
    };
    const end = (status: Run["status"], summary: Record<string, unknown>) => {
      const log = this.live.get(run.id) ?? "";
      this.live.delete(run.id);
      this.engagement.finishRun(run.id, { status, rawIds: log.trim() ? [this.engagement.putRaw(Buffer.from(log), { type: "stdout", mime: "text/plain", runId: run.id })] : [], summary });
    };
    void work(say).then(
      (summary) => end("finished", summary),
      (e: Error) => {
        say(`error: ${e.message}${e instanceof ToolboxError && e.hint ? `\n${e.hint}` : ""}`);
        end("failed", { error: e.message, ...(e instanceof ToolboxError ? { code: e.code } : {}) });
      },
    );
    return { status: "started", run };
  }

  /** Installs a package with Homebrew (macOS: no root, no password), as a run in Executions. */
  private installWithBrew(name: string, pkg: string, by: Actor): RunOutcome {
    const argv = ["install", pkg];
    const run = this.engagement.startRun({ actor: by, origin: "runner", tool: "brew", command: `brew ${argv.join(" ")}`, targets: [], risk: "passive", policy: { result: "approved", reason: "system install with Homebrew" }, runner: "local" });
    this.live.set(run.id, "");
    execFile("brew", argv, { timeout: 30 * 60_000, maxBuffer: 16 * 1024 * 1024, env: { ...process.env, HOMEBREW_NO_ENV_HINTS: "1" } }, (error, stdout, stderr) => {
      const output = `${stdout ?? ""}${stderr ?? ""}`;
      this.live.delete(run.id);
      const rawIds = output.trim() ? [this.engagement.putRaw(Buffer.from(output), { type: "stdout", mime: "text/plain", runId: run.id })] : [];
      this.registry.invalidate();
      if (!error) {
        this.engagement.finishRun(run.id, { status: "finished", exitCode: 0, rawIds, summary: { installed: { tool: name, via: "brew" } } });
        this.engagement.audit(by, "tool.installed", { tool: name }, { via: "brew", command: `brew ${argv.join(" ")}` });
        this.engagement.events.emit("change", { type: "tool.installed", tool: name, version: "system" });
        void this.resumeGaps(name).catch(() => undefined);
      } else {
        this.engagement.finishRun(run.id, { status: "failed", rawIds, summary: { error: output.trim().split("\n").slice(-3).join(" ").slice(0, 300) || error.message, code: "FAILED" } });
      }
    });
    return { status: "started", run };
  }

  /** Installs a system package through pkexec (the password window), as a run in Executions. */
  private installWithSystem(name: string, argv: string[], by: Actor): RunOutcome {
    const run = this.engagement.startRun({ actor: by, origin: "runner", tool: "pkexec", command: `pkexec ${argv.join(" ")}`, targets: [], risk: "passive", policy: { result: "approved", reason: "system install with the operator's password" }, runner: "local" });
    this.live.set(run.id, "");
    void withPassword(argv).then((r) => {
      const output = r.ok ? r.output : r.error;
      this.live.delete(run.id);
      const rawIds = output.trim() ? [this.engagement.putRaw(Buffer.from(output), { type: "stdout", mime: "text/plain", runId: run.id })] : [];
      this.registry.invalidate();
      if (r.ok) {
        this.engagement.finishRun(run.id, { status: "finished", exitCode: 0, rawIds, summary: { installed: { tool: name, via: "system" } } });
        this.engagement.audit(by, "tool.installed", { tool: name }, { via: "system", command: argv.join(" ") });
        this.engagement.events.emit("change", { type: "tool.installed", tool: name, version: "system" });
        void this.resumeGaps(name).catch(() => undefined);
      } else {
        this.engagement.finishRun(run.id, { status: "failed", rawIds, summary: { error: r.dismissed ? "the password window was closed" : r.error, code: r.dismissed ? "DISMISSED" : "FAILED" } });
      }
    });
    return { status: "started", run };
  }

  /**
   * Installs a tool from the verified catalog into Penteos's tool box (no root, no compiler), as a
   * run the operator sees in Executions: each step in its output, the reason and what to do if it
   * fails. When it is ready, the engagement hears "tool.installed" (what was left for it resumes).
   */
  private installFromCatalog(name: string, by: Actor): RunOutcome {
    const box = this.registry.toolbox!;
    const entry = box.entry(name)!;
    const run = this.engagement.startRun({
      actor: by,
      origin: "runner",
      tool: "penteos-toolbox",
      command: `install ${name} ${entry.version}`,
      targets: [],
      risk: "passive",
      policy: { result: "approved" },
      runner: "local",
    });
    this.live.set(run.id, "");
    const say = (line: string) => {
      const before = this.live.get(run.id) ?? "";
      const chunk = `${line}\n`;
      this.live.set(run.id, before + chunk);
      this.engagement.events.emit("change", { type: "run.output", id: run.id, chunk, offset: before.length });
    };
    const manifest = this.registry.get(name);
    // The unpacked file must answer as the tool before it is switched on.
    const verify = async (binary: string) => {
      // Without a manifest, the two usual spellings (Go tools: -version; most others: --version).
      let out = await runForIdentity(binary, manifest?.identity?.args ?? ["-version"]);
      if (!manifest?.identity && (out.startsWith("__error__") || !/\d+\.\d+/.test(out))) out = await runForIdentity(binary, ["--version"]);
      if (out.startsWith("__error__")) return out.slice(10);
      const pattern = manifest?.identity ? new RegExp(manifest.identity.pattern, "mi") : /\d+\.\d+/;
      return pattern.test(out) ? undefined : `it did not print its version (${out.trim().slice(0, 160) || "no output"})`;
    };
    void box
      .install(name, { onProgress: say, verify })
      .then((t) => {
        this.registry.invalidate();
        const output = this.live.get(run.id) ?? "";
        this.live.delete(run.id);
        this.engagement.finishRun(run.id, { status: "finished", exitCode: 0, rawIds: [this.engagement.putRaw(Buffer.from(output), { type: "stdout", mime: "text/plain", runId: run.id })], summary: { installed: { tool: name, version: t.version, bytes: t.bytes } } });
        this.engagement.audit(by, "tool.installed", { tool: name }, { version: t.version, sha256: t.sha256, source: box.asset(name)?.url });
        this.engagement.events.emit("change", { type: "tool.installed", tool: name, version: t.version });
        // What was left for lack of it is taken up again now, without anyone asking.
        void this.resumeGaps(name).catch(() => undefined);
      })
      .catch((e: Error) => {
        const code = e instanceof ToolboxError ? e.code : "FAILED";
        const hint = e instanceof ToolboxError ? e.hint : undefined;
        say(`not installed: ${e.message}${hint ? `\n${hint}` : ""}`);
        const output = this.live.get(run.id) ?? "";
        this.live.delete(run.id);
        this.engagement.finishRun(run.id, { status: "failed", rawIds: [this.engagement.putRaw(Buffer.from(output), { type: "stdout", mime: "text/plain", runId: run.id })], summary: { error: e.message, code, ...(hint ? { hint } : {}) } });
      });
    return { status: "started", run };
  }

  private addApproval(by: Actor, reason: string, summary: string, request: Approval["request"]): Approval {
    const now = Date.now();
    const approval: Approval = {
      id: ulid(),
      createdAt: new Date(now).toISOString(),
      expiresAt: new Date(now + APPROVAL_LONG_TTL_MS).toISOString(),
      requestedBy: by,
      reason,
      warnings: [],
      summary,
      request,
    };
    this.approvals.set(approval.id, approval);
    this.engagement.audit(by, `approval.request.${request.kind}`, { approval: approval.id }, approval);
    this.engagement.events.emit("change", { type: "approval.changed" });
    return approval;
  }

  // -------------------------------------------------------------------------------------------
  // Approvals
  // -------------------------------------------------------------------------------------------

  listApprovals(): Approval[] {
    const now = new Date().toISOString();
    for (const [id, a] of this.approvals) {
      if (a.expiresAt >= now) continue;
      this.approvals.delete(id);
      this.expired.set(id, a);
      this.engagement.emit({ type: "approval.expired", id, summary: a.summary, requestedBy: a.requestedBy });
      this.engagement.events.emit("change", { type: "approval.changed" });
    }
    return [...this.approvals.values()];
  }

  /** Requests that lapsed unanswered (kept so their status and request can still be shown). */
  private readonly expired: Map<string, Approval>;

  async resolveApproval(id: string, approve: boolean, by: Actor, options: { forSession?: boolean; only?: string[]; plugin?: { trust?: "free" | "isolated" } } = {}): Promise<RunOutcome | undefined> {
    const approval = this.listApprovals().find((a) => a.id === id);
    if (!approval) throw new Error(`approval not found or expired: ${id}`);
    this.approvals.delete(id);
    if (approve && options.forSession) this.addGrant(approval, by);
    this.decisions.set(id, { approved: approve, by, at: new Date().toISOString(), summary: approval.summary, approval });
    this.engagement.audit(by, approve ? "approval.approve" : "approval.reject", { approval: id }, { id });
    this.engagement.events.emit("change", { type: "approval.changed" });
    if (!approve) {
      // A gap that was waiting on this card goes back to open (the operator said no to this way).
      for (const g of listGaps(this.engagement)) if (g.approvalId === id) updateGap(this.engagement, g.id, { status: "open", approvalId: undefined });
      this.engagement.events.emit("change", { type: "approval.resolved", id, approved: false, summary: approval.summary, requestedBy: approval.requestedBy, decidedBy: by });
      return undefined;
    }
    const outcome = await this.applyApproval(approval, by, options.only, options.plugin);
    // A gap that was waiting on this card: resolved by the run it started.
    for (const g of listGaps(this.engagement)) {
      if (g.approvalId !== id) continue;
      if (outcome?.status === "started") updateGap(this.engagement, g.id, { status: "resolved", resolvedRun: outcome.run.id, approvalId: undefined });
      else updateGap(this.engagement, g.id, { status: "open", approvalId: undefined });
    }
    // Whoever asked (usually an agent) learns how it ended, even if it is busy right now.
    this.engagement.events.emit("change", {
      type: "approval.resolved",
      id,
      approved: true,
      summary: approval.summary,
      requestedBy: approval.requestedBy,
      decidedBy: by,
      ...(outcome?.status === "started" ? { runId: outcome.run.id } : {}),
      ...(outcome ? { result: outcome.status } : {}),
    });
    return outcome;
  }

  private async applyApproval(approval: Approval, by: Actor, only?: string[], plugin?: { trust?: "free" | "isolated" }): Promise<RunOutcome | undefined> {
    if (approval.request.kind === "findings") {
      // Only what the operator left ticked; the rest stays in review.
      const chosen = new Set(only ?? approval.request.findings.map((f) => f.id));
      const approved: string[] = [];
      const left: string[] = [];
      for (const f of approval.request.findings) {
        const current = this.engagement.get(f.id);
        if (!chosen.has(f.id) || !current || current.kind !== "finding" || !["draft", "in_review"].includes(String(current.attributes.status))) {
          left.push(f.id);
          continue;
        }
        this.engagement.editEntity(f.id, { status: "approved", reviewer: by }, by);
        approved.push(f.id);
      }
      return { status: "findings_approved", approved, left };
    }
    if (approval.request.kind === "scope") {
      return { status: "scope_added", ruleId: this.engagement.addScopeRule(approval.request.rule, by) };
    }
    if (approval.request.kind === "install") return this.install(approval.request.tool, by);
    if (approval.request.kind === "install_kit") {
      // Each tool installs as its own run (one after another in the box); the first is returned.
      const outcomes = approval.request.tools.filter((t) => this.registry.toolbox?.asset(t)).map((t) => this.installFromCatalog(t, by));
      return outcomes[0];
    }
    if (approval.request.kind === "ws") {
      return this.openWs(approval.request, { actor: approval.requestedBy, policy: { type: "human" }, origin: "agent_tool" }, by);
    }
    if (approval.request.kind === "fuzz") {
      return this.runFuzz(approval.request.input, { actor: approval.requestedBy, policy: { type: "human" }, origin: "agent_tool" }, by);
    }
    if (approval.request.kind === "http") {
      const as: ToolCaller = { actor: approval.requestedBy, policy: { type: "human" }, origin: "agent_tool" };
      const probe = approval.request.probe;
      if (probe?.tool === "webjs") return this.harvestScripts(probe.input, as, by);
      if (probe?.tool === "apiprobe") return this.probeEndpoints(probe.input, as, by);
      if (probe?.tool === "apispec") return this.readApiSpec(probe.input, as, by);
      if (probe?.tool === "ratelimit") return this.probeRateLimit(probe.input, as, by);
      if (probe?.tool === "enumeration") return this.measureEnumeration(probe.input, as, by);
      if (probe?.tool === "versions") return this.detectVersions(probe.input, as, by);
      if (probe?.tool === "browser") return this.browse(probe.input, as, by);
      if (probe?.tool === "serveractions") return this.probeServerActions(probe.input, as, by);
      if (probe?.tool === "transport") return this.checkTransport(probe.input, as, by);
      if (probe?.tool === "webprobe") return this.webProbe(probe.input, as, by);
      return this.runHttp(approval.request, as, by);
    }
    if (approval.request.kind === "proxy_rules") {
      return this.setProxyRules(approval.request.rules, approval.request.reason, { actor: approval.requestedBy, policy: { type: "human" }, origin: "agent_tool" }, by);
    }
    if (approval.request.kind === "phase") {
      setPhase(this.engagement, approval.request.to, by, approval.request.summary);
      void this.proposePhaseKit(approval.request.to, approval.requestedBy).catch(() => undefined);
      return { status: "phase_changed", phase: approval.request.to };
    }
    if (approval.request.kind === "plugin") {
      if (!this.pluginInstall) throw new Error("this core does not install plugins");
      return this.pluginInstall(approval.request.proposal, by, plugin);
    }
    if (approval.request.kind === "manifest") {
      const saved = this.registry.save(approval.request.manifest);
      this.engagement.audit(by, "tool.manifest_saved", { tool: saved.name }, saved);
      return { status: "manifest_saved", tool: saved.name };
    }
    if (approval.request.kind === "capability") {
      return this.runBuiltin(approval.request.capability, approval.request.targets, { actor: approval.requestedBy, policy: { type: "human" }, origin: "agent_tool" }, approval.request.options, by);
    }
    const caller: ToolCaller = { actor: approval.requestedBy, policy: { type: "human" }, origin: "agent_tool" };
    return approval.request.kind === "nmap"
      ? this.runNmap(approval.request.argv, caller, by)
      : this.runExec(approval.request, caller, by);
  }

  // -------------------------------------------------------------------------------------------
  // Process management
  // -------------------------------------------------------------------------------------------

  /** The agent no longer needs what it asked for: the card goes away and the decision is recorded. */
  withdrawApproval(id: string, by: Actor, reason: string): void {
    const approval = this.listApprovals().find((a) => a.id === id);
    if (!approval) throw new Error(`approval not found or already decided: ${id}`);
    if (approval.requestedBy.id !== by.id) throw new Error("only whoever asked can withdraw a request");
    this.approvals.delete(id);
    this.decisions.set(id, { approved: false, withdrawn: true, by, at: new Date().toISOString(), summary: approval.summary, approval });
    this.engagement.audit(by, "approval.withdraw", { approval: id }, { reason });
    this.engagement.events.emit("change", { type: "approval.changed" });
  }

  grants(): Grant[] {
    return this.engagement.getMeta<Grant[]>("grants") ?? [];
  }

  revokeGrant(id: string, by: Actor): void {
    this.engagement.setMeta("grants", this.grants().filter((g) => g.id !== id), by);
  }

  private addGrant(approval: Approval, by: Actor): void {
    const r = approval.request;
    if (r.kind === "ws") {
      const origin = new URL(r.url.replace(/^ws/, "http")).origin;
      const grant: Grant = { id: ulid(), tool: "ws", targets: [origin], risk: r.risk, grantedTo: approval.requestedBy, by, at: new Date().toISOString() };
      this.engagement.setMeta("grants", [...this.grants(), grant], by);
      return;
    }
    if (r.kind === "fuzz") {
      const url = requestUrl(r.input.origin, parseRawRequest(parseTemplate(r.input.template).parts.join("")));
      const grant: Grant = { id: ulid(), tool: "fuzz", targets: [url.origin], risk: r.input.risk, grantedTo: approval.requestedBy, by, at: new Date().toISOString() };
      this.engagement.setMeta("grants", [...this.grants(), grant], by);
      return;
    }
    if (r.kind === "http") {
      const url = requestUrl(r.origin, parseRawRequest(r.raw));
      const grant: Grant = { id: ulid(), tool: "http", targets: [url.origin], risk: r.risk, grantedTo: approval.requestedBy, by, at: new Date().toISOString() };
      this.engagement.setMeta("grants", [...this.grants(), grant], by);
      return;
    }
    if (r.kind !== "exec" && r.kind !== "nmap") return;
    const targets = r.kind === "nmap" ? analyzeNmapArgs(r.argv).targets : r.targets;
    // A grant without targets would allow anything that tool can do: never.
    if (targets.length === 0) return;
    const tool = r.kind === "nmap" ? "nmap" : (this.registry.forBinary(r.argv[0]!)?.name ?? r.argv[0]!);
    const risk = r.kind === "nmap" ? analyzeNmapArgs(r.argv).risk : r.risk;
    const grant: Grant = { id: ulid(), tool, targets: [...new Set(targets)].sort(), risk, grantedTo: approval.requestedBy, by, at: new Date().toISOString() };
    this.engagement.setMeta("grants", [...this.grants(), grant], by);
  }

  /** A standing permission covering this request, if the operator gave one. */
  private grantFor(caller: ToolCaller, tool: string, targets: string[], risk: RiskLevel): Grant | undefined {
    if (caller.policy.type !== "agent" || targets.length === 0) return undefined;
    return this.grants().find(
      (g) =>
        g.grantedTo.id === caller.actor.id &&
        !riskExceeds(risk, g.risk) &&
        g.tool === tool &&
        targets.every((t) => g.targets.includes(t)),
    );
  }

  /**
   * The agent asks the operator to approve the findings it considers ready. One request at a time:
   * a new one replaces the previous. Only a human approves; this only puts the decision in front of them.
   */
  proposeFindings(ids: string[], reason: string, by: Actor): Approval {
    const findings = [...new Set(ids)].map((id) => {
      const f = this.engagement.get(id);
      if (!f || f.kind !== "finding") throw new Error(`finding not found: ${id}`);
      const status = String(f.attributes.status);
      if (!["draft", "in_review"].includes(status)) throw new Error(`finding ${id} is ${status}: only draft or in_review findings can be put up for approval`);
      const verdict = (f.attributes.verification as { verdict?: string } | undefined)?.verdict;
      return { id, title: String(f.attributes.title), severity: String(f.attributes.severity), ...(verdict ? { verdict } : {}) };
    });
    for (const a of this.listApprovals()) if (a.request.kind === "findings") this.withdrawApproval(a.id, by, "replaced by a new request");
    const n = findings.length;
    return this.addApproval(by, reason, `Approve ${n} finding${n === 1 ? "" : "s"}`, { kind: "findings", findings });
  }



  /** State of each approval: pending, approved, rejected or expired/unknown. */
  approvalStatus(ids: string[]): Record<string, { state: "pending" | "approved" | "rejected" | "withdrawn" | "expired"; summary?: string; at?: string; request?: Approval["request"] }> {
    const pending = new Map(this.listApprovals().map((a) => [a.id, a]));
    return Object.fromEntries(
      ids.map((id) => {
        const p = pending.get(id);
        if (p) return [id, { state: "pending" as const, summary: p.summary, request: p.request }];
        const d = this.decisions.get(id);
        if (d) return [id, { state: d.withdrawn ? ("withdrawn" as const) : d.approved ? ("approved" as const) : ("rejected" as const), summary: d.summary, at: d.at, request: d.approval.request }];
        const x = this.expired.get(id);
        return [id, { state: "expired" as const, ...(x ? { summary: x.summary, request: x.request } : {}) }];
      }),
    );
  }

  /** An agent closes the current phase and asks to move on; a human decides. */
  proposePhase(to: string, title: string, summary: string, by: Actor, warnings: string[] = []): Approval {
    const existing = this.listApprovals().find((a) => a.request.kind === "phase" && a.request.to === to);
    if (existing) return existing;
    const now = Date.now();
    const approval: Approval = {
      id: ulid(),
      createdAt: new Date(now).toISOString(),
      expiresAt: new Date(now + APPROVAL_TTL_MS).toISOString(),
      requestedBy: by,
      reason: summary,
      warnings,
      summary: `Move to phase "${title}"`,
      request: { kind: "phase", to, title, summary },
    };
    this.approvals.set(approval.id, approval);
    this.engagement.audit(by, "approval.request", { approval: approval.id }, approval);
    this.engagement.events.emit("change", { type: "approval.changed" });
    return approval;
  }

  /**
   * Replace rules rewrite every flow the operator browses through the proxy, so an agent sets them
   * on its own only when it works autonomously up to active risk; otherwise it asks.
   */
  setProxyRules(rules: ReplaceRule[], reason: string, caller: ToolCaller, approvedBy?: Actor): RunOutcome {
    for (const [n, r] of rules.entries()) {
      const problem = validateRule(r);
      if (problem) throw new Error(`rule ${n + 1}: ${problem}`);
    }
    const p = caller.policy;
    if (!approvedBy && p.type === "agent" && !(p.autonomy === "autonomous" && !riskExceeds("active", p.maxRisk))) {
      const request = { kind: "proxy_rules" as const, rules, reason };
      const same = this.listApprovals().find((a) => a.requestedBy.id === caller.actor.id && JSON.stringify(a.request) === JSON.stringify(request));
      if (same) return { status: "pending_approval", approval: same, duplicate: true };
      const now = Date.now();
      const active = rules.filter((r) => r.enabled);
      const approval: Approval = {
        id: ulid(),
        createdAt: new Date(now).toISOString(),
        expiresAt: new Date(now + APPROVAL_TTL_MS).toISOString(),
        requestedBy: caller.actor,
        reason,
        warnings: [],
        summary: active.length ? `Proxy replace rules: ${active.map(describeRule).join(" · ")}` : "Remove all proxy replace rules",
        request,
      };
      this.approvals.set(approval.id, approval);
      this.engagement.audit(caller.actor, "approval.request", { approval: approval.id }, approval);
      this.engagement.events.emit("change", { type: "approval.changed" });
      return { status: "pending_approval", approval };
    }
    this.engagement.setMeta("proxyRules", rules, approvedBy ?? caller.actor);
    this.engagement.emit({ type: "intercept.changed" });
    if (caller.actor.type === "agent") {
      const n = rules.filter((r) => r.enabled).length;
      this.engagement.emit({ type: "proxy.agent_changed", change: "rules", count: n, reason, text: `${n ? `${n} replace rule${n === 1 ? "" : "s"} active` : "No replace rules"}: ${reason}` });
    }
    return { status: "rules_set", rules };
  }

  /**
   * An agent asks for a scope change. Agents can never change the scope themselves: this only
   * creates an approval that a human accepts or rejects.
   */
  proposeScopeRule(rule: ScopeRuleAttributes, reason: string, by: Actor): Approval {
    const now = Date.now();
    const t = rule.target;
    const what = t.type === "range" ? `${t.from}-${t.to}` : t.type === "entity" ? t.entityId : t.value;
    // A wildcard is the widest rule there is: say how many known names it would let in.
    const base = t.type === "wildcard" ? t.value.replace(/^\*\./, "").toLowerCase() : "";
    const covers = base ? this.engagement.query({ kind: "domain", limit: 100000 }).filter((d) => String(d.attributes.fqdn).toLowerCase().endsWith(`.${base}`)).length : 0;
    const approval: Approval = {
      id: ulid(),
      createdAt: new Date(now).toISOString(),
      expiresAt: new Date(now + APPROVAL_LONG_TTL_MS).toISOString(),
      requestedBy: by,
      reason,
      warnings: [],
      summary: `${rule.effect === "include" ? "Include" : "Exclude"} ${t.type} ${what}${rule.ports ? ` (ports ${rule.ports})` : ""}`,
      ...(base && rule.effect === "include" ? { covers } : {}),
      request: { kind: "scope", rule },
    };
    this.approvals.set(approval.id, approval);
    this.engagement.audit(by, "scope.propose_rule", { approval: approval.id }, approval);
    this.engagement.events.emit("change", { type: "approval.changed" });
    return approval;
  }

  /** Resolves when the run leaves "running", or after `seconds`. */
  waitForRun(runId: string, seconds: number): Promise<Run | undefined> {
    const current = this.engagement.getRun(runId);
    if (!current || current.status !== "running") return Promise.resolve(current);
    return new Promise((resolve) => {
      const done = () => {
        clearTimeout(timer);
        this.engagement.events.off("change", onChange);
        resolve(this.engagement.getRun(runId));
      };
      const onChange = (e: { type: string; id?: string }) => {
        if (e.type === "run.finished" && e.id === runId) done();
      };
      const timer = setTimeout(done, seconds * 1000);
      this.engagement.events.on("change", onChange);
    });
  }

  /** Output so far of a run in progress, or undefined if it is not running here. */
  liveOutput(runId: string): string | undefined {
    return this.live.get(runId);
  }

  /** Runs the operator (or an agent) asked to cancel: they end as "cancelled", not "failed". */
  private readonly cancelled = new Set<string>();

  /**
   * Cancels a run. A process gets SIGINT (tools save partial results on it), then SIGTERM and
   * SIGKILL if it ignores it. A run with no process here (a single HTTP request in flight, or one
   * left "running" by a restart) is closed as cancelled, so the button always does something.
   */
  cancel(runId: string): boolean {
    const job = this.fuzzJobs.get(runId);
    if (job) {
      job.cancelled = true;
      return true;
    }
    const own = this.builtinJobs.get(runId);
    if (own) {
      this.cancelled.add(runId);
      own.abort();
      return true;
    }
    const child = this.processes.get(runId);
    if (child) {
      this.cancelled.add(runId);
      killTree(child, "SIGINT");
      setTimeout(() => this.processes.get(runId) === child && killTree(child, "SIGTERM"), 3000).unref?.();
      setTimeout(() => this.processes.get(runId) === child && killTree(child, "SIGKILL"), 6000).unref?.();
      return true;
    }
    const run = this.engagement.getRun(runId);
    if (run?.status !== "running") return false;
    this.engagement.finishRun(runId, { status: "cancelled", summary: { note: "cancelled while no process was attached (a request in flight, or left running by a restart)" } });
    return true;
  }

  /** Stops every running process (stop-work). */
  cancelAll(signal: NodeJS.Signals = "SIGINT"): number {
    for (const child of this.processes.values()) killTree(child, signal);
    for (const s of this.wsSessions.values()) s.ws.close(1001, "stop-work");
    for (const job of this.fuzzJobs.values()) job.cancelled = true;
    return this.processes.size + this.fuzzJobs.size;
  }

  private spawnTracked(run: Run, command: string, args: string[], after: (output: string, rawIds: string[]) => (IngestSummary & { skipped?: number }) | undefined): void {
    const chunks: Buffer[] = [];
    // Secrets are substituted here, for the process only: the run keeps {{secret:name}}.
    // Its own process group, so cancelling also stops what the tool launched (scripts, helpers):
    // otherwise a child keeps the output open and the run never ends. Tied to the core: if the
    // core dies, the tool stops too instead of going on against the target (tied.ts).
    const child = spawnTied(command, this.engagement.resolveSecrets(args).argv, { cwd: this.workDir(), env: cleanEnv(this.registry.toolbox?.binDir, this.registry.toolbox?.env()) });
    this.processes.set(run.id, child);
    this.live.set(run.id, "");
    const onData = (data: Buffer) => {
      chunks.push(data);
      const chunk = data.toString("utf8");
      const before = this.live.get(run.id) ?? "";
      this.live.set(run.id, before + chunk);
      // `offset` lets a client that fetched the buffer meanwhile skip what it already has.
      this.engagement.events.emit("change", { type: "run.output", id: run.id, chunk, offset: before.length });
    };
    child.stdout?.on("data", onData);
    child.stderr?.on("data", onData);

    let finished = false;
    const finish = (exitCode: number | null, error?: Error) => {
      if (finished) return;
      finished = true;
      this.processes.delete(run.id);
      this.live.delete(run.id);
      const output = Buffer.concat(chunks);
      const rawIds = output.length > 0 ? [this.engagement.putRaw(output, { type: "stdout", mime: "text/plain", runId: run.id })] : [];
      let summary: Record<string, unknown> | undefined;
      try {
        const ingested = after(output.toString("utf8"), rawIds);
        if (ingested) summary = { ingested };
      } catch (e) {
        summary = { ingestError: (e as Error).message };
      }
      if (error) summary = { ...summary, error: error.message };
      const cancelled = this.cancelled.delete(run.id);
      this.engagement.finishRun(run.id, {
        status: cancelled ? "cancelled" : error || (exitCode !== 0 && exitCode !== null) ? "failed" : "finished",
        ...(exitCode !== null ? { exitCode } : {}),
        rawIds,
        ...(summary ? { summary } : {}),
      });
    };
    child.on("error", (error) => finish(null, error));
    child.on("close", (code) => finish(code));
  }
}

/** Sends a signal to a tool and everything it started (its process group). */
function killTree(child: ChildProcess, signal: NodeJS.Signals): void {
  try {
    if (child.pid && process.platform !== "win32") process.kill(-child.pid, signal);
    else child.kill(signal);
  } catch {
    child.kill(signal);
  }
}
