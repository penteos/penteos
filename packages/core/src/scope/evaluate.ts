import {
  DEFAULT_NETWORK_CONTEXT,
  type EngagementAttributes,
  normalizeFqdn,
  normalizeOrigin,
  type RiskLevel,
  riskExceeds,
  type ScopeRuleAttributes,
  type TimeWindow,
} from "@penteos/schema";
import {
  type AddressRange,
  parseTarget,
  rangeBetween,
  rangeContains,
  rangeOfCidr,
  rangeOfIp,
  rangesOverlap,
  type Target,
} from "./target.js";

/**
 * Scope evaluation. This is the core's main safety mechanism: every
 * target-facing operation - human or agent - goes through it, so it is a pure function with no
 * I/O, easy to test exhaustively.
 */

export interface ScopeRule extends ScopeRuleAttributes {
  id: string;
}

export type ActorPolicy =
  | { type: "human" }
  | { type: "agent"; autonomy: "suggest" | "with_approval" | "autonomous"; maxRisk: RiskLevel };

export interface ScopeQuery {
  target: string;
  risk: RiskLevel;
  actor: ActorPolicy;
  networkContext?: string;
  /** For domain targets: IPs it currently resolves to, if known (used for warnings). */
  resolvedIps?: string[];
  now?: Date;
}

export type ScopeCode = "STOP_WORK_ACTIVE" | "OUT_OF_SCOPE" | "OUTSIDE_WINDOW" | "RISK_EXCEEDED" | "INVALID_TARGET" | "HOST_BUSY";

/** Why a human has to look, so the interface can say it in the operator's language. */
export type AskWhy = { code: "autonomy"; autonomy: string } | { code: "agent_risk"; risk: string; ceiling: string } | { code: "review" } | { code: "unverifiable"; targets: string } | { code: "no_targets" };

export type ScopeDecision =
  | { decision: "allow"; ruleId: string; warnings: string[] }
  | { decision: "ask"; ruleId: string; reason: string; warnings: string[]; why: AskWhy }
  | { decision: "deny"; code: ScopeCode; reason: string; ruleId?: string };

type Engagement = Pick<EngagementAttributes, "maxRisk" | "stopWork" | "startsAt" | "endsAt">;

// ---------------------------------------------------------------------------------------------
// Matching
// ---------------------------------------------------------------------------------------------

function parsePorts(spec: string): Array<[number, number]> {
  return spec.split(",").map((part) => {
    const [a, b] = part.split("-").map(Number);
    return [a!, b ?? a!];
  });
}

function portAllowed(spec: string, port: number): boolean {
  return parsePorts(spec).some(([a, b]) => port >= a && port <= b);
}

function ruleRange(rule: ScopeRule): AddressRange | undefined {
  const t = rule.target;
  if (t.type === "ip") return rangeOfIp(t.value);
  if (t.type === "cidr") return rangeOfCidr(t.value);
  if (t.type === "range") return rangeBetween(t.from, t.to);
  return undefined;
}

function hostMatchesName(rule: ScopeRule, host: string): boolean {
  const t = rule.target;
  if (t.type === "domain") return normalizeFqdn(t.value) === host;
  if (t.type === "wildcard") {
    const base = normalizeFqdn(t.value.slice(2));
    return host.endsWith(`.${base}`);
  }
  return false;
}

function targetPort(target: Target): number | undefined {
  return target.type === "url" ? target.port : target.port;
}

/**
 * `include` must cover the whole target; `exclude` applies on any overlap. Scanning a /24 that
 * contains one excluded host is a violation, even if the other 253 are in scope.
 */
function matches(rule: ScopeRule, target: Target, context: string, mode: "covers" | "overlaps"): boolean {
  if (rule.networkContext !== undefined && rule.networkContext !== context) return false;
  if (rule.target.type === "entity") return false; // needs the graph; resolved by the caller in v1

  let hit = false;
  const range = ruleRange(rule);

  if (target.type === "address" && range) {
    hit = mode === "covers" ? rangeContains(range, target.range) : rangesOverlap(range, target.range);
  } else if (target.type === "domain") {
    hit = hostMatchesName(rule, target.fqdn);
  } else if (target.type === "url") {
    if (rule.target.type === "url") {
      const ruleUrl = new URL(rule.target.value);
      hit = normalizeOrigin(rule.target.value) === target.origin && target.path.startsWith(ruleUrl.pathname);
    } else if (target.hostIsIp && range) {
      const hostRange = rangeOfIp(target.host);
      hit = mode === "covers" ? rangeContains(range, hostRange) : rangesOverlap(range, hostRange);
    } else if (!target.hostIsIp) {
      hit = hostMatchesName(rule, target.host);
    }
  }
  if (!hit) return false;

  if (rule.ports !== undefined) {
    const port = targetPort(target);
    // Unknown port: the action may touch any port. It overlaps an exclude, but is not covered by an include.
    if (port === undefined) return mode === "overlaps";
    return portAllowed(rule.ports, port);
  }
  return true;
}

// ---------------------------------------------------------------------------------------------
// Time windows
// ---------------------------------------------------------------------------------------------

const WEEKDAYS: Record<string, number> = { Sun: 0, Mon: 1, Tue: 2, Wed: 3, Thu: 4, Fri: 5, Sat: 6 };

function minutes(hhmm: string): number {
  const [h, m] = hhmm.split(":").map(Number);
  return h! * 60 + m!;
}

function insideWindow(window: TimeWindow, now: Date): boolean {
  const parts = new Intl.DateTimeFormat("en-US", {
    timeZone: window.timeZone,
    weekday: "short",
    hour: "2-digit",
    minute: "2-digit",
    hourCycle: "h23",
  }).formatToParts(now);
  const get = (type: string) => parts.find((p) => p.type === type)?.value ?? "";
  const day = WEEKDAYS[get("weekday")]!;
  const current = Number(get("hour")) * 60 + Number(get("minute"));
  const start = minutes(window.start);
  const end = minutes(window.end);

  if (start <= end) return window.days.includes(day) && current >= start && current < end;
  // Overnight window (e.g. 22:00-06:00): the part after midnight belongs to the previous day.
  if (current >= start) return window.days.includes(day);
  return current < end && window.days.includes((day + 6) % 7);
}

// ---------------------------------------------------------------------------------------------
// Evaluation
// ---------------------------------------------------------------------------------------------

function describe(rule: ScopeRule): string {
  const t = rule.target;
  const what = t.type === "range" ? `${t.from}-${t.to}` : t.type === "entity" ? `entity ${t.entityId}` : t.value;
  return `${rule.effect} ${what}${rule.ports ? ` ports ${rule.ports}` : ""}`;
}

const hostOf = (target: Target, raw: string): string => ("host" in target && typeof target.host === "string" ? target.host : raw);

export function evaluateScope(engagement: Engagement, rules: ScopeRule[], query: ScopeQuery): ScopeDecision {
  const now = query.now ?? new Date();
  const context = query.networkContext ?? DEFAULT_NETWORK_CONTEXT;

  // 1. Stop-work beats everything.
  if (engagement.stopWork?.active) {
    return { decision: "deny", code: "STOP_WORK_ACTIVE", reason: `Stop-work is active: ${engagement.stopWork.reason}` };
  }

  if (
    (engagement.startsAt && now < new Date(engagement.startsAt)) ||
    (engagement.endsAt && now > new Date(engagement.endsAt))
  ) {
    return { decision: "deny", code: "OUTSIDE_WINDOW", reason: "The engagement is not within its authorized dates" };
  }

  let target: Target;
  try {
    target = parseTarget(query.target);
  } catch (error) {
    return { decision: "deny", code: "INVALID_TARGET", reason: (error as Error).message };
  }

  // 2. Exclusions always win.
  const excluded = rules.find((r) => r.effect === "exclude" && matches(r, target, context, "overlaps"));
  if (excluded) {
    return {
      decision: "deny",
      code: "OUT_OF_SCOPE",
      ruleId: excluded.id,
      reason: `${query.target} overlaps an exclusion (${describe(excluded)})${excluded.reason ? `: ${excluded.reason}` : ""}`,
    };
  }

  // 3. Default deny: some inclusion must cover the target.
  const includes = rules.filter((r) => r.effect === "include" && matches(r, target, context, "covers"));
  if (includes.length === 0) {
    // The host is in scope, but only on some ports, and the target names none: say so, with the fix.
    const onPorts = rules.find((r) => r.effect === "include" && r.ports !== undefined && targetPort(target) === undefined && matches({ ...r, ports: undefined }, target, context, "covers"));
    if (onPorts) {
      return { decision: "deny", code: "OUT_OF_SCOPE", ruleId: onPorts.id, reason: `${query.target} is in scope only on ports ${onPorts.ports}, and this target names no port (it could touch any). Write it with its port: https://${hostOf(target, query.target)} or ${hostOf(target, query.target)}:${String(onPorts.ports).split(/[,-]/)[0]}.` };
    }
    return { decision: "deny", code: "OUT_OF_SCOPE", reason: `${query.target} does not match any inclusion rule` };
  }

  // 4-5. Windows and risk ceilings: any matching inclusion that permits the action is enough.
  if (riskExceeds(query.risk, engagement.maxRisk)) {
    return {
      decision: "deny",
      code: "RISK_EXCEEDED",
      reason: `Risk "${query.risk}" exceeds the engagement ceiling "${engagement.maxRisk}"`,
    };
  }
  const inWindow = includes.filter((r) => !r.windows?.length || r.windows.some((w) => insideWindow(w, now)));
  if (inWindow.length === 0) {
    return {
      decision: "deny",
      code: "OUTSIDE_WINDOW",
      ruleId: includes[0]!.id,
      reason: `Outside the allowed time windows for ${query.target}`,
    };
  }
  const rule = inWindow.find((r) => !r.maxRisk || !riskExceeds(query.risk, r.maxRisk));
  if (!rule) {
    const first = inWindow[0]!;
    return {
      decision: "deny",
      code: "RISK_EXCEEDED",
      ruleId: first.id,
      reason: `Risk "${query.risk}" exceeds the ceiling "${first.maxRisk}" for ${describe(first)}`,
    };
  }

  // 6-7. Warnings that need a human look, then actor autonomy.
  const warnings: string[] = [];
  if (target.type === "domain" || (target.type === "url" && !target.hostIsIp)) {
    for (const ip of query.resolvedIps ?? []) {
      const ipTarget = parseTarget(ip);
      const hit = rules.find((r) => r.effect === "exclude" && matches(r, ipTarget, context, "overlaps"));
      if (hit) warnings.push(`${query.target} resolves to ${ip}, which is excluded (${describe(hit)})`);
    }
  }

  const actor = query.actor;
  if (actor.type === "agent") {
    if (actor.autonomy !== "autonomous") {
      return { decision: "ask", ruleId: rule.id, reason: `Agent autonomy is "${actor.autonomy}"`, warnings, why: { code: "autonomy", autonomy: actor.autonomy } };
    }
    if (riskExceeds(query.risk, actor.maxRisk)) {
      return {
        decision: "ask",
        ruleId: rule.id,
        reason: `Risk "${query.risk}" exceeds the agent's own ceiling "${actor.maxRisk}"`,
        warnings,
        why: { code: "agent_risk", risk: query.risk, ceiling: actor.maxRisk },
      };
    }
  }

  if (warnings.length > 0) {
    return { decision: "ask", ruleId: rule.id, reason: "The target needs review", warnings, why: { code: "review" } };
  }
  return { decision: "allow", ruleId: rule.id, warnings };
}
