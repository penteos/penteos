import { lang, t } from "./i18n";

/**
 * Every enumerated value the core speaks in English, in the operator's language (catalog
 * "labels"). The maps keep their old names and shape - `RISK_ES[v]`, `Object.entries(RISK_ES)` -
 * but each value is read from the catalog when it is used. Unknown values fall back to themselves.
 */

function localized(group: string, keys: string[]): Record<string, string> {
  return new Proxy({} as Record<string, string>, {
    get: (_target, prop) => (typeof prop === "string" && keys.includes(prop) ? t(`labels.${group}.${prop}`) : undefined),
    has: (_target, prop) => keys.includes(String(prop)),
    ownKeys: () => keys,
    getOwnPropertyDescriptor: (_target, prop) => (keys.includes(String(prop)) ? { enumerable: true, configurable: true, value: t(`labels.${group}.${String(prop)}`) } : undefined),
  });
}

export const RISK_ES = localized("risk", ["passive", "active", "intrusive", "exploitation"]);
export const SEVERITY_ES = localized("severity", ["critical", "high", "medium", "low", "info"]);
export const FINDING_STATUS_ES = localized("findingStatus", ["draft", "in_review", "approved", "reported", "fixed", "partially_fixed", "not_fixed", "not_verifiable", "reopened", "wont_fix"]);
export const TASK_STATUS_ES = localized("taskStatus", ["todo", "in_progress", "blocked", "awaiting_approval", "done", "cancelled"]);
export const RUN_STATUS_ES = localized("runStatus", ["running", "finished", "failed", "denied", "cancelled"]);
export const RUN_ORIGIN_ES = localized("runOrigin", ["terminal", "runner", "agent_tool", "import", "api"]);
export const AUTONOMY_ES = localized("autonomy", ["copilot", "maestro", "maestro_auto"]);
export const DATA_POLICY_ES = localized("dataPolicy", ["any_provider", "approved_providers", "local_only", "no_ai"]);
export const SCOPE_TYPE_ES = localized("scopeType", ["ip", "cidr", "range", "domain", "wildcard", "url", "entity"]);
export const ENGAGEMENT_STATUS_ES = localized("engagementStatus", ["planning", "active", "paused", "reporting", "closed", "archived"]);

export const label = (map: Record<string, string>, value: unknown): string => {
  const v = String(value ?? "");
  return v in map ? map[v]! : v;
};
export const risk = (v: unknown) => label(RISK_ES, v);
export const severity = (v: unknown) => label(SEVERITY_ES, v);

/** A fuzzer anomaly tag from the core ("status 200→500", "size +120", "slow 900 ms", "match", "uncommon"). */
export function anomaly(tag: string): string {
  const m = /^(status|size|slow) (.+)$/.exec(tag);
  if (m) return `${t(`labels.anomaly.${m[1]}`)} ${m[2]}`;
  return tag === "match" || tag === "uncommon" || tag === "error" ? t(`labels.anomaly.${tag}`) : tag;
}

/** An OWASP WSTG category's name in the interface language (the core sends both). */
export function wstgName(c: { title: string; titleEn?: string }): string {
  return lang() === "en" ? (c.titleEn ?? c.title) : c.title;
}
