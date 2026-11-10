import type { Approval } from "../state";
import { t, tn } from "../i18n";
import { risk } from "../labels";

/**
 * Approvals come from the core with an English summary (for agents and the audit log). The card
 * builds its own wording from the structured request, in the operator's language.
 */

type Rule = { enabled?: boolean; target: string; match: string; replace: string; regex?: boolean };

function ruleText(r: Rule): string {
  const where = t(`agent.rule.target.${r.target}`);
  if (!r.match && r.target.endsWith("header")) return t("agent.rule.add", { value: r.replace, where });
  if (!r.replace) return t("agent.rule.remove", { value: r.match, where });
  return t("agent.rule.replace", { match: r.match, replace: r.replace, where: r.regex ? `${where}, regex` : where });
}

/** The card's main line; the core's English summary when the request has no wording of its own. */
export function approvalSummary(a: Approval): string {
  const q = a.request;
  if (!q) return a.summary;
  switch (q.kind) {
    case "phase":
      return q.title ? t("agent.approval.phase.summary", { title: q.title }) : a.summary;
    case "findings":
      return tn("agent.approval.findings.summary", q.findings?.length ?? 0);
    case "plugin":
      return q.proposal ? (q.proposal.update ? t("plugins.proposal.summaryUpdate", { name: q.proposal.name, from: q.proposal.update.from ?? "?", to: q.proposal.version }) : t("plugins.proposal.summary", { name: q.proposal.name, version: q.proposal.version })) : a.summary;
    case "scope": {
      const rule = q.rule;
      if (!rule) return a.summary;
      const tg = rule.target;
      const what = tg.type === "range" ? `${tg.from}-${tg.to}` : tg.type === "entity" ? tg.entityId : tg.value;
      const text = t(`agent.approval.scope.${rule.effect === "exclude" ? "exclude" : "include"}`, { type: t(`labels.scopeType.${tg.type}`), what });
      return rule.ports ? `${text} (${t("agent.approval.scope.ports", { ports: rule.ports })})` : text;
    }
    case "proxy_rules": {
      const active = (q.rules ?? []).filter((r) => r.enabled !== false);
      return active.length ? t("agent.approval.proxy_rules.summary", { rules: active.map(ruleText).join(" · ") }) : t("agent.approval.proxy_rules.clear");
    }
    default:
      return a.summary;
  }
}

/** Why a human has to decide, when the scope engine asked; otherwise the reason as given. */
export function approvalWhy(a: Approval): string {
  const w = a.why;
  if (!w) return a.reason;
  switch (w.code) {
    case "autonomy":
      return t("agent.approval.why.autonomy", { autonomy: t(`agent.approval.autonomy.${w.autonomy}`) });
    case "agent_risk":
      return t("agent.approval.why.agentRisk", { risk: risk(w.risk), ceiling: risk(w.ceiling) });
    case "review":
      return t("agent.approval.why.review");
    case "unverifiable":
      return t("agent.approval.why.unverifiable", { targets: w.targets });
    case "no_targets":
      return t("agent.approval.why.noTargets");
    default:
      return a.reason;
  }
}

/** Notes the card adds in the operator's language (local files the command reads). */
export function approvalNotes(a: Approval): string[] {
  const out: string[] = [];
  if (a.localFiles?.length) out.push(t("agent.approval.localFiles", { files: a.localFiles.join(", ") }));
  // A wildcard is the widest scope change: say what it lets in.
  if (a.covers !== undefined) out.push(a.covers ? tn("agent.approval.covers", a.covers) : t("agent.approval.coversUnknown"));
  return out;
}
