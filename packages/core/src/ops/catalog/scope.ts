import { defineOperation, OperationError } from "../registry.js";
import { RiskLevel, ScopeRuleAttributes } from "@penteos/schema";
import { z } from "zod";
import { rulesOf } from "./rules.js";
import type { ReplaceRule } from "../../proxy/intercept.js";
import { engagementId } from "./shared.js";
import { outOfScopeSurface, recordSurfaceDecision } from "../../surface.js";

// ---------------------------------------------------------------------------------------------
// scope
// ---------------------------------------------------------------------------------------------

defineOperation({
  name: "scope.list_rules",
  title: "List scope rules",
  description: "Lists the inclusion and exclusion rules of the engagement.",
  kind: "read",
  actors: ["human", "agent"],
  input: z.object({ engagementId }),
  handler: (input, ctx) => ctx.engagement(input.engagementId).scopeRules(),
});

defineOperation({
  name: "scope.add_rule",
  title: "Add scope rule",
  description: "Adds an inclusion or exclusion rule.",
  kind: "admin",
  actors: ["human"],
  input: z.object({ engagementId, rule: ScopeRuleAttributes }),
  handler: (input, ctx) => ({ id: ctx.engagement(input.engagementId).addScopeRule(input.rule, ctx.caller.actor) }),
});

defineOperation({
  name: "scope.remove_rule",
  title: "Remove scope rule",
  description: "Removes a scope rule.",
  kind: "admin",
  actors: ["human"],
  input: z.object({ engagementId, ruleId: z.string() }),
  handler: (input, ctx) => {
    ctx.engagement(input.engagementId).removeScopeRule(input.ruleId, ctx.caller.actor);
    return { removed: input.ruleId };
  },
});

defineOperation({
  name: "scope.propose_rule",
  title: "Propose scope change",
  description:
    "Proposes a scope rule with a justification. You cannot change the scope: a human approves or rejects the proposal. Use it when the engagement goal clearly needs targets that are out of scope. Always propose the narrowest rule that unblocks the work: the exact host (e.g. www.example.com when example.com redirects there), never a wildcard unless the operator asked for subdomains. When the rules say noSubdomains, wildcard proposals are refused.",
  kind: "write",
  actors: ["agent"],
  input: z.object({ engagementId, rule: ScopeRuleAttributes, reason: z.string().min(1) }),
  handler: (input, ctx) => {
    const e = ctx.engagement(input.engagementId);
    if (input.rule.effect === "include" && input.rule.target.type === "wildcard" && rulesOf(e).noSubdomains) {
      throw new OperationError(
        "SUBDOMAINS_EXCLUDED",
        "The operator does not want subdomains in this project. Propose the exact host you need instead (for example the www host the site redirects to), or ask the operator on the board.",
      );
    }
    const approval = ctx.runner(input.engagementId).proposeScopeRule(input.rule, input.reason, ctx.caller.actor);
    return { status: "pending_approval", approvalId: approval.id, summary: approval.summary };
  },
});

defineOperation({
  name: "scope.check",
  title: "Check scope",
  description:
    "Evaluates whether a target (IP, CIDR, host:port, domain or URL) is in scope for a given risk level. ALWAYS call this before proposing an action against a new target.",
  kind: "read",
  actors: ["human", "agent"],
  input: z.object({ engagementId, target: z.string().min(1), risk: RiskLevel.default("active"), networkContext: z.string().optional() }),
  handler: (input, ctx) =>
    ctx.engagement(input.engagementId).checkScope(input.target, input.risk, ctx.caller.policy, input.networkContext),
});

// ---------------------------------------------------------------------------------------------
// Surface found outside the scope: every asset gets a decision
// ---------------------------------------------------------------------------------------------

defineOperation({
  name: "surface.list",
  title: "Surface outside the scope",
  description:
    "Hosts of the client's own domains that reconnaissance found outside the scope (an automation server, a QA environment, a payments site), with what is known of each and the decision taken: proposed for inclusion, or set aside with a reason. Undecided ones keep a round from closing.",
  kind: "read",
  actors: ["human", "agent"],
  input: z.object({ engagementId }),
  handler: (input, ctx) => {
    const all = outOfScopeSurface(ctx.engagement(input.engagementId));
    return { undecided: all.filter((s) => !s.decision), decided: all.filter((s) => s.decision) };
  },
});

defineOperation({
  name: "surface.decide",
  title: "Decide on surface outside the scope",
  description:
    "Decides, in one call, on hosts found outside the scope (surface_list). propose: asks the operator to include each one (a scope proposal per host, narrowest rule: its web origin, else the host), with the reason the operator will read - say what makes it worth testing (an exposed automation tool, a QA environment, plain HTTP, a version with known CVEs). set_aside: leaves them out on purpose, with the reason (a third-party service, parked, the operator excluded it). Never leave discovered assets undecided.",
  kind: "write",
  actors: ["human", "agent"],
  input: z.object({ engagementId, hosts: z.array(z.string().min(1)).min(1).max(50), decision: z.enum(["propose", "set_aside"]), reason: z.string().min(3).max(800) }),
  handler: (input, ctx) => {
    const e = ctx.engagement(input.engagementId);
    const known = new Map(outOfScopeSurface(e).map((s) => [s.host, s]));
    const hosts = input.hosts.map((h) => h.replace(/^[a-z][a-z0-9+.-]*:\/\//i, "").replace(/[:/].*$/, "").toLowerCase());
    const unknown = hosts.filter((h) => !known.has(h));
    if (unknown.length) throw new OperationError("NOT_FOUND", `not surface outside the scope: ${unknown.join(", ")} (see surface_list)`);
    const approvals: string[] = [];
    if (input.decision === "propose") {
      const runner = ctx.runner(input.engagementId);
      for (const h of hosts) {
        const asset = known.get(h)!;
        const origin = asset.origins.find((o) => o.startsWith("https://")) ?? asset.origins[0];
        const rule = origin ? { effect: "include" as const, target: { type: "url" as const, value: origin.replace(/:(443|80)$/, "") } } : { effect: "include" as const, target: { type: "domain" as const, value: h } };
        const about = [asset.title, asset.technologies.slice(0, 4).join(", ")].filter(Boolean).join(" · ");
        approvals.push(runner.proposeScopeRule(rule, `${input.reason}${about ? ` (${about})` : ""}`, ctx.caller.actor).id);
      }
    }
    recordSurfaceDecision(e, hosts, input.decision === "propose" ? "proposed" : "set_aside", input.reason, ctx.caller.actor);
    return { decided: hosts.length, ...(approvals.length ? { approvals, note: "The operator decides each inclusion on its card; once approved the host is in scope and you can test it." } : {}) };
  },
});
