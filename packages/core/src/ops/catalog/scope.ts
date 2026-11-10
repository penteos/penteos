import { defineOperation, OperationError } from "../registry.js";
import { RiskLevel, ScopeRuleAttributes } from "@penteos/schema";
import { z } from "zod";
import { rulesOf } from "./rules.js";
import type { ReplaceRule } from "../../proxy/intercept.js";
import { engagementId } from "./shared.js";

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
