import { defineOperation, OperationError } from "../registry.js";
import { z } from "zod";
import { excludeSubdomains } from "./rules.js";
import type { ReplaceRule } from "../../proxy/intercept.js";
import { engagementId, outcome } from "./shared.js";

// ---------------------------------------------------------------------------------------------
// approvals
// ---------------------------------------------------------------------------------------------

defineOperation({
  name: "approval.list",
  title: "Pending approvals",
  description: "Actions waiting for a human decision.",
  kind: "read",
  actors: ["human", "agent"],
  input: z.object({ engagementId }),
  handler: (input, ctx) => ctx.runner(input.engagementId).listApprovals(),
});

defineOperation({
  name: "approval.status",
  title: "Approval status",
  description: "How each given approval ended: pending, approved, rejected or expired.",
  kind: "read",
  actors: ["human", "agent"],
  input: z.object({ engagementId, ids: z.array(z.string()).max(200) }),
  handler: (input, ctx) => ctx.runner(input.engagementId).approvalStatus(input.ids),
});

for (const approve of [true, false]) {
  defineOperation({
    name: approve ? "approval.approve" : "approval.reject",
    title: approve ? "Approve action" : "Reject action",
    description: approve ? "Approves a pending action, which then runs." : "Rejects a pending action.",
    kind: "admin",
    actors: ["human"],
    input: z.object({
      engagementId,
      approvalId: z.string(),
      ...(approve
        ? {
            forSession: z.boolean().default(false).describe("Also allow the same tool against the same targets, up to the same risk, for the rest of the engagement."),
            only: z.array(z.string()).optional().describe("For a findings request: the ones to approve (all when absent); the rest stay in review."),
            plugin: z
              .object({ reviewedCode: z.boolean().default(false), trust: z.enum(["free", "isolated"]).optional() })
              .optional()
              .describe("For a code plugin the Maestro built: the operator says they reviewed its code, and how it runs (isolated unless freed)."),
          }
        : {}),
    }),
    handler: async (input, ctx) => {
      const runner = ctx.runner(input.engagementId);
      const request = runner.listApprovals().find((a) => a.id === input.approvalId)?.request;
      const plugin = (input as { plugin?: { reviewedCode: boolean; trust?: "free" | "isolated" } }).plugin;
      // Code the Maestro wrote runs only after a person says they reviewed it (checked before the approval is spent).
      if (approve && request?.kind === "plugin" && request.proposal.code && !plugin?.reviewedCode) {
        throw new OperationError("VALIDATION_ERROR", "this plugin runs code the Maestro wrote: review it and confirm (plugin.reviewedCode) to approve it");
      }
      const result = await runner.resolveApproval(input.approvalId, approve, ctx.caller.actor, {
        forSession: Boolean((input as { forSession?: boolean }).forSession),
        ...((input as { only?: string[] }).only ? { only: (input as { only: string[] }).only } : {}),
        ...(plugin?.trust ? { plugin: { trust: plugin.trust } } : {}),
      });
      // Rejecting a wildcard means "no subdomains": the agents stop proposing them.
      if (!approve && request?.kind === "scope" && request.rule.effect === "include" && request.rule.target.type === "wildcard") {
        excludeSubdomains(ctx.engagement(input.engagementId), ctx.caller.actor);
      }
      return outcome(result, ctx);
    },
  });
}

defineOperation({
  name: "approval.withdraw",
  title: "Withdraw a request",
  description: "Withdraws an approval you asked for and no longer need (the operator stops seeing it). Do this whenever your plan changed while a request was waiting.",
  kind: "write",
  actors: ["human", "agent"],
  input: z.object({ engagementId, approvalId: z.string(), reason: z.string().min(1) }),
  handler: (input, ctx) => {
    try {
      ctx.runner(input.engagementId).withdrawApproval(input.approvalId, ctx.caller.actor, input.reason);
    } catch (e) {
      throw new OperationError("VALIDATION_ERROR", (e as Error).message);
    }
    return { status: "withdrawn" };
  },
});

defineOperation({
  name: "approval.grants",
  title: "Standing permissions",
  description: "Permissions the operator gave for the rest of the engagement (same tool, same targets, up to a risk level).",
  kind: "read",
  actors: ["human", "agent"],
  input: z.object({ engagementId }),
  handler: (input, ctx) => ctx.runner(input.engagementId).grants(),
});

defineOperation({
  name: "approval.revoke_grant",
  title: "Revoke a standing permission",
  description: "Removes a permission given for the session: the next request asks again.",
  kind: "admin",
  actors: ["human"],
  input: z.object({ engagementId, id: z.string() }),
  handler: (input, ctx) => {
    ctx.runner(input.engagementId).revokeGrant(input.id, ctx.caller.actor);
    return { status: "revoked" };
  },
});
