import { z } from "zod";
import { defineOperation, OperationError } from "../registry.js";
import type { Engagement } from "../../engagement.js";
import { engagementId } from "./shared.js";

/**
 * Rules of engagement the operator gives up front: test accounts, what is
 * allowed, what to avoid. The agents read them in engagement_brief and stop asking for them in
 * the middle of the work. Passwords never live here: an account points to a saved secret.
 */

export const TestAccount = z.object({
  label: z.string().min(1).max(80).describe("What it is for, e.g. 'app admin' or 'unprivileged user'"),
  username: z.string().min(1).max(200),
  secret: z.string().max(60).optional().describe("Name of the saved secret with the password or token (use it as {{secret:name}})"),
  role: z.enum(["admin", "user", "low", "service", "other"]).default("user"),
  notes: z.string().max(500).optional(),
});

export const EngagementRules = z.object({
  accounts: z.array(TestAccount).max(30).default([]),
  /** Free text: what the client explicitly allows (levels, techniques, windows, data handling). */
  allowed: z.string().max(4000).default(""),
  /** Free text: what must not be touched or done. */
  avoid: z.string().max(4000).default(""),
  /**
   * The operator does not want subdomains: agents may not propose a wildcard, and the plan works on
   * the hosts in scope. Set in the wizard (subdomains unchecked) or by rejecting a wildcard proposal.
   */
  noSubdomains: z.boolean().default(false),
  updatedAt: z.string().optional(),
});
export type EngagementRules = z.infer<typeof EngagementRules>;

export function rulesOf(e: Engagement): EngagementRules {
  return EngagementRules.parse(e.getMeta("rules") ?? {});
}

defineOperation({
  name: "rules.get",
  title: "Rules of engagement",
  description: "Test accounts (with the secret that holds each password), what the client allows and what to avoid, and noSubdomains (true: the operator does not want subdomains; never propose a wildcard, work on the hosts in scope). Read them before asking the operator for credentials or permissions.",
  kind: "read",
  actors: ["human", "agent"],
  input: z.object({ engagementId }),
  handler: (input, ctx) => rulesOf(ctx.engagement(input.engagementId)),
});

defineOperation({
  name: "rules.set",
  title: "Set the rules of engagement",
  description: "Replaces the test accounts and the allowed / avoid texts. Each account's secret must already be saved.",
  kind: "admin",
  actors: ["human"],
  input: z.object({ engagementId, accounts: z.array(TestAccount).max(30).default([]), allowed: z.string().max(4000).default(""), avoid: z.string().max(4000).default(""), noSubdomains: z.boolean().optional().describe("Kept as it was when omitted") }),
  handler: (input, ctx) => {
    const e = ctx.engagement(input.engagementId);
    const known = new Set(e.secrets().map((s) => s.name));
    for (const a of input.accounts) if (a.secret && !known.has(a.secret)) throw new OperationError("UNKNOWN_SECRET", `the secret "${a.secret}" is not saved`);
    const rules: EngagementRules = { accounts: input.accounts, allowed: input.allowed, avoid: input.avoid, noSubdomains: input.noSubdomains ?? rulesOf(e).noSubdomains, updatedAt: new Date().toISOString() };
    e.setMeta("rules", rules, ctx.caller.actor);
    return rules;
  },
});

/** Records that the operator does not want subdomains (wizard choice, or a rejected wildcard). */
export function excludeSubdomains(e: Engagement, actor: Parameters<Engagement["setMeta"]>[2]): void {
  const current = rulesOf(e);
  if (current.noSubdomains) return;
  e.setMeta("rules", { ...current, noSubdomains: true, updatedAt: new Date().toISOString() }, actor);
}
