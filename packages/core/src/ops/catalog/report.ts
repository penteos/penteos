import { defineOperation } from "../registry.js";
import { z } from "zod";
import { readiness, type ReportDraft } from "../../report.js";
import type { ReplaceRule } from "../../proxy/intercept.js";
import { engagementId } from "./shared.js";

// ---------------------------------------------------------------------------------------------
// report
// ---------------------------------------------------------------------------------------------

defineOperation({
  name: "report.get",
  title: "Deliverable status",
  description: "The report draft (executive summary) and what is missing to deliver: findings by status, findings without evidence or remediation.",
  kind: "read",
  actors: ["human", "agent"],
  input: z.object({ engagementId }),
  handler: (input, ctx) => {
    const e = ctx.engagement(input.engagementId);
    return { draft: e.getMeta<ReportDraft>("report") ?? {}, readiness: readiness(e) };
  },
});

defineOperation({
  name: "report.set_summary",
  title: "Set executive summary",
  description: "Writes the executive summary of the report (markdown, for a non-technical reader: overall risk, most important findings, priorities). The operator can edit it afterwards.",
  kind: "write",
  actors: ["human", "agent"],
  input: z.object({ engagementId, executiveSummary: z.string().max(20_000) }),
  handler: (input, ctx) => {
    const e = ctx.engagement(input.engagementId);
    const draft: ReportDraft = { ...(e.getMeta<ReportDraft>("report") ?? {}), executiveSummary: input.executiveSummary, updatedAt: new Date().toISOString() };
    e.setMeta("report", draft, ctx.caller.actor);
    return draft;
  },
});
