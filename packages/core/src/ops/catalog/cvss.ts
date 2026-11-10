import { defineOperation, OperationError } from "../registry.js";
import { z } from "zod";
import { type ReportDraft } from "../../report.js";
import { scoreCvss } from "../../cvss.js";
import type { ReplaceRule } from "../../proxy/intercept.js";
import { engagementId } from "./shared.js";

// ---------------------------------------------------------------------------------------------
// CVSS and report sections

defineOperation({
  name: "cvss.score",
  title: "Score a CVSS vector",
  description: "Computes the score and severity of a CVSS 4.0 or 3.1 vector.",
  kind: "read",
  actors: ["human", "agent"],
  input: z.object({ vector: z.string().min(9) }),
  handler: (input) => {
    try {
      return scoreCvss(input.vector);
    } catch (e) {
      throw new OperationError("VALIDATION_ERROR", (e as Error).message);
    }
  },
});

defineOperation({
  name: "finding.set_cvss",
  title: "Set the CVSS of a finding",
  description:
    "Sets a finding's CVSS vector (4.0 preferred, 3.1 accepted); Penteos computes the score. Returns the severity the score suggests: the finding's severity is not changed automatically.",
  kind: "write",
  actors: ["human", "agent"],
  input: z.object({ engagementId, id: z.string(), vector: z.string().min(9) }),
  handler: (input, ctx) => {
    const e = ctx.engagement(input.engagementId);
    const f = e.get(input.id);
    if (!f || f.kind !== "finding") throw new OperationError("NOT_FOUND", `finding ${input.id} not found`);
    let s;
    try {
      s = scoreCvss(input.vector);
    } catch (err) {
      throw new OperationError("VALIDATION_ERROR", (err as Error).message);
    }
    const updated = e.editEntity(input.id, { cvss: { version: s.version, vector: s.vector, score: s.score } }, ctx.caller.actor);
    return { finding: updated, score: s.score, suggestedSeverity: s.severity, severity: updated.attributes.severity };
  },
});

defineOperation({
  name: "report.set_section",
  title: "Write a report section",
  description:
    "Writes a section of the deliverable in markdown: executiveSummary (non-technical reader) or conclusion.",
  kind: "write",
  actors: ["human", "agent"],
  input: z.object({ engagementId, section: z.enum(["executiveSummary", "conclusion"]), text: z.string().max(40_000) }),
  handler: (input, ctx) => {
    const e = ctx.engagement(input.engagementId);
    const draft: ReportDraft = { ...(e.getMeta<ReportDraft>("report") ?? {}), [input.section]: input.text, updatedAt: new Date().toISOString() };
    e.setMeta("report", draft, ctx.caller.actor);
    return draft;
  },
});
