import { FindingText } from "./findings.js";
import { Severity } from "@penteos/schema";
import { z } from "zod";
import { FindingLibrary, FindingTemplate, templateId } from "../../library.js";
import { defineOperation, executeOperation, OperationError, type OperationContext } from "../registry.js";
import type { ReplaceRule } from "../../proxy/intercept.js";
import { engagementId } from "./shared.js";

// ---------------------------------------------------------------------------------------------
// findings library
// ---------------------------------------------------------------------------------------------

const builtinLibrary = new FindingLibrary();
const libraryOf = (ctx: OperationContext) => ctx.library ?? builtinLibrary;

defineOperation({
  name: "library.list",
  title: "Findings library",
  description: "Reusable finding write-ups (title, severity, CWE, description, impact, remediation, references). Search it before writing a finding from scratch.",
  kind: "read",
  actors: ["human", "agent"],
  input: z.object({ query: z.string().optional() }),
  handler: (input, ctx) => libraryOf(ctx).list(input.query).map((t) => ({ id: t.id, title: t.title, severity: t.severity, cwe: t.cwe, tags: t.tags, source: t.source })),
});

defineOperation({
  name: "library.get",
  title: "Finding template",
  description: "Full text of a template from the findings library.",
  kind: "read",
  actors: ["human", "agent"],
  input: z.object({ id: z.string() }),
  handler: (input, ctx) => {
    const t = libraryOf(ctx).get(input.id);
    if (!t) throw new OperationError("NOT_FOUND", `template not found: ${input.id}`);
    return t;
  },
});

defineOperation({
  name: "library.save",
  title: "Save to library",
  description: "Saves a template to the organization's findings library, either written directly or taken from an existing finding (its client-specific details should be generalized first).",
  kind: "write",
  actors: ["human"],
  input: z.object({ engagementId, template: FindingTemplate.partial({ id: true }).optional(), fromFindingId: z.string().optional() }),
  handler: (input, ctx) => {
    let base: Record<string, unknown> = { ...(input.template ?? {}) };
    if (input.fromFindingId) {
      const f = ctx.engagement(input.engagementId).get(input.fromFindingId);
      if (!f || f.kind !== "finding") throw new OperationError("NOT_FOUND", `finding not found: ${input.fromFindingId}`);
      const a = f.attributes;
      base = { title: a.title, severity: a.severity, cwe: a.cwe, description: a.description, impact: a.impact, remediation: a.remediation, references: a.references, ...base };
    }
    if (!base.title) throw new OperationError("VALIDATION_ERROR", "a template needs at least a title");
    return libraryOf(ctx).save({ id: base.id ?? templateId(String(base.title)), ...base });
  },
});

defineOperation({
  name: "finding.from_template",
  title: "Finding from template",
  description:
    "Creates a DRAFT finding from a library template, adapted to this case: pass the observations it confirms (or the affected entities), the evidence, and overrides for anything specific (title, severity, description…). Prefer this over writing from scratch when a template fits.",
  kind: "write",
  actors: ["human", "agent"],
  input: z.object({
    engagementId,
    templateId: z.string(),
    observationIds: z.array(z.string()).default([]),
    instances: z.array(z.object({ entityId: z.string(), location: z.string().optional() })).default([]),
    evidenceIds: z.array(z.string()).default([]),
    title: z.string().optional(),
    severity: Severity.optional(),
    ...FindingText,
  }),
  handler: async (input, ctx) => {
    const t = libraryOf(ctx).get(input.templateId);
    if (!t) throw new OperationError("NOT_FOUND", `template not found: ${input.templateId}`);
    const pick = <T,>(override: T | undefined, base: T) => (override === undefined || override === "" ? base : override);
    const fields = {
      engagementId: input.engagementId,
      title: pick(input.title, t.title),
      severity: pick(input.severity, t.severity),
      description: pick(input.description, t.description),
      impact: pick(input.impact, t.impact),
      remediation: pick(input.remediation, t.remediation),
      cwe: pick(input.cwe, t.cwe),
      references: pick(input.references, t.references),
      evidenceIds: input.evidenceIds,
    };
    const finding = (input.observationIds.length
      ? await executeOperation("observation.promote", { ...fields, observationIds: input.observationIds }, ctx)
      : await executeOperation("finding.create", { ...fields, instances: input.instances }, ctx)) as { id: string };
    return ctx.engagement(input.engagementId).editEntity(finding.id, { templateRef: t.id }, ctx.caller.actor);
  },
});
