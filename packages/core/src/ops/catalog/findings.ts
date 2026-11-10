import { defineOperation, OperationError } from "../registry.js";
import { Severity, ulid } from "@penteos/schema";
import { z } from "zod";
import type { ReplaceRule } from "../../proxy/intercept.js";
import { engagementId, untrusted } from "./shared.js";
import { openDeepening } from "../../impact.js";

// ---------------------------------------------------------------------------------------------
// findings / evidence
// ---------------------------------------------------------------------------------------------

defineOperation({
  name: "evidence.from_raw",
  title: "Evidence from output",
  description: "Creates evidence from a fragment of a raw artifact (byte range).",
  kind: "write",
  actors: ["human", "agent"],
  input: z.object({
    engagementId,
    rawId: z.string(),
    caption: z.string().min(1),
    range: z.object({ start: z.number().int().min(0), end: z.number().int().min(0) }).optional(),
  }),
  handler: (input, ctx) => {
    const e = ctx.engagement(input.engagementId);
    // Evidence pointing to an output that does not exist proves nothing: refuse it up front.
    if (!e.hasRaw(input.rawId)) throw new OperationError("NOT_FOUND", `raw artifact not found: ${input.rawId}. Use the rawId a run, http_send or raw_get returned (sha256:…).`);
    return e.createEntity(
      "evidence",
      {
        caption: input.caption,
        source: { type: "raw_excerpt", rawId: input.rawId, ...(input.range ? { range: input.range } : {}) },
        capturedAt: new Date().toISOString(),
      },
      ctx.caller.actor,
    );
  },
});

defineOperation({
  name: "finding.create",
  title: "Create finding",
  description: "Creates a finding in draft status, with affected entities and evidence.",
  kind: "write",
  actors: ["human", "agent"],
  input: z.object({
    engagementId,
    title: z.string().min(1),
    severity: Severity,
    description: z.string().optional(),
    impact: z.string().optional(),
    remediation: z.string().optional(),
    instances: z.array(z.object({ entityId: z.string(), location: z.string().optional() })).default([]),
    evidenceIds: z.array(z.string()).default([]),
    cwe: z.array(z.string().regex(/^CWE-\d+$/)).optional(),
    references: z.array(z.string()).optional(),
  }),
  handler: (input, ctx) => {
    const e = ctx.engagement(input.engagementId);
    const instances = input.instances.map((i) => {
      const entity = e.get(i.entityId);
      if (!entity) throw new OperationError("NOT_FOUND", `entity not found: ${i.entityId}`);
      return { id: ulid(), entity: { kind: entity.kind, id: entity.id }, ...(i.location ? { location: i.location } : {}), status: "open" as const, observationIds: [] };
    });
    const created = e.createEntity(
      "finding",
      {
        title: input.title,
        severity: input.severity,
        ...(input.description ? { description: input.description } : {}),
        ...(input.impact ? { impact: input.impact } : {}),
        ...(input.remediation ? { remediation: input.remediation } : {}),
        instances,
        evidenceIds: input.evidenceIds,
        ...(input.cwe ? { cwe: input.cwe } : {}),
        ...(input.references ? { references: input.references } : {}),
        owner: ctx.caller.actor,
      },
      ctx.caller.actor,
    );
    // A serious finding is where the work starts: its impact questions open with it.
    return openDeepening(e, created.id, ctx.caller.actor) ? e.get(created.id)! : created;
  },
});

export const FindingText = {
  description: z.string().optional(),
  impact: z.string().optional(),
  remediation: z.string().optional(),
  reproduction: z.string().max(20_000).optional().describe("Steps to reproduce it, numbered, exact (requests, parameters, what to look for): the technical report shows them."),
  cwe: z.array(z.string().regex(/^CWE-\d+$/)).optional(),
  references: z.array(z.string()).optional(),
  cvss: z.object({ version: z.enum(["4.0", "3.1"]), vector: z.string(), score: z.number().min(0).max(10) }).optional(),
};

defineOperation({
  name: "observation.promote",
  title: "Promote observations to a finding",
  description:
    "Turns one or more observations backed by evidence into a DRAFT finding: the affected assets come from the observations, which are marked as confirmed and linked. Attach evidence (evidence_from_raw first). A human reviews and approves findings.",
  kind: "write",
  actors: ["human", "agent"],
  input: z.object({
    engagementId,
    observationIds: z.array(z.string()).min(1),
    title: z.string().min(1),
    severity: Severity,
    evidenceIds: z.array(z.string()).default([]),
    ...FindingText,
  }),
  handler: (input, ctx) => {
    const e = ctx.engagement(input.engagementId);
    const observations = input.observationIds.map((id) => {
      const o = e.get(id);
      if (!o || o.kind !== "observation") throw new OperationError("NOT_FOUND", `observation not found: ${id}`);
      return o;
    });
    const seen = new Set<string>();
    const instances = observations.flatMap((o) =>
      ((o.attributes.affects as Array<{ kind: string; id: string }>) ?? [])
        .filter((ref) => !seen.has(ref.id) && seen.add(ref.id))
        .map((ref) => ({
          id: ulid(),
          entity: ref,
          ...(o.attributes.location ? { location: String(o.attributes.location) } : {}),
          status: "open" as const,
          observationIds: observations.filter((x) => (x.attributes.affects as Array<{ id: string }>).some((r) => r.id === ref.id)).map((x) => x.id),
        })),
    );
    const { engagementId: _e, observationIds: _o, ...fields } = input;
    const finding = e.createEntity("finding", { ...fields, instances, owner: ctx.caller.actor }, ctx.caller.actor);
    for (const o of observations) e.editEntity(o.id, { triage: "confirmed", findingId: finding.id }, ctx.caller.actor);
    return openDeepening(e, finding.id, ctx.caller.actor) ? e.get(finding.id)! : finding;
  },
});

defineOperation({
  name: "observation.triage",
  title: "Classify observations you will not report",
  description:
    "Gives a disposition to observations that will NOT become findings, so nothing sits unreviewed: false_positive (not real - say why), duplicate (already covered by another observation or finding), accepted_risk (real but the client accepts it). One reason line for all of them. For the real ones, promote them instead (observation_promote) so the verifier checks them. Do this before closing a round: a round does not close with high-signal observations left untouched.",
  kind: "write",
  actors: ["human", "agent"],
  input: z.object({
    engagementId,
    ids: z.array(z.string()).min(1).max(200),
    triage: z.enum(["false_positive", "duplicate", "accepted_risk", "new"]),
    reason: z.string().min(1).max(400),
  }),
  handler: (input, ctx) => {
    const e = ctx.engagement(input.engagementId);
    let count = 0;
    for (const id of input.ids) {
      const o = e.get(id);
      if (!o || o.kind !== "observation") throw new OperationError("NOT_FOUND", `observation not found: ${id}`);
      if (o.attributes.findingId) continue; // one that became a finding is not re-triaged here
      e.editEntity(id, { triage: input.triage, triageReason: input.reason }, ctx.caller.actor);
      count++;
    }
    return { status: "triaged", count };
  },
});

defineOperation({
  name: "finding.update",
  title: "Edit finding",
  description: "Edits the text of a finding (title, severity, description, impact, remediation, steps to reproduce, CWE, CVSS, references), adds evidence, or takes off evidence attached by mistake (removeEvidenceIds: it stays in the project and the audit log, only no longer backs this finding; at least one must remain).",
  kind: "write",
  actors: ["human", "agent"],
  input: z.object({ engagementId, id: z.string(), title: z.string().min(1).optional(), severity: Severity.optional(), addEvidenceIds: z.array(z.string()).optional(), removeEvidenceIds: z.array(z.string()).optional(), ...FindingText }),
  handler: (input, ctx) => {
    const e = ctx.engagement(input.engagementId);
    const finding = e.get(input.id);
    if (!finding || finding.kind !== "finding") throw new OperationError("NOT_FOUND", `finding not found: ${input.id}`);
    if (ctx.caller.actor.type === "agent" && !["draft", "in_review"].includes(String(finding.attributes.status))) {
      throw new OperationError("PERMISSION_DENIED", "agents can only edit findings in draft or in review");
    }
    const { engagementId: _e, id: _id, addEvidenceIds, removeEvidenceIds, ...fields } = input;
    const changes: Record<string, unknown> = Object.fromEntries(Object.entries(fields).filter(([, v]) => v !== undefined));
    const current = (finding.attributes.evidenceIds as string[]) ?? [];
    if (addEvidenceIds?.length || removeEvidenceIds?.length) {
      const unknown = (removeEvidenceIds ?? []).filter((id) => !current.includes(id));
      if (unknown.length) throw new OperationError("VALIDATION_ERROR", `not evidence of this finding: ${unknown.join(", ")}`);
      const next = [...new Set([...current, ...(addEvidenceIds ?? [])])].filter((id) => !(removeEvidenceIds ?? []).includes(id));
      // No proof, no finding: what remains has to show it.
      if (next.length === 0 && current.length > 0) throw new OperationError("VALIDATION_ERROR", "a finding keeps at least one piece of evidence: add the right one in the same call (addEvidenceIds) before taking the wrong one off");
      changes.evidenceIds = next;
    }
    const edited = e.editEntity(input.id, changes, ctx.caller.actor);
    // Raised to high, or now recognised as an exposure: its impact questions open.
    return openDeepening(e, input.id, ctx.caller.actor) ? e.get(input.id)! : edited;
  },
});

defineOperation({
  name: "finding.set_instances",
  title: "Set affected entities",
  description: "Replaces the entities a finding affects (the hosts, endpoints or applications where it occurs), with the same shape as finding_create: [{ entityId, location? }]. An agent must leave at least one.",
  kind: "write",
  actors: ["human", "agent"],
  input: z.object({ engagementId, id: z.string(), instances: z.array(z.object({ entityId: z.string(), location: z.string().optional() })) }),
  handler: (input, ctx) => {
    const e = ctx.engagement(input.engagementId);
    const finding = e.get(input.id);
    if (!finding || finding.kind !== "finding") throw new OperationError("NOT_FOUND", `finding not found: ${input.id}`);
    const agent = ctx.caller.actor.type === "agent";
    if (agent && !["draft", "in_review"].includes(String(finding.attributes.status))) {
      throw new OperationError("PERMISSION_DENIED", "agents can only edit findings in draft or in review");
    }
    if (agent && input.instances.length === 0) {
      throw new OperationError("VALIDATION_ERROR", "a finding must name at least one affected entity; to drop a wrong one, send the right ones");
    }
    // Keep the id, status and observations of an instance that stays.
    const before = (finding.attributes.instances as Array<{ id: string; entity: { id: string }; location?: string; status: string; observationIds: string[] }> | undefined) ?? [];
    const instances = input.instances.map((i) => {
      const entity = e.get(i.entityId);
      if (!entity) throw new OperationError("NOT_FOUND", `entity not found: ${i.entityId}`);
      const kept = before.find((b) => b.entity.id === entity.id && (b.location ?? "") === (i.location ?? ""));
      return kept ?? { id: ulid(), entity: { kind: entity.kind, id: entity.id }, ...(i.location ? { location: i.location } : {}), status: "open" as const, observationIds: [] };
    });
    return e.editEntity(input.id, { instances }, ctx.caller.actor);
  },
});

defineOperation({
  name: "finding.request_approval",
  title: "Ask to approve findings",
  description:
    "Puts the findings you consider ready for the report in front of the operator as one decision card: they approve all, some or none (the rest stay in review). Only a human approves findings; use this instead of asking in a task or in the chat. A new request replaces the previous one. Prefer findings the verifier reproduced; say in reason anything the operator should weigh.",
  kind: "write",
  actors: ["human", "agent"],
  input: z.object({ engagementId, ids: z.array(z.string()).min(1).max(50), reason: z.string().min(1) }),
  handler: (input, ctx) => {
    try {
      const a = ctx.runner(input.engagementId).proposeFindings(input.ids, input.reason, ctx.caller.actor);
      return { status: "pending_approval", approvalId: a.id, findings: input.ids.length };
    } catch (e) {
      throw new OperationError(/not found/.test((e as Error).message) ? "NOT_FOUND" : "VALIDATION_ERROR", (e as Error).message);
    }
  },
});

defineOperation({
  name: "finding.set_status",
  title: "Change finding status",
  description: "Moves a finding through its workflow. Agents may move it between draft and in_review; approving, reporting and closing are human decisions.",
  kind: "write",
  actors: ["human", "agent"],
  input: z.object({
    engagementId,
    id: z.string(),
    status: z.enum(["draft", "in_review", "approved", "reported", "fixed", "partially_fixed", "not_fixed", "not_verifiable", "reopened", "wont_fix"]),
  }),
  handler: (input, ctx) => {
    if (ctx.caller.actor.type === "agent" && !["draft", "in_review"].includes(input.status)) {
      throw new OperationError("PERMISSION_DENIED", "only a human can approve or close a finding");
    }
    const e = ctx.engagement(input.engagementId);
    const finding = e.get(input.id);
    if (!finding || finding.kind !== "finding") throw new OperationError("NOT_FOUND", `finding not found: ${input.id}`);
    const edited = e.editEntity(input.id, { status: input.status, ...(ctx.caller.actor.type === "human" && input.status === "approved" ? { reviewer: ctx.caller.actor } : {}) }, ctx.caller.actor);
    // Going to review is when a second pair of eyes tries to reproduce it (if there is a verifier).
    const v = finding.attributes.verification as { state?: string } | undefined;
    if (input.status === "in_review" && (!v || v.state === "failed")) ctx.verifier?.request(e.info.id, input.id, ctx.caller.actor, true);
    return edited;
  },
});

defineOperation({
  name: "finding.request_verification",
  title: "Verify a finding independently",
  description:
    "Asks the independent verifier to reproduce a finding: a separate agent that did not see how it was found tries to reproduce it from its description and evidence, and records a verdict (reproduced / not reproduced / inconclusive) with its own evidence. It also starts by itself when a finding goes to in_review. You hear the verdict as news.",
  kind: "write",
  actors: ["human", "agent"],
  input: z.object({ engagementId, id: z.string() }),
  handler: (input, ctx) => {
    const e = ctx.engagement(input.engagementId);
    const finding = e.get(input.id);
    if (!finding || finding.kind !== "finding") throw new OperationError("NOT_FOUND", `finding not found: ${input.id}`);
    const v = finding.attributes.verification as { state?: string } | undefined;
    if (v && (v.state === "pending" || v.state === "running")) return { status: "already_verifying" };
    if (!ctx.verifier) throw new OperationError("VALIDATION_ERROR", "the verifier runs with the agents (desktop app or team server)");
    const r = ctx.verifier.request(e.info.id, input.id, ctx.caller.actor, false);
    if (!r.ok) throw new OperationError("VALIDATION_ERROR", r.reason);
    return { status: "requested" };
  },
});

defineOperation({
  name: "finding.verdict",
  title: "Record the verification verdict",
  description:
    "The verdict of an independent verification: reproduced, not_reproduced or inconclusive, with a short factual summary of what was tried and what happened, and the evidence of the reproduction. Agents can only do this as the verifier assigned to that finding.",
  kind: "write",
  actors: ["human", "agent"],
  input: z.object({
    engagementId,
    id: z.string(),
    verdict: z.enum(["reproduced", "not_reproduced", "inconclusive"]),
    summary: z.string().min(1).max(4000),
    evidenceIds: z.array(z.string()).max(20).default([]),
  }),
  handler: (input, ctx) => {
    const e = ctx.engagement(input.engagementId);
    const finding = e.get(input.id);
    if (!finding || finding.kind !== "finding") throw new OperationError("NOT_FOUND", `finding not found: ${input.id}`);
    const v = finding.attributes.verification as { state?: string; by?: { id: string }; requestedBy?: unknown; requestedAt?: string } | undefined;
    if (ctx.caller.actor.type === "agent" && !(v?.state === "running" && v.by?.id === ctx.caller.actor.id)) {
      throw new OperationError("PERMISSION_DENIED", "only the verifier assigned to this finding can record its verdict");
    }
    for (const id of input.evidenceIds) if (e.get(id)?.kind !== "evidence") throw new OperationError("NOT_FOUND", `evidence not found: ${id}`);
    const verification = {
      state: "done",
      verdict: input.verdict,
      summary: input.summary,
      by: ctx.caller.actor,
      requestedBy: v?.requestedBy ?? ctx.caller.actor,
      requestedAt: v?.requestedAt ?? new Date().toISOString(),
      at: new Date().toISOString(),
      evidenceIds: input.evidenceIds,
    };
    const edited = e.editEntity(input.id, { verification }, ctx.caller.actor);
    e.emit({ type: "verification.done", findingId: input.id, title: String(finding.attributes.title), verdict: input.verdict, summary: input.summary });
    return edited;
  },
});

defineOperation({
  name: "evidence.get",
  title: "Get evidence",
  description: "An evidence item with the excerpt of raw output it points to.",
  kind: "read",
  actors: ["human", "agent"],
  input: z.object({ engagementId, id: z.string() }),
  handler: (input, ctx) => {
    const e = ctx.engagement(input.engagementId);
    const ev = e.get(input.id);
    if (!ev || ev.kind !== "evidence") throw new OperationError("NOT_FOUND", `evidence not found: ${input.id}`);
    const src = ev.attributes.source as { rawId: string; range?: { start: number; end: number } };
    let excerpt = "";
    try {
      const raw = e.readRaw(src.rawId);
      excerpt = (src.range ? raw.subarray(src.range.start, src.range.end) : raw.subarray(0, 4000)).toString("utf8");
    } catch {
      excerpt = "";
    }
    return { ...ev, excerpt: untrusted(ctx, excerpt) };
  },
});
