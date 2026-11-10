import { ImpactQuestionKey, RiskLevel } from "@penteos/schema";
import { z } from "zod";
import { deepeningOf, type Deepening, findingsToDeepen, impactLeads, openDeepening } from "../../impact.js";
import type { RunOutcome } from "../../tools/runner.js";
import { defineOperation, OperationError } from "../registry.js";
import { engagementId, outcome } from "./shared.js";

// ---------------------------------------------------------------------------------------------
// Deepening findings: how far it reaches, what the exposed data allows, what it chains with
// ---------------------------------------------------------------------------------------------

const QUESTION_TEXT: Record<z.infer<typeof ImpactQuestionKey>, string> = {
  reach: "How far does it reach? How many records, organisations or users, measured (not assumed).",
  exposed: "What does the exposed data allow? Each secret, token, account or internal reference: what it opens.",
  chain: "What does it chain with? Another finding or route that this one feeds or makes worse.",
};

defineOperation({
  name: "finding.impact",
  title: "Impact questions of a finding",
  description:
    "The impact questions of a finding (reach, exposed, chain) with their answers, and the leads Penteos computed from its evidence and the graph: the tool and arguments that answer each one. Serious findings get the questions when created; answer them before closing the round.",
  kind: "read",
  actors: ["human", "agent"],
  input: z.object({ engagementId, id: z.string().optional().describe("A finding; omit it to list the findings with open questions") }),
  handler: (input, ctx) => {
    const e = ctx.engagement(input.engagementId);
    if (!input.id) return { findings: findingsToDeepen(e) };
    const f = e.get(input.id);
    if (!f || f.kind !== "finding") throw new OperationError("NOT_FOUND", `finding not found: ${input.id}`);
    const d = deepeningOf(f);
    return {
      id: f.id,
      title: f.attributes.title,
      severity: f.attributes.severity,
      ...(d
        ? { reason: d.reason, questions: d.questions.map((q) => ({ ...q, question: QUESTION_TEXT[q.key] })) }
        : { questions: [], note: "No impact questions are open on this finding (open them with finding_deepen if its impact is worth measuring)." }),
      leads: impactLeads(e, f),
    };
  },
});

defineOperation({
  name: "finding.deepen",
  title: "Open the impact questions of a finding",
  description: "Opens the three impact questions (reach, exposed, chain) on a finding that does not have them, with the reason. Penteos opens them by itself on high and critical findings and on exposure or access-control ones.",
  kind: "write",
  actors: ["human", "agent"],
  input: z.object({ engagementId, id: z.string(), reason: z.string().min(3).max(300) }),
  handler: (input, ctx) => {
    const e = ctx.engagement(input.engagementId);
    const f = e.get(input.id);
    if (!f || f.kind !== "finding") throw new OperationError("NOT_FOUND", `finding not found: ${input.id}`);
    if (deepeningOf(f)) return { status: "already_open", questions: deepeningOf(f)!.questions };
    if (!openDeepening(e, input.id, ctx.caller.actor, input.reason)) throw new OperationError("VALIDATION_ERROR", "this finding is closed");
    return { status: "opened", leads: impactLeads(e, e.get(input.id)!) };
  },
});

defineOperation({
  name: "finding.answer_impact",
  title: "Answer an impact question",
  description:
    "Records what was established about one impact question of a finding. answered: what was found, with the evidence that shows it (required for reach and exposed: a measure, a response, a log). not_applicable: why it does not apply and what was checked (e.g. 'no secrets in the response; fields are public catalogue data'). The answer goes into the report as demonstrated impact. If what you found changes the severity, update the finding too.",
  kind: "write",
  actors: ["human", "agent"],
  input: z.object({
    engagementId,
    id: z.string(),
    key: ImpactQuestionKey,
    status: z.enum(["answered", "not_applicable", "open"]),
    answer: z.string().min(20).max(3000).optional(),
    evidenceIds: z.array(z.string()).max(20).default([]),
  }),
  handler: (input, ctx) => {
    const e = ctx.engagement(input.engagementId);
    const f = e.get(input.id);
    if (!f || f.kind !== "finding") throw new OperationError("NOT_FOUND", `finding not found: ${input.id}`);
    const agent = ctx.caller.actor.type === "agent";
    if (agent && ["fixed", "wont_fix", "not_verifiable", "reported"].includes(String(f.attributes.status))) throw new OperationError("PERMISSION_DENIED", "this finding is closed or already reported");
    const d = deepeningOf(f);
    if (!d) throw new OperationError("VALIDATION_ERROR", "this finding has no impact questions; open them first with finding_deepen");
    if (input.status !== "open" && !input.answer) throw new OperationError("VALIDATION_ERROR", "say what was found (answered) or why it does not apply and what was checked (not_applicable)");
    if (agent && input.status === "answered" && input.key !== "chain" && !input.evidenceIds.length) {
      throw new OperationError("VALIDATION_ERROR", `an answer about ${input.key} needs the evidence that shows it (evidence_from_raw on the measure or the response first)`);
    }
    for (const id of input.evidenceIds) if (e.get(id)?.kind !== "evidence") throw new OperationError("NOT_FOUND", `evidence not found: ${id}`);
    const deepening: Deepening = {
      ...d,
      questions: d.questions.map((q) =>
        q.key === input.key
          ? { key: q.key, status: input.status, ...(input.answer ? { answer: input.answer } : {}), evidenceIds: input.evidenceIds, by: ctx.caller.actor, at: new Date().toISOString() }
          : q,
      ),
    };
    // The evidence of the impact is evidence of the finding too.
    const evidenceIds = [...new Set([...((f.attributes.evidenceIds as string[] | undefined) ?? []), ...input.evidenceIds])];
    e.editEntity(input.id, { deepening, evidenceIds }, ctx.caller.actor);
    const left = deepening.questions.filter((q) => q.status === "open").map((q) => q.key);
    return { status: "recorded", open: left, ...(left.length ? {} : { note: "All impact questions are answered. If the reach or the chain changes the severity, update it (finding_update) and the CVSS." }) };
  },
});

defineOperation({
  name: "web.measure_enumeration",
  title: "Measure how many records a route opens",
  description:
    "Measures the reach of a route with an identifier (/api/tenants/{id}, /api/users/:id): read-only GETs on identifiers, told apart from what a missing record looks like. With integers it finds the highest id and the density and estimates the total (exact when every id fits in the budget); with values it tries the given slugs or codes. Returns the count, ids that answered, field names of a record (never values) and rawIds for evidence. Use it to answer the reach question of a finding instead of reading records one by one. header (optional) measures as a given user.",
  kind: "target",
  actors: ["human", "agent"],
  input: z.object({
    engagementId,
    origin: z.string().url(),
    template: z.string().min(2).describe("Route with one placeholder: /api/tenants/{id}"),
    header: z.string().optional().describe('A header to send, e.g. "Authorization: Bearer {{secret:user_a}}"'),
    values: z.array(z.string().min(1).max(200)).max(500).optional().describe("Identifiers to try when they are not integers (slugs, codes)"),
    maxRequests: z.number().int().min(20).max(500).default(120),
    risk: RiskLevel.default("active"),
  }),
  handler: async (input, ctx) => {
    let result: RunOutcome;
    try {
      result = await ctx.runner(input.engagementId).measureEnumeration(
        { origin: input.origin, template: input.template, ...(input.header ? { header: input.header } : {}), ...(input.values?.length ? { values: input.values } : {}), maxRequests: input.maxRequests, risk: input.risk },
        { ...ctx.caller, origin: ctx.caller.actor.type === "agent" ? "agent_tool" : "runner" },
      );
    } catch (e) {
      if (e instanceof OperationError) throw e;
      throw new OperationError("VALIDATION_ERROR", (e as Error).message);
    }
    return outcome(result, ctx);
  },
});
