import { defineOperation, OperationError } from "../registry.js";
import { existsSync } from "node:fs";
import { basename, join } from "node:path";
import { getBaseline, linkBaseline, readDocumentText, setBaseline } from "../../baseline.js";
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
  name: "baseline.read_document",
  title: "Read a previous assessment's report",
  description:
    "Reads the text of a previous report of this client (PDF, Word .docx, Markdown or text) so its findings can be loaded as the baseline (baseline_set). The operator puts the file in the project's inputs/ folder (you read only from there; a person may give any path). Then extract each finding faithfully: its own reference (M1, A3…), title, severity, asset and a one-line summary - never invent or merge them.",
  kind: "read",
  actors: ["human", "agent"],
  input: z.object({ engagementId, file: z.string().min(1).describe("A file name in the project's inputs/ folder, or (a person) a full path") }),
  handler: (input, ctx) => {
    const e = ctx.engagement(input.engagementId);
    const inputs = join(e.dir, "inputs");
    const file = ctx.caller.actor.type === "agent" || !input.file.startsWith("/") ? join(inputs, basename(input.file)) : input.file;
    if (!existsSync(file)) throw new OperationError("NOT_FOUND", `${file} does not exist${ctx.caller.actor.type === "agent" ? ` (ask the operator to put the report in ${inputs})` : ""}`);
    try {
      const { text, method } = readDocumentText(file);
      return { file, method, characters: text.length, text: text.slice(0, 200_000), ...(text.length > 200_000 ? { note: "Truncated at 200,000 characters: the findings tables are usually early; ask for the rest if needed." } : {}) };
    } catch (err) {
      throw new OperationError("VALIDATION_ERROR", (err as Error).message);
    }
  },
});

const BaselineFindingInput = z.object({
  ref: z.string().min(1).max(30),
  title: z.string().min(1).max(300),
  severity: z.enum(["critical", "high", "medium", "low", "info"]),
  asset: z.string().max(200).optional(),
  summary: z.string().max(600).optional(),
});

defineOperation({
  name: "baseline.set",
  title: "Load a previous assessment as the baseline",
  description: "Loads the findings of a previous assessment (read with baseline_read_document) as this one's baseline. Then each gets a status with baseline_link: still_open (with the finding of this assessment that confirms it), fixed (re-tested, gone - say how) or not_retested (with why). The report then says what was fixed, what remains and what is new. Re-loading keeps the statuses already given.",
  kind: "write",
  actors: ["human", "agent"],
  input: z.object({ engagementId, source: z.string().min(1).max(200).describe("Which report: who did it, its date or title"), date: z.string().max(40).optional(), findings: z.array(BaselineFindingInput).min(1).max(300) }),
  handler: (input, ctx) => {
    const refs = input.findings.map((f) => f.ref);
    if (new Set(refs).size !== refs.length) throw new OperationError("VALIDATION_ERROR", "each finding needs its own ref");
    const b = setBaseline(ctx.engagement(input.engagementId), { source: input.source, ...(input.date ? { date: input.date } : {}), findings: input.findings }, ctx.caller.actor);
    return { loaded: b.findings.length, undecided: b.findings.filter((f) => !f.status).length };
  },
});

defineOperation({
  name: "baseline.link",
  title: "Give a previous finding its status",
  description: "Says what happened to a finding of the previous assessment: still_open (findingId: this assessment's finding that confirms it), fixed (you re-tested it and it is gone: say how in the note) or not_retested (why: out of this round's scope, needs an account…). A round does not close with previous findings without a status.",
  kind: "write",
  actors: ["human", "agent"],
  input: z.object({ engagementId, ref: z.string().min(1), status: z.enum(["still_open", "fixed", "not_retested"]), findingId: z.string().optional(), note: z.string().max(800).optional() }),
  handler: (input, ctx) => {
    const e = ctx.engagement(input.engagementId);
    if (input.status === "still_open" && !input.findingId) throw new OperationError("VALIDATION_ERROR", "still_open needs the findingId of this assessment's finding that confirms it");
    if (input.status !== "still_open" && !input.note?.trim()) throw new OperationError("VALIDATION_ERROR", `${input.status} needs a note: how it was re-tested, or why it was not`);
    if (input.findingId && e.get(input.findingId)?.kind !== "finding") throw new OperationError("NOT_FOUND", `finding not found: ${input.findingId}`);
    try {
      return linkBaseline(e, input.ref, { status: input.status, ...(input.findingId ? { findingId: input.findingId } : {}), ...(input.note ? { note: input.note } : {}) }, ctx.caller.actor);
    } catch (err) {
      throw new OperationError("NOT_FOUND", (err as Error).message);
    }
  },
});

defineOperation({
  name: "baseline.get",
  title: "The previous assessment's baseline",
  description: "The previous assessment's findings loaded as the baseline, with each one's status.",
  kind: "read",
  actors: ["human", "agent"],
  input: z.object({ engagementId }),
  handler: (input, ctx) => getBaseline(ctx.engagement(input.engagementId)) ?? { findings: [] },
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
