import { defineOperation, OperationError } from "../registry.js";
import { z } from "zod";
import { Branding, reportReadiness, DELIVERABLE_STATUSES, renderReport, type ReportDraft } from "../../report.js";
import { reportToHtml } from "../../report-html.js";
import type { Engagement } from "../../engagement.js";
import { ulid } from "@penteos/schema";
import { REPORT_TEXT } from "../../report-text.js";
import { reportToDocx } from "../../docx.js";
import type { ReplaceRule } from "../../proxy/intercept.js";
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { engagementId } from "./shared.js";
import { restore } from "../../privacy/vault.js";

// ---------------------------------------------------------------------------------------------
// team
// ---------------------------------------------------------------------------------------------

defineOperation({
  name: "team.list",
  title: "Team",
  description: "Operators of this team server, their roles and whether they are connected.",
  kind: "read",
  actors: ["human"],
  input: z.object({}),
  handler: (_input, ctx) => ({ operators: ctx.workspace.operators(), online: ctx.presence?.() ?? [] }),
});

defineOperation({
  name: "team.add",
  title: "Add operator",
  description: "Creates an operator with a role. Returns the access token ONCE: it is not stored in clear.",
  kind: "admin",
  actors: ["human"],
  input: z.object({ name: z.string().min(1).max(60), role: z.enum(["observer", "reviewer", "operator", "lead"]) }),
  handler: (input, ctx) => {
    if (ctx.workspace.operators().some((o) => o.name.toLowerCase() === input.name.toLowerCase())) {
      throw new OperationError("CONFLICT", `there is already an operator called ${input.name}`);
    }
    return ctx.workspace.addOperator(input.name, input.role);
  },
});

defineOperation({
  name: "team.set_disabled",
  title: "Disable operator",
  description: "Disables (or re-enables) an operator: their token stops working immediately.",
  kind: "admin",
  actors: ["human"],
  input: z.object({ id: z.string(), disabled: z.boolean() }),
  handler: (input, ctx) => {
    if (input.disabled) {
      // Never leave the team without anyone who can administer it.
      if (input.id === ctx.caller.actor.id) throw new OperationError("CONFLICT", "you cannot disable yourself");
      const target = ctx.workspace.operators().find((o) => o.id === input.id);
      const activeLeads = ctx.workspace.operators().filter((o) => o.role === "lead" && !o.disabled);
      if (target?.role === "lead" && activeLeads.length <= 1) throw new OperationError("CONFLICT", "this is the last active lead");
    }
    ctx.workspace.setOperatorDisabled(input.id, input.disabled);
    ctx.onOperatorsChanged?.();
    return { id: input.id, disabled: input.disabled };
  },
});

defineOperation({
  name: "branding.get",
  title: "Report branding",
  description: "How reports are signed: company name, logo, color, authors, confidentiality notice.",
  kind: "read",
  actors: ["human", "agent"],
  input: z.object({}),
  handler: (_input, ctx) => ctx.workspace.branding(),
});

defineOperation({
  name: "branding.set",
  title: "Set report branding",
  description: "Sets the company name, logo, color, authors and confidentiality notice used on reports.",
  kind: "admin",
  actors: ["human"],
  input: Branding.partial(),
  handler: (input, ctx) => ctx.workspace.setBranding({ ...ctx.workspace.branding(), ...input }),
});

defineOperation({
  name: "report.render",
  title: "Render report",
  description:
    "Builds the deliverable from the graph: the complete technical report (default) or the executive one, with approved findings and their evidence, scope, methodology, timeline, remediation plan, inventory and traceability. Formats: markdown, html (the print-ready document: preview and PDF) or docx. With includeDrafts it is marked as a draft; with issue it is recorded as a delivered version.",
  kind: "write",
  actors: ["human", "agent"],
  input: z.object({
    engagementId,
    includeDrafts: z.boolean().default(false),
    format: z.enum(["markdown", "docx", "html"]).default("markdown"),
    kind: z.enum(["technical", "executive"]).default("technical"),
    issue: z.boolean().default(false).describe("Record this as a delivered version (with what changed since the previous one)."),
    limitations: z.string().max(4000).optional().describe("Only a person: the limits of this delivery they accept (e.g. 'no test accounts; the back office was out of reach'), to issue it as final with partial coverage. Printed in the report."),
  }),
  handler: async (input, ctx) => {
    const e = ctx.engagement(input.engagementId);
    const info = e.info;
    if (input.limitations?.trim() && ctx.caller.actor.type !== "human") throw new OperationError("PERMISSION_DENIED", "only a person accepts the limits of a delivery");
    // A report is final only when it is: the executive summary written, and the coverage enough to
    // state the overall risk (or its limits accepted by a person). Otherwise it is a draft, on every
    // page, whatever was asked, and the answer says what is missing.
    const { missing, coverage } = reportReadiness(e, input.limitations);
    // Marked a draft (banner, stamp, file name) is not the same as including unapproved findings.
    const asDraft = input.includeDrafts || missing.length > 0;
    const branding = ctx.workspace.branding();
    // Sections plugins enabled in this project add (one that fails is left out and reported).
    const plugins = ctx.pluginRuntime ? await ctx.pluginRuntime.reportSections(e, ctx) : { sections: [], problems: [] };
    const markdown = renderReport(e, { includeDrafts: input.includeDrafts, markDraft: asDraft, extra: plugins.sections, kind: input.kind, ...(input.limitations?.trim() ? { limitations: input.limitations.trim() } : {}), ...(branding.companyName ? { company: branding.companyName } : {}), ...(branding.authors ? { authors: branding.authors } : {}) });
    const pluginSections = { readiness: { final: !asDraft, missing, coverage }, ...(plugins.problems.length ? { pluginProblems: plugins.problems } : {}) };
    // The deliverable carries the real values; what an agent reads back keeps the vault's markers.
    const forPeople = restore(e, markdown).text;
    const date = new Date().toISOString().slice(0, 10);
    const T = REPORT_TEXT[info.language ?? "en"];
    const image = (ref: string) => {
      const mime = e.rawMime(ref) ?? "";
      if (!/^image\//.test(mime)) return undefined;
      try {
        return { data: e.readRaw(ref), mime };
      } catch {
        return undefined;
      }
    };
    const dir = join(e.dir, "reports");
    mkdirSync(dir, { recursive: true });
    const stamp = new Date().toISOString().replace(/[:.]/g, "-");
    const base = `${T.fileName}${input.kind === "executive" ? "-ejecutivo" : ""}-${stamp}${asDraft ? `-${T.draftSuffix}` : ""}`;
    const issued = (format: string, file?: string) => (input.issue || format === "docx" ? recordVersion(e, { kind: input.kind, format, includeDrafts: asDraft, ...(file ? { file } : {}) }) : undefined);
    if (input.format === "docx") {
      const docx = await reportToDocx(forPeople, branding, { client: info.clientName, engagement: info.name, date, draft: asDraft, language: info.language, image });
      const file = join(dir, `${base}.docx`);
      writeFileSync(file, docx, { mode: 0o600 });
      e.audit(ctx.caller.actor, "report.render", { file }, { includeDrafts: input.includeDrafts, format: "docx", kind: input.kind, size: docx.length });
      const version = issued("docx", file);
      return { file, docxBase64: docx.toString("base64"), ...(version ? { version } : {}), ...pluginSections };
    }
    if (input.format === "html") {
      const html = reportToHtml(forPeople, branding, { client: info.clientName, engagement: info.name, date, draft: asDraft, language: info.language, image });
      if (input.issue) e.audit(ctx.caller.actor, "report.render", { kind: input.kind }, { includeDrafts: input.includeDrafts, format: "pdf", kind: input.kind });
      const version = issued("pdf");
      return { html, markdown, fileName: base, ...(version ? { version } : {}), ...pluginSections };
    }
    // Every issued version is kept with the engagement.
    const file = join(dir, `${base}.md`);
    writeFileSync(file, forPeople, { mode: 0o600 });
    e.audit(ctx.caller.actor, "report.render", { file }, { includeDrafts: input.includeDrafts, kind: input.kind, sha: markdown.length });
    const version = issued("markdown", file);
    return {
      markdown,
      file,
      meta: { engagement: info.name, client: info.clientName, mode: info.mode, date, draft: asDraft },
      branding,
      ...(version ? { version } : {}),
      ...pluginSections,
    };
  },
});

// ---------------------------------------------------------------------------------------------
// Delivered versions: what was delivered when, and what changed since the previous one.
// ---------------------------------------------------------------------------------------------

interface ReportVersion {
  id: string;
  at: string;
  kind: "technical" | "executive";
  format: string;
  includeDrafts: boolean;
  label: string;
  file?: string;
  findings: Array<{ id: string; title: string; severity: string; status: string }>;
}

function versionsOf(e: Engagement): ReportVersion[] {
  return e.getState<ReportVersion[]>("report.versions") ?? [];
}

function recordVersion(e: Engagement, v: { kind: "technical" | "executive"; format: string; includeDrafts: boolean; file?: string }): ReportVersion {
  const all = versionsOf(e);
  const draft = e.getMeta<ReportDraft>("report");
  const findings = e
    .query({ kind: "finding", limit: 5000 })
    .filter((f) => v.includeDrafts || DELIVERABLE_STATUSES.has(String(f.attributes.status)))
    .map((f) => ({ id: f.id, title: String(f.attributes.title), severity: String(f.attributes.severity), status: String(f.attributes.status) }));
  const version: ReportVersion = { id: ulid(), at: new Date().toISOString(), kind: v.kind, format: v.format, includeDrafts: v.includeDrafts, label: draft?.version?.trim() || "1.0", ...(v.file ? { file: v.file } : {}), findings };
  e.setState("report.versions", [...all, version].slice(-100));
  return version;
}

function versionDiff(prev: ReportVersion | undefined, cur: ReportVersion) {
  if (!prev) return undefined;
  const before = new Map(prev.findings.map((f) => [f.id, f]));
  const now = new Map(cur.findings.map((f) => [f.id, f]));
  return {
    previous: prev.at,
    added: cur.findings.filter((f) => !before.has(f.id)).map((f) => f.title),
    removed: prev.findings.filter((f) => !now.has(f.id)).map((f) => f.title),
    changed: cur.findings
      .filter((f) => before.has(f.id) && (before.get(f.id)!.severity !== f.severity || before.get(f.id)!.status !== f.status))
      .map((f) => ({ title: f.title, from: `${before.get(f.id)!.severity}/${before.get(f.id)!.status}`, to: `${f.severity}/${f.status}` })),
  };
}

defineOperation({
  name: "report.versions",
  title: "Delivered report versions",
  description: "The versions of the deliverable that were issued (technical or executive, format, date, findings), newest first, each with what changed since the previous one of its kind.",
  kind: "read",
  actors: ["human", "agent"],
  input: z.object({ engagementId }),
  handler: (input, ctx) => {
    const all = versionsOf(ctx.engagement(input.engagementId));
    return {
      versions: all
        .map((v, i) => ({ ...v, findings: v.findings.length, diff: versionDiff([...all.slice(0, i)].reverse().find((p) => p.kind === v.kind), v) }))
        .reverse(),
    };
  },
});

defineOperation({
  name: "report.set_draft",
  title: "Write parts of the report",
  description:
    "Writes the parts of the deliverable people write (markdown, in the project's language): executive summary (for a non-technical reader: overall risk, the most important findings, priorities), conclusion, limitations (what could not be covered and why), methodology notes, test type (black, grey, white box), distribution (who receives it) and the document's version. Only the fields given change; the operator can edit them afterwards.",
  kind: "write",
  actors: ["human", "agent"],
  input: z.object({
    engagementId,
    executiveSummary: z.string().max(20_000).optional(),
    conclusion: z.string().max(20_000).optional(),
    limitations: z.string().max(10_000).optional(),
    methodology: z.string().max(10_000).optional(),
    testType: z.enum(["black", "grey", "white"]).optional(),
    distribution: z.string().max(1000).optional(),
    version: z.string().max(40).optional(),
  }),
  handler: (input, ctx) => {
    const e = ctx.engagement(input.engagementId);
    const { engagementId: _e, ...fields } = input;
    const draft: ReportDraft = { ...(e.getMeta<ReportDraft>("report") ?? {}), ...Object.fromEntries(Object.entries(fields).filter(([, v]) => v !== undefined)), updatedAt: new Date().toISOString() };
    e.setMeta("report", draft, ctx.caller.actor);
    return draft;
  },
});
