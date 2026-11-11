import { gapLine, listGaps } from "./tools/capabilities.js";
import { attackPaths } from "./graph.js";
import { diffSnapshots, getSnapshot, takeSnapshot } from "./recurrent.js";
import { WSTG, wstgTitle } from "./wstg.js";
import { REPORT_TEXT, type ReportText } from "./report-text.js";
import { cvssBreakdown, FULL_TEXT } from "./report-text-full.js";
import { getPlan } from "./plan.js";
import { getBaseline } from "./baseline.js";
import { type EntityAttributes, REPORT_SECTION_IDS } from "@penteos/schema";
import type { Engagement, Entity } from "./engagement.js";

type FindingAttrs = EntityAttributes<"finding">;
const attrs = (f: Entity) => f.attributes as FindingAttrs;

/**
 * The deliverable, built from the graph: nothing is copied by hand, so every statement in the
 * report points back to findings, assets and evidence that exist.
 */

import { z } from "zod";

/** How the organization signs its reports. One per installation (or team server). */
export const Branding = z.object({
  companyName: z.string().max(120).default(""),
  /** data: URL of a PNG, JPEG or SVG logo (kept small: it travels inside every exported report). */
  logo: z
    .string()
    .regex(/^data:image\/(png|jpeg|svg\+xml);base64,[A-Za-z0-9+/=]+$/)
    .max(600_000)
    .optional(),
  primaryColor: z.string().regex(/^#[0-9a-fA-F]{6}$/).default("#5b4bd6"),
  authors: z.string().max(300).default(""),
  confidentiality: z
    .string()
    .max(2000)
    .default(REPORT_TEXT.es.confidentiality),
  footer: z.string().max(200).default(""),
});
export type Branding = z.infer<typeof Branding>;

export interface ReportDraft {
  executiveSummary?: string;
  conclusion?: string;
  /** What the tests could not cover, and why (the default text is used when empty). */
  limitations?: string;
  /** The team's own notes on how it worked (added to the standard methodology). */
  methodology?: string;
  testType?: "black" | "grey" | "white";
  /** Who receives the document. */
  distribution?: string;
  /** The document's version ("1.0", "1.1 - after retest"). */
  version?: string;
  updatedAt?: string;
}

const ORDER = ["critical", "high", "medium", "low", "info"] as const;
/** Findings that a human already validated. */
export const DELIVERABLE_STATUSES = new Set(["approved", "reported", "fixed", "partially_fixed", "not_fixed", "not_verifiable", "reopened", "wont_fix"]);

export interface Readiness {
  findings: number;
  deliverable: number;
  drafts: number;
  inReview: number;
  withoutEvidence: string[];
  withoutRemediation: string[];
  withoutReproduction: Array<{ id: string; title: string }>;
  hasExecutiveSummary: boolean;
  hasConclusion: boolean;
  /** Whether the work done allows stating the overall risk, and what is missing if not. */
  coverage: AssessmentCoverage;
}

export function readiness(engagement: Engagement): Readiness {
  const findings = engagement.query({ kind: "finding", limit: 5000 });
  const draft = engagement.getMeta<ReportDraft>("report");
  return {
    findings: findings.length,
    deliverable: findings.filter((f) => DELIVERABLE_STATUSES.has(String(f.attributes.status))).length,
    drafts: findings.filter((f) => f.attributes.status === "draft").length,
    inReview: findings.filter((f) => f.attributes.status === "in_review").length,
    withoutEvidence: findings.filter((f) => !(f.attributes.evidenceIds as string[] | undefined)?.length).map((f) => String(f.attributes.title)),
    withoutRemediation: findings.filter((f) => !String(f.attributes.remediation ?? "").trim()).map((f) => String(f.attributes.title)),
    withoutReproduction: findings.filter((f) => DELIVERABLE_STATUSES.has(String(f.attributes.status)) || f.attributes.status === "in_review").filter((f) => !String(f.attributes.reproduction ?? "").trim()).map((f) => ({ id: f.id, title: String(f.attributes.title) })),
    hasExecutiveSummary: Boolean(draft?.executiveSummary?.trim()),
    hasConclusion: Boolean(draft?.conclusion?.trim()),
    coverage: assessmentCoverage(engagement),
  };
}

function label(entity: Entity | undefined, T: ReportText): string {
  if (!entity) return T.deletedAsset;
  const a = entity.attributes;
  return String(a.origin ?? a.fqdn ?? a.ip ?? (a.pathTemplate ? `${a.pathTemplate}` : entity.naturalKey.replace(/^default\|/, "").replaceAll("|", ":")));
}

function fence(text: string, lang = ""): string {
  const longest = Math.max(2, ...[...text.matchAll(/`+/g)].map((m) => m[0].length));
  const ticks = "`".repeat(longest + 1);
  return `${ticks}${lang}\n${text}\n${ticks}`;
}

/** An HTTP exchange as stored (request, blank line, response): its two halves. */
function splitExchange(text: string): { request: string; response?: string } {
  const m = /\r?\n\r?\n(HTTP\/[\d.]+ \d{3}[^\n]*)/.exec(text);
  if (!m) return { request: text };
  return { request: text.slice(0, m.index).trimEnd(), response: text.slice(m.index).trim() };
}

const IMAGE = /^image\/(png|jpe?g|gif|webp)$/;

/** The deliverable's sections, in their order; each one is skipped when it has nothing to say. */
export const REPORT_SECTIONS = REPORT_SECTION_IDS;
export type ReportSectionId = (typeof REPORT_SECTIONS)[number];

/** A section that is not Penteos's own: a plugin's, or a custom report's. */
export interface ExtraSection {
  title: string;
  markdown: string;
  /** Goes right after this section (when it is in the report); otherwise before the annex. */
  after?: ReportSectionId;
}

export interface ReportOptions {
  /** Findings not yet approved go in too (the report is then a draft). */
  includeDrafts?: boolean;
  /** Marked as a draft: unfinished (no executive summary, coverage not enough), whatever it holds. */
  markDraft?: boolean;
  /** Only these sections (in their usual order). */
  only?: readonly string[];
  /** Every section but these. */
  skip?: readonly string[];
  extra?: readonly ExtraSection[];
  /** Replaces the report's title ("Pentest - <project>"). */
  title?: string;
  /** Leaves out findings below this severity. */
  minSeverity?: (typeof ORDER)[number];
  /** The complete technical report (default) or the short one for management. */
  kind?: "technical" | "executive";
  /** Who signs it, for the document control (the organization's branding). */
  company?: string;
  authors?: string;
  /** What a person accepts as the limits of this delivery, to issue it as final with partial coverage. */
  limitations?: string;
}

/**
 * How much of the assessment was really done: testing phases not carried out (reporting aside) and,
 * for web applications in scope, the OWASP WSTG categories that apply and were not tested. The
 * overall risk is only stated when this allows it: a "Low" from one day without an account is a
 * reassurance the work cannot back.
 */
export interface AssessmentCoverage {
  determined: boolean;
  phases: string[];
  untested: number;
  applicable: number;
  apps: Array<{ origin: string; untested: number; applicable: number }>;
}

/** Above this share of applicable categories left untested, the overall risk is not determined. */
const MAX_UNTESTED_SHARE = 0.4;

export function assessmentCoverage(engagement: Engagement): AssessmentCoverage {
  const plan = getPlan(engagement);
  // Exploitation left undone is often the agreement (not authorized), not a gap in the analysis:
  // it shows in the methodology, but it does not by itself keep the risk from being stated.
  const phases = plan.phases.filter((p) => p.id !== "reporting" && !p.exploitation && p.status === "pending").map((p) => p.title);
  const apps: AssessmentCoverage["apps"] = [];
  for (const app of engagement.query({ kind: "webapp", limit: 1000 })) {
    if (app.outOfScope) continue;
    const cov = (app.attributes.coverage ?? {}) as Record<string, { status?: string }>;
    let applicable = 0;
    let untested = 0;
    for (const c of WSTG) {
      const st = cov[c.id]?.status ?? "untested";
      if (st === "n/a") continue;
      applicable++;
      if (st === "untested" || st === "in_progress") untested++;
    }
    if (applicable) apps.push({ origin: String(app.attributes.origin ?? app.naturalKey), untested, applicable });
  }
  const untested = apps.reduce((n, a) => n + a.untested, 0);
  const applicable = apps.reduce((n, a) => n + a.applicable, 0);
  const tooLittle = engagement.info.mode === "web" && (!applicable || untested / applicable > MAX_UNTESTED_SHARE);
  return { determined: phases.length === 0 && !tooLittle, phases, untested, applicable, apps: apps.filter((a) => a.untested) };
}

/** What keeps a report from being final: the executive summary, and coverage (unless a person accepted its limits). */
export function reportReadiness(engagement: Engagement, limitations?: string): { final: boolean; missing: Array<"executive_summary" | "coverage">; coverage: AssessmentCoverage } {
  const coverage = assessmentCoverage(engagement);
  const missing: Array<"executive_summary" | "coverage"> = [
    ...(engagement.getMeta<{ executiveSummary?: string }>("report")?.executiveSummary?.trim() ? [] : (["executive_summary"] as const)),
    ...(coverage.determined || limitations?.trim() ? [] : (["coverage"] as const)),
  ];
  return { final: missing.length === 0, missing, coverage };
}

const ULID = /\b[0-9A-HJKMNP-TV-Z]{26}\b/g;

/**
 * What a report reader must never see: Penteos's internal ids (replaced by what they name: a
 * finding's title, an evidence's caption) and saved-credential markers (named, never shown). Inside
 * fenced blocks only the credential markers change: the rest is evidence, kept as captured.
 */
function forReaders(engagement: Engagement, text: string, secretRef: string): string {
  const name = (id: string): string | undefined => {
    const e = engagement.get(id);
    if (!e) return undefined;
    const a = e.attributes as Record<string, unknown>;
    return String(a.title ?? a.caption ?? a.origin ?? a.fqdn ?? a.ip ?? a.name ?? "").trim() || undefined;
  };
  const secrets = (s: string) => s.replace(/\{\{secret:[A-Za-z0-9_.-]+\}\}/g, secretRef);
  const prose = (s: string) => secrets(s).replace(ULID, (id) => {
    const n = name(id);
    return n === undefined ? id : `«${n}»`;
  });
  // Fenced blocks close with a fence at least as long as the one that opened them (evidence that
  // itself contains ``` is wrapped in ````).
  let out = "";
  let last = 0;
  for (const m of text.matchAll(/^(`{3,})[^\n]*\n[\s\S]*?^\1`*[ \t]*$/gm)) {
    out += prose(text.slice(last, m.index)) + secrets(m[0]);
    last = m.index + m[0].length;
  }
  return out + prose(text.slice(last));
}

/** What the executive report keeps. */
const EXECUTIVE_SECTIONS = ["document_control", "executive_summary", "scope", "retest", "comparison", "findings", "remediation_plan", "conclusion"];

export function renderReport(engagement: Engagement, options: ReportOptions = {}): string {
  const info = engagement.info;
  const mode = info.mode;
  const round = info.roundMode;
  const T = REPORT_TEXT[info.language ?? "en"];
  const SEVERITY_ES = T.severities;
  const STATUS_ES = T.statuses;
  const draft = engagement.getMeta<ReportDraft>("report");
  const all = engagement.query({ kind: "finding", limit: 5000 });
  const findings = all
    .filter((f) => options.includeDrafts || DELIVERABLE_STATUSES.has(String(f.attributes.status)))
    .filter((f) => !options.minSeverity || ORDER.indexOf(attrs(f).severity) <= ORDER.indexOf(options.minSeverity))
    .sort((a, b) => ORDER.indexOf(attrs(a).severity) - ORDER.indexOf(attrs(b).severity) || attrs(a).title.localeCompare(attrs(b).title));
  const rules = engagement.scopeRules();
  const counts = engagement.counts();
  const audit = engagement.verifyAudit();
  const today = new Date().toISOString().slice(0, 10);
  const out: string[] = [];
  // Each section starts with a marker; numbering and selection happen once the whole text is there.
  const section = (id: ReportSectionId, title: string) => out.push(`${MARK}${id}${MARK}${title}`, "");
  const pending = T.pending;

  const kindTitle = T.kind[round === "retest" || round === "continuous" ? round : "pentest"];
  const reportKind = options.kind ?? "technical";
  const kind = reportKind;
  out.push(`# ${options.title?.trim() || (reportKind === "executive" ? FULL_TEXT[info.language ?? "en"].executiveKind(`${kindTitle} - ${info.name}`) : `${kindTitle} - ${info.name}`)}`, "");
  out.push(`**${T.client}:** ${info.clientName} · **${T.issued}:** ${today}`);
  if (info.startsAt || info.endsAt) out.push(T.period(info.startsAt?.slice(0, 10) ?? "?", info.endsAt?.slice(0, 10) ?? "?"));
  if (options.includeDrafts || options.markDraft) out.push("", T.draftBanner);
  out.push("");

  const F = FULL_TEXT[info.language ?? "en"];
  const runsAll = engagement.runs(100000).filter((r) => r.status !== "denied");
  const day = (iso: string) => iso.slice(0, 10);
  const firstRun = runsAll.reduce<string | undefined>((m, r) => (!m || r.startedAt < m ? r.startedAt : m), undefined);
  const lastRun = runsAll.reduce<string | undefined>((m, r) => (!m || r.startedAt > m ? r.startedAt : m), undefined);
  const periodFrom = info.startsAt?.slice(0, 10) ?? (firstRun ? day(firstRun) : undefined);
  const periodTo = info.endsAt?.slice(0, 10) ?? (lastRun ? day(lastRun) : undefined);

  section("document_control", F.documentControl);
  out.push(`| ${F.dc.version} | ${cell(draft?.version?.trim() || "1.0")} |`, "|---|---|");
  out.push(`| ${F.dc.date} | ${today} |`);
  if (options.company) out.push(`| ${F.dc.preparedBy} | ${cell(options.company)} |`);
  if (options.authors) out.push(`| ${F.dc.team} | ${cell(options.authors)} |`);
  out.push(`| ${T.client} | ${cell(info.clientName)} |`);
  if (draft?.distribution?.trim()) out.push(`| ${F.dc.distribution} | ${cell(draft.distribution)} |`);
  if (draft?.testType) out.push(`| ${F.dc.testType} | ${F.testTypes[draft.testType]} |`);
  if (periodFrom && periodTo) out.push(`| ${F.dc.period} | ${periodFrom} - ${periodTo} |`);
  out.push(`| ${F.dc.classification} | ${T.confidential} |`, "");

  section("executive_summary", T.executiveSummary);
  {
    // The overall risk: from the most serious finding, but only as far as the coverage reached
    // allows. With too little tested it is "not determined" ("at least High" if a high or critical
    // was found anyway), with what was not done written out; a person may accept those limits.
    const worst = ORDER.find((sev) => findings.some((f) => attrs(f).severity === sev && sev !== "info")) as "critical" | "high" | "medium" | "low" | undefined;
    const coverage = assessmentCoverage(engagement);
    const accepted = options.limitations?.trim();
    const level = coverage.determined || accepted ? (worst ? F.riskLevels[worst] : F.riskLevels.none) : worst === "critical" || worst === "high" ? F.riskAtLeast(F.riskLevels[worst]) : F.riskUndetermined;
    const top = findings[0] && attrs(findings[0]).severity !== "info" ? attrs(findings[0]).title : "";
    out.push(F.riskLine(level, findings.length, top), "");
    if (!coverage.determined) out.push(F.coverageCaveat(coverage), "");
    if (accepted) out.push(`**${F.acceptedLimitations}:** ${accepted}`, "");
  }
  out.push(draft?.executiveSummary?.trim() || pending, "");
  const serious = findings.filter((f) => attrs(f).severity === "critical" || attrs(f).severity === "high").slice(0, 5);
  if (serious.length) {
    out.push(`**${F.topRisks}**`, "");
    for (const f of serious) out.push(`- **${cell(attrs(f).title)}** (${SEVERITY_ES[attrs(f).severity]})${attrs(f).remediation?.trim() ? ` - ${firstSentence(String(attrs(f).remediation))}` : ""}`);
    out.push("");
  }
  if (findings.length) out.push(`<!-- chart:severity ${JSON.stringify(Object.fromEntries(ORDER.map((sev) => [sev, findings.filter((f) => attrs(f).severity === sev).length])))} -->`, "");

  section("scope", T.scope);
  const includes = rules.filter((r) => r.effect === "include");
  const excludes = rules.filter((r) => r.effect === "exclude");
  const target = (r: (typeof rules)[number]) => (r.target.type === "range" ? `${r.target.from}-${r.target.to}` : r.target.type === "entity" ? r.target.entityId : r.target.value);
  out.push(`**${T.included}:**`, "");
  for (const r of includes) out.push(`- \`${target(r)}\`${r.ports ? ` (${T.ports(r.ports)})` : ""}${r.reason ? ` - ${r.reason}` : ""}`);
  if (!includes.length) out.push(`- ${T.noRules}`);
  if (excludes.length) {
    out.push("", `**${T.excluded}:**`, "");
    for (const r of excludes) out.push(`- \`${target(r)}\`${r.reason ? ` - ${r.reason}` : ""}`);
  }
  out.push("");
  if ((periodFrom && periodTo) || draft?.testType) {
    out.push(`**${F.rulesOfEngagement}:**`, "");
    if (periodFrom && periodTo) out.push(`- ${F.window(periodFrom, periodTo)}`);
    if (draft?.testType) out.push(`- ${F.dc.testType}: ${F.testTypes[draft.testType]}`);
    out.push("");
  }

  section("methodology", F.methodology);
  out.push(F.methodologyIntro[mode === "web" ? "web" : mode === "infra" ? "network" : "other"], "");
  {
    const plan = getPlan(engagement);
    const phases = plan.phases.filter((p) => p.status !== "pending" || p.summary);
    if (phases.length) {
      out.push(F.phasesHead, "|---|---|---|");
      // The reporting phase is this very document: never "not carried out" inside it.
      for (const p of plan.phases) out.push(`| ${cell(p.title)} | ${F.phaseStatus[p.id === "reporting" && p.status === "pending" ? "current" : p.status]} | ${cell(firstSentence(p.summary ?? p.goal ?? ""))} |`);
      out.push("");
    }
  }
  if (draft?.methodology?.trim()) out.push(`**${F.operatorNotes}**`, "", draft.methodology.trim(), "");

  section("timeline", F.timeline);
  if (runsAll.length && firstRun && lastRun) {
    const byDay = new Map<string, { runs: number; tools: Set<string>; findings: number }>();
    for (const r of runsAll) {
      const d = byDay.get(day(r.startedAt)) ?? { runs: 0, tools: new Set<string>(), findings: 0 };
      d.runs++;
      if (r.tool) d.tools.add(r.tool);
      byDay.set(day(r.startedAt), d);
    }
    for (const f of all) {
      const d = byDay.get(day(f.createdAt));
      if (d) d.findings++;
    }
    out.push(F.timelineIntro(day(firstRun), day(lastRun), byDay.size), "", F.timelineHead, "|---|---|---|---|");
    for (const [d, v] of [...byDay].sort((a, b) => a[0].localeCompare(b[0])).slice(-60)) out.push(`| ${d} | ${v.runs} | ${cell([...v.tools].slice(0, 8).join(", ") || F.none)} | ${v.findings} |`);
    out.push("");
  } else out.push(F.timelineNone, "");

  // Infrastructure: the attack paths found over the directory come before the findings.
  if (mode === "infra") {
    const paths = attackPaths(engagement, { maxPaths: 5 });
    if (paths.length) {
      section("paths", T.paths);
      paths.forEach((p, i) => out.push(`${i + 1}. ${p.map((s, j) => (j === 0 ? `**${s.label}**` : `→ _${T.via[s.via ?? ""] ?? s.via}_ → **${s.label}**`)).join(" ")}`));
      out.push("");
    }
  }

  // Retest: what happened with each finding of the original engagement.
  if (round === "retest") {
    section("retest", T.retest);
    const verified = all.filter((f) => f.tags.includes("retest"));
    if (verified.length) {
      const by = (st: string) => verified.filter((f) => f.attributes.status === st).length;
      out.push(
        T.retestSummary({ total: verified.length, fixed: by("fixed"), partial: by("partially_fixed"), notFixed: by("not_fixed"), notVerifiable: by("not_verifiable"), unverified: by("reported") }),
        "",
        T.retestHead,
        "|---|---|---|",
      );
      for (const f of verified) out.push(`| ${cell(attrs(f).title)} | ${SEVERITY_ES[attrs(f).severity]} | ${STATUS_ES[attrs(f).status] ?? attrs(f).status} |`);
      out.push("");
    } else out.push(T.retestNone, "");
    const baseline = engagement.getMeta<string>("baseline");
    const original = baseline ? getSnapshot(engagement, baseline) : undefined;
    if (original) {
      const d = diffSnapshots(original, takeSnapshot(engagement));
      out.push(
        T.comparison({ resolved: d.findings.resolved.length, persisting: d.findings.persisting.length, added: d.findings.new.length, servicesAdded: d.services.added.length, servicesRemoved: d.services.removed.length }),
        "",
      );
    }
  }

  // A previous assessment done elsewhere: what was fixed, what remains, what is new.
  const baseline = getBaseline(engagement);
  if (baseline?.findings.length) {
    section("comparison", F.comparisonTitle);
    const by = (s?: string) => baseline.findings.filter((f) => f.status === s).length;
    out.push(F.comparisonIntro(baseline.source, baseline.date), "", F.comparisonCounts({ fixed: by("fixed"), open: by("still_open"), notRetested: by("not_retested") + by(undefined) }), "", F.comparisonHead, "|---|---|---|---|---|");
    for (const f of baseline.findings) {
      const now = f.findingId ? engagement.get(f.findingId) : undefined;
      out.push(`| ${cell(f.ref)} | ${cell(f.title)} | ${SEVERITY_ES[f.severity] ?? f.severity} | ${F.comparisonStatus[f.status ?? "not_retested"]} | ${cell(now ? `«${String(now.attributes.title)}»` : f.note ?? "")} |`);
    }
    const linked = new Set(baseline.findings.map((f) => f.findingId).filter(Boolean));
    const fresh = findings.filter((f) => !linked.has(f.id));
    out.push("", `**${F.comparisonNew(fresh.length)}**`, "");
    for (const f of fresh.slice(0, 40)) out.push(`- ${cell(attrs(f).title)} (${SEVERITY_ES[attrs(f).severity]})`);
    out.push("");
  }

  section("findings", round === "retest" ? T.findings : T.findingsSummary);
  if (!findings.length) {
    out.push(options.includeDrafts ? T.noFindings : T.noApprovedFindings, "");
  } else {
    out.push(`<!-- chart:severity ${JSON.stringify(Object.fromEntries(ORDER.map((sev) => [sev, findings.filter((f) => attrs(f).severity === sev).length])))} -->`, "");
    out.push(T.severityHead, "|---|---|");
    for (const sev of ORDER) {
      const c = findings.filter((f) => attrs(f).severity === sev).length;
      if (c) out.push(`| ${SEVERITY_ES[sev]} | ${c} |`);
    }
    out.push("", T.findingsHead, "|---|---|---|---|---|");
    findings.forEach((f, i) => out.push(`| F-${String(i + 1).padStart(2, "0")} | ${cell(attrs(f).title)} | ${SEVERITY_ES[attrs(f).severity]} | ${attrs(f).cvss ? `${attrs(f).cvss!.score}` : "-"} | ${STATUS_ES[attrs(f).status] ?? attrs(f).status} |`));
    out.push("");
  }

  if (findings.length) {
    section("detailed", T.detailed);
    findings.forEach((f, i) => {
      const a = attrs(f);
      out.push(`### F-${String(i + 1).padStart(2, "0")} · ${a.title}`, "");
      const meta = [`**${T.severity}:** ${SEVERITY_ES[a.severity] ?? a.severity}`];
      if (a.cvss) meta.push(`**CVSS ${a.cvss.version}:** ${a.cvss.score} (\`${a.cvss.vector}\`)`);
      if ((a.cwe as string[] | undefined)?.length) meta.push(`**CWE:** ${(a.cwe as string[]).join(", ")}`);
      meta.push(`**${T.status}:** ${STATUS_ES[a.status] ?? a.status}`);
      out.push(meta.join(" · "), "");
      if (a.cvss?.vector) {
        const rows = cvssBreakdown(a.cvss.vector, F);
        if (rows.length) {
          out.push(`**${F.cvssDetail}**`, "", `| ${rows.map(([k]) => k).join(" | ")} |`, `|${rows.map(() => "---").join("|")}|`, `| ${rows.map(([, v]) => v).join(" | ")} |`, "");
        }
      }
      if (String(a.description ?? "").trim()) out.push(`**${T.description}**`, "", String(a.description).trim(), "");
      if (String(a.impact ?? "").trim()) out.push(`**${T.impact}**`, "", String(a.impact).trim(), "");
      // What was measured and demonstrated beyond detecting it (reach, exposed data, chains).
      const shown = ((a.deepening as { questions?: Array<{ key: "reach" | "exposed" | "chain"; status: string; answer?: string }> } | undefined)?.questions ?? []).filter((q) => q.status === "answered" && q.answer?.trim());
      if (shown.length) {
        out.push(`**${T.demonstrated}**`, "");
        for (const q of shown) out.push(`- **${T.impactKeys[q.key]}:** ${q.answer!.trim()}`);
        out.push("");
      }
      const instances = (a.instances as Array<{ entity: { id: string }; location?: string }> | undefined) ?? [];
      if (instances.length) {
        out.push(`**${T.affected}**`, "");
        for (const inst of instances) out.push(`- \`${label(engagement.get(inst.entity.id), T)}\`${inst.location ? ` - ${inst.location}` : ""}`);
        out.push("");
      }
      if (String(a.reproduction ?? "").trim() && kind === "technical") out.push(`**${F.reproduction}**`, "", String(a.reproduction).trim(), "");
      const evidence = ((a.evidenceIds as string[] | undefined) ?? []).map((id) => engagement.get(id)).filter((e): e is Entity => Boolean(e));
      if (evidence.length) {
        out.push(`**${T.evidence}**`, "");
        for (const ev of evidence) {
          const src = ev.attributes.source as { type?: string; rawId: string; range?: { start: number; end: number } };
          out.push(`*${ev.attributes.caption}*`, "");
          try {
            const mime = engagement.rawMime(src.rawId) ?? "";
            // A screenshot goes in as an image (the PDF and Word show it; markdown keeps its reference).
            if (IMAGE.test(mime)) {
              out.push(`![${cell(String(ev.attributes.caption))}](raw:${src.rawId})`, "");
              continue;
            }
            const raw = engagement.readRaw(src.rawId);
            // Credentials and session cookies never reach the deliverable: only their reference.
            const slice = engagement.redact((src.range ? raw.subarray(src.range.start, src.range.end) : raw.subarray(0, 6000)).toString("utf8"));
            const text = slice.length > 6000 ? `${slice.slice(0, 6000)}\n[…]` : slice;
            const ex = src.type === "http_exchange" || /^message\/http/.test(mime) ? splitExchange(text) : undefined;
            if (ex?.response) {
              const cutTo = (t: string, n: number) => (t.length > n ? `${t.slice(0, n)}\n[…]` : t);
              out.push(`_${F.request}_`, "", fence(cutTo(ex.request, 3000), "http"), "", `_${F.response}_`, "", fence(cutTo(ex.response, 3000), "http"), "");
            } else out.push(fence(text.length > 3000 ? `${text.slice(0, 3000)}\n[…]` : text), "");
          } catch {
            out.push(T.evidenceMissing, "");
          }
        }
      }
      const v = a.verification as { verdict?: string; by?: { type: string; name?: string }; at?: string } | undefined;
      if (v?.verdict === "reproduced" && v.at) out.push(`_${F.verified(v.by?.type === "human" ? (v.by.name ?? "el equipo") : "Penteos", v.at.slice(0, 10))}_`, "");
      if (String(a.remediation ?? "").trim()) out.push(`**${T.remediation}**`, "", String(a.remediation).trim(), "");
      if ((a.references as string[] | undefined)?.length) {
        out.push(`**${T.references}**`, "");
        for (const r of a.references as string[]) out.push(`- ${r}`);
        out.push("");
      }
    });
  }

  // What to fix first: by severity, with the first sentence of each recommendation.
  const actionable = findings.filter((f) => attrs(f).severity !== "info");
  if (actionable.length) {
    section("remediation_plan", F.remediationPlan);
    out.push(F.remediationIntro, "");
    const horizon = (sev: string) => (sev === "critical" || sev === "high" ? "now" : sev === "medium" ? "short" : "mid");
    for (const h of ["now", "short", "mid"] as const) {
      const list = findings.map((f, i) => ({ f, id: `F-${String(i + 1).padStart(2, "0")}` })).filter(({ f }) => attrs(f).severity !== "info" && horizon(attrs(f).severity) === h);
      if (!list.length) continue;
      out.push(`### ${F.horizons[h]}`, "", F.planHead, "|---|---|---|---|");
      for (const { f, id } of list) {
        const assets = ((attrs(f).instances as Array<{ entity: { id: string } }> | undefined) ?? []).slice(0, 4).map((x) => label(engagement.get(x.entity.id), T)).join(", ");
        out.push(`| ${id} | ${cell(attrs(f).title)} | ${cell(assets || F.none)} | ${cell(firstSentence(String(attrs(f).remediation ?? "")) || F.none)} |`);
      }
      out.push("");
    }
  }

  section("surface", T.surface);
  out.push(T.surfaceLine(counts as Record<string, number>), "");
  const webapps = engagement.query({ kind: "webapp", limit: 50 }).filter((w) => !w.outOfScope);
  if (webapps.length) {
    out.push(T.appsHead, "|---|---|");
    for (const w of webapps) {
      const tech = ((w.attributes.technologies as Array<{ name: string }> | undefined) ?? []).map((t) => t.name).join(", ");
      out.push(`| \`${w.attributes.origin}\` | ${tech || "-"} |`);
    }
    out.push("");
  }

  // What was tested on each web application (OWASP WSTG).
  const covered = webapps.filter((w) => w.attributes.coverage && Object.keys(w.attributes.coverage as object).length);
  if (covered.length) {
    section("coverage", T.coverage);
    for (const w of covered) {
      const cov = w.attributes.coverage as Record<string, { status: string; note?: string }>;
      out.push(`**\`${w.attributes.origin}\`**`, "", T.coverageHead, "|---|---|---|");
      for (const c of WSTG) {
        const v = cov[c.id];
        out.push(`| ${c.id} · ${wstgTitle(c, info.language ?? "en")} | ${T.coverageStatus[v?.status ?? "untested"]} | ${cell(v?.note ?? "")} |`);
      }
      out.push("");
    }
  }

  // Everything that was seen, for reference (trimmed: the project has all of it).
  {
    const hosts = engagement.query({ kind: "host", limit: 5000 }).filter((h) => !h.outOfScope);
    const services = engagement.query({ kind: "service", limit: 5000 }).filter((x) => !x.outOfScope);
    const apps = engagement.query({ kind: "webapp", limit: 2000 }).filter((w) => !w.outOfScope);
    const techs = engagement.query({ kind: "technology", limit: 2000 });
    if (hosts.length || services.length || apps.length || techs.length) {
      section("inventory", F.inventory);
      const MAX = 150;
      if (hosts.length) {
        out.push(`### ${F.hostsTitle}`, "", F.hostsHead, "|---|---|---|---|");
        for (const h of hosts.slice(0, MAX)) {
          const ha = h.attributes as { ip?: string; hostnames?: string[]; os?: { name?: string } | string; status?: string };
          out.push(`| \`${cell(ha.ip ?? label(h, T))}\` | ${cell((ha.hostnames ?? []).slice(0, 4).join(", ") || F.none)} | ${cell(typeof ha.os === "string" ? ha.os : (ha.os?.name ?? F.none))} | ${cell(ha.status ?? F.none)} |`);
        }
        if (hosts.length > MAX) out.push("", F.trimmed(MAX, hosts.length));
        out.push("");
      }
      if (services.length) {
        out.push(`### ${F.servicesTitle}`, "", F.servicesHead, "|---|---|---|---|");
        for (const sv of services.slice(0, MAX)) {
          const sa = sv.attributes as { hostId?: string; port?: number; transport?: string; name?: string; product?: string; version?: string };
          out.push(`| \`${cell(label(sa.hostId ? engagement.get(sa.hostId) : undefined, T))}\` | ${sa.port ?? "?"}/${sa.transport ?? "tcp"} | ${cell(sa.name ?? F.none)} | ${cell([sa.product, sa.version].filter(Boolean).join(" ") || F.none)} |`);
        }
        if (services.length > MAX) out.push("", F.trimmed(MAX, services.length));
        out.push("");
      }
      if (apps.length) {
        out.push(`### ${F.appsTitle}`, "", F.appsHead, "|---|---|");
        for (const w of apps.slice(0, MAX)) {
          const tech = ((w.attributes.technologies as Array<{ name: string; version?: string }> | undefined) ?? []).map((t) => (t.version ? `${t.name} ${t.version}` : t.name)).join(", ");
          out.push(`| \`${cell(w.attributes.origin)}\` | ${cell(tech || F.none)} |`);
        }
        out.push("");
      }
      if (techs.length) {
        out.push(`### ${F.techTitle}`, "", F.techHead, "|---|---|---|");
        for (const t of techs.slice(0, MAX)) {
          const ta = t.attributes as { name?: string; version?: string; on?: { id: string }; entityId?: string };
          const on = ta.on?.id ?? ta.entityId;
          out.push(`| ${cell(ta.name ?? t.naturalKey)} | ${cell(ta.version ?? F.none)} | ${cell(on ? label(engagement.get(on), T) : F.none)} |`);
        }
        if (techs.length > MAX) out.push("", F.trimmed(MAX, techs.length));
        out.push("");
      }
    }
  }

  section("limitations", F.limitations);
  out.push(draft?.limitations?.trim() || F.defaultLimitations, "");
  // What missing tools left undone or done by a lesser method, recorded by Penteos as it happened:
  // a report must say what was not covered and why.
  {
    const lang = info.language ?? "en";
    const left = listGaps(engagement).filter((g) => g.status === "open" || g.status === "accepted");
    if (left.length) {
      out.push(`**${F.toolGaps}**`, "");
      for (const g of left) out.push(`- ${gapLine(g, lang)}${g.accepted?.reason ? ` - ${g.accepted.reason}` : ""}`);
      out.push("");
    }
  }
  // What reconnaissance found outside the scope: untested, said so, with what is known of each.
  {
    const seen = new Set<string>();
    const lines: string[] = [];
    for (const kind of ["webapp", "domain", "host"] as const) {
      for (const e of engagement.query({ kind, limit: 2000 })) {
        if (!e.outOfScope) continue;
        const a = e.attributes as Record<string, unknown>;
        const name = String(a.origin ?? a.fqdn ?? a.ip ?? "");
        const host = name.replace(/^[a-z]+:\/\//, "").replace(/:\d+$/, "");
        if (!name || seen.has(host)) continue;
        seen.add(host);
        const tech = Array.isArray(a.technologies) ? (a.technologies as Array<{ name?: string }>).map((t) => t.name).filter(Boolean).slice(0, 4).join(", ") : "";
        const about = [a.title ? String(a.title) : "", tech].filter(Boolean).join(" · ");
        lines.push(`- \`${name}\`${about ? ` - ${cell(about)}` : ""}`);
      }
    }
    if (lines.length) out.push(`**${F.discoveredTitle}**`, "", F.discoveredIntro, "", ...lines.slice(0, 60), "");
  }

  if (draft?.conclusion?.trim()) {
    section("conclusion", T.conclusion);
    out.push(draft.conclusion.trim(), "");
  }

  // What the tests left on the client's side, so it can be cleaned (and was, or was accepted).
  const traces = engagement.getState<Array<{ what: string; where: string; cleanup?: string; status: "pending" | "cleaned" | "accepted" }>>("traces") ?? [];
  if (traces.length) {
    section("traces", T.traces);
    out.push(T.tracesIntro, "", T.tracesHead, "|---|---|---|---|");
    for (const tr of traces) out.push(`| ${cell(tr.what)} | ${cell(tr.where)} | ${cell(tr.cleanup ?? "")} | ${T.traceStatus[tr.status]} |`);
    out.push("");
  }

  // Which tools were used against the targets, how often and when; and the commands themselves
  // (secrets never shown). Local analysis in the sandbox and tool installs touched nothing: left out.
  const testing = runsAll.filter((r) => (r.targets?.length ?? 0) > 0);
  if (testing.length) {
    out.push(`${MARK}tools${MARK}${F.tools}`, "");
    const byTool = new Map<string, { n: number; first: string; last: string }>();
    for (const r of testing) {
      const name = r.tool ?? r.command?.split(/\s+/)[0] ?? "?";
      const cur = byTool.get(name);
      if (!cur) byTool.set(name, { n: 1, first: r.startedAt, last: r.startedAt });
      else {
        cur.n++;
        if (r.startedAt < cur.first) cur.first = r.startedAt;
        if (r.startedAt > cur.last) cur.last = r.startedAt;
      }
    }
    out.push(F.toolsHead, "|---|---|---|---|");
    for (const [t, v] of [...byTool].sort((a, b) => b[1].n - a[1].n)) out.push(`| ${cell(t)} | ${v.n} | ${v.first.slice(0, 16).replace("T", " ")} | ${v.last.slice(0, 16).replace("T", " ")} |`);
    const commands = testing.filter((r) => r.command).sort((a, b) => a.startedAt.localeCompare(b.startedAt));
    if (commands.length) {
      out.push("", `### ${F.commandsTitle}`, "", F.commandsHead, "|---|---|---|");
      for (const r of commands.slice(-120)) out.push(`| ${r.startedAt.slice(0, 16).replace("T", " ")} | ${cell(r.tool ?? F.none)} | \`${cell(engagement.redact(String(r.command)).slice(0, 220))}\` |`);
      if (commands.length > 120) out.push("", F.trimmed(120, commands.length));
    }
    out.push("");
  }

  out.push(`${MARK}annex${MARK}${T.annex}`, "");
  out.push(
    T.annexText(engagement.runs(100000).length) + (audit.ok ? T.auditOk(audit.events) : T.auditBroken(audit.brokenAt)),
    "",
  );
  return forReaders(engagement, assemble(out, reportKind === "executive" ? { ...options, only: options.only?.length ? options.only.filter((x) => EXECUTIVE_SECTIONS.includes(x)) : EXECUTIVE_SECTIONS } : options), F.secretRef);
}

/** The first sentence of a text (a recommendation's main action), at most 220 characters. */
function firstSentence(text: string): string {
  const t = text.replace(/\s+/g, " ").replace(/[*_`#>]/g, "").trim();
  const m = /^(.{20,220}?[.!?])(\s|$)/.exec(t);
  return m ? m[1]! : t.slice(0, 220);
}

const MARK = "\u0000§";
/** Sections that start on a new page in the printed document. */
const PAGE_BREAK = new Set(["executive_summary", "findings", "detailed", "remediation_plan", "inventory", "tools"]);
/** Sections that are not numbered: the document's frame and the annexes. */
const UNNUMBERED = new Set(["document_control", "tools", "annex"]);

/** Splits the text at its section markers, keeps the chosen ones, adds the extra ones and numbers them. */
function assemble(lines: string[], options: ReportOptions): string {
  const head: string[] = [];
  const parts: Array<{ id: string; title: string; body: string[] }> = [];
  for (const line of lines) {
    if (line.startsWith(MARK)) {
      const [, id, title] = line.split(MARK);
      parts.push({ id: id!, title: title!, body: [] });
    } else (parts.at(-1)?.body ?? head).push(line);
  }
  const keep = (id: string) => (!options.only?.length || options.only.includes(id)) && !options.skip?.includes(id);
  const kept = parts.filter((p) => keep(p.id));
  for (const extra of options.extra ?? []) {
    const part = { id: "extra", title: extra.title.trim().replace(/\n+/g, " ") || "-", body: ["", ...demote(extra.markdown), ""] };
    const at = extra.after ? kept.findIndex((p) => p.id === extra.after) : -1;
    if (at >= 0) {
      // After the section and after other extras already placed there.
      let i = at + 1;
      while (kept[i]?.id === "extra") i++;
      kept.splice(i, 0, part);
    } else {
      const annex = kept.findIndex((p) => p.id === "annex");
      kept.splice(annex >= 0 ? annex : kept.length, 0, part);
    }
  }
  let n = 0;
  const out = [...head];
  for (const p of kept) {
    // The major sections start on a new page in the PDF (a marker the other formats ignore).
    if (PAGE_BREAK.has(p.id)) out.push("<!-- pagebreak -->");
    // The annex is not numbered; the body of each section starts after a blank line.
    out.push(UNNUMBERED.has(p.id) ? `## ${p.title}` : `## ${++n}. ${p.title}`);
    const body = p.body[0] === "" ? p.body : ["", ...p.body];
    out.push(...body);
  }
  return out.join("\n");
}

/** A section's own headings stay inside it: "#" and "##" become "###". */
function demote(markdown: string): string[] {
  return markdown
    .replace(/\r\n/g, "\n")
    .split("\n")
    .map((l) => (/^#{1,2} /.test(l) ? `### ${l.replace(/^#+ /, "")}` : l));
}

/** Text for a markdown table cell. */
function cell(v: unknown): string {
  return String(v ?? "").replace(/\|/g, "\\|").replace(/\n+/g, " ");
}

