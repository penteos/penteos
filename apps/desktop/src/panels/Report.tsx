import { Bot, CheckCircle2, CircleAlert, Download, FileText, FolderOpen, History, RefreshCw, ShieldCheck, Wand2 } from "../ui/icons";
import { useEffect, useMemo, useState } from "react";
import { useApp, useOperation } from "../state";
import { Badge, toast } from "../ui/bits";
import { PluginExports } from "../ui/plugins";
import { ago, t, tn } from "../i18n";
import { TracesSection, useTraces } from "../ui/Traces";
import { HelpHint } from "../ui/HelpHint";
import { revealProjectFolder } from "../ui/files";

/**
 * The deliverable in three steps and its history: prepare (what is missing, fixed from here or by
 * the Maestro), write (the parts people write), generate (technical or executive; PDF, Word or
 * markdown) and the versions delivered, with what changed between them.
 */

interface Draft {
  executiveSummary?: string;
  conclusion?: string;
  limitations?: string;
  methodology?: string;
  testType?: "black" | "grey" | "white";
  distribution?: string;
  version?: string;
}
/** Whether the work done allows stating the overall risk (core: assessmentCoverage). */
interface Coverage {
  determined: boolean;
  phases: string[];
  untested: number;
  applicable: number;
}

interface ReportState {
  draft: Draft;
  readiness: {
    findings: number;
    deliverable: number;
    drafts: number;
    inReview: number;
    withoutEvidence: string[];
    withoutRemediation: string[];
    withoutReproduction: Array<{ id: string; title: string }>;
    hasExecutiveSummary: boolean;
    hasConclusion: boolean;
    coverage: Coverage;
  };
}
interface Branding {
  companyName: string;
  logo?: string;
  primaryColor: string;
  authors: string;
  confidentiality: string;
  footer: string;
}
interface Version {
  id: string;
  at: string;
  kind: "technical" | "executive";
  format: string;
  label: string;
  includeDrafts: boolean;
  findings: number;
  diff?: { previous: string; added: string[]; removed: string[]; changed: Array<{ title: string; from: string; to: string }> };
}
type Step = "prepare" | "write" | "generate" | "versions";
type Rendering = Promise<{ html?: string; docxBase64?: string; markdown?: string } & PluginProblems>;
interface Work {
  (): Promise<void>;
}
const STEP_KEY = "penteos.report.step";

function BrandingEditor() {
  const { client } = useApp();
  const current = useOperation<Branding>("branding.get", {}, { refreshOn: () => false });
  const [form, setForm] = useState<Branding>();
  useEffect(() => {
    if (current.data && !form) setForm(current.data);
  }, [current.data, form]);
  if (!form) return null;
  const set = (k: keyof Branding, v: string) => setForm({ ...form, [k]: v });

  function pickLogo(file: File | undefined) {
    if (!file) return;
    if (file.size > 400_000) return toast("bad", t("ops.branding.logoTooBig.title"), t("ops.branding.logoTooBig.body"));
    const reader = new FileReader();
    reader.onload = () => set("logo", String(reader.result));
    reader.readAsDataURL(file);
  }
  async function save() {
    try {
      const { logo, ...rest } = form!;
      await client.call("branding.set", { ...rest, ...(logo ? { logo } : {}) });
      toast("ok", t("ops.branding.saved.title"), t("ops.branding.saved.body"));
    } catch (e) {
      toast("bad", t("common.notSaved"), (e as Error).message);
    }
  }

  return (
    <div className="branding">
      <div className="row2">
        <label>{t("ops.branding.company")}<input className="input" value={form.companyName} onChange={(e) => set("companyName", e.target.value)} placeholder={t("ops.branding.companyPlaceholder")} /></label>
        <label>{t("ops.branding.authors")}<input className="input" value={form.authors} onChange={(e) => set("authors", e.target.value)} placeholder={t("ops.branding.authorsPlaceholder")} /></label>
        <label style={{ flex: "0 0 110px" }}>{t("ops.branding.color")}<input className="input" type="color" value={form.primaryColor} onChange={(e) => set("primaryColor", e.target.value)} style={{ padding: 2 }} /></label>
      </div>
      <div className="row2" style={{ alignItems: "center" }}>
        <label>{t("ops.branding.logo")}
          <input className="input" type="file" accept="image/png,image/jpeg,image/svg+xml" onChange={(e) => pickLogo(e.target.files?.[0])} style={{ paddingTop: 3 }} />
        </label>
        {form.logo ? <img src={form.logo} alt="" style={{ maxHeight: 40, maxWidth: 160, background: "#fff", padding: 4, borderRadius: 3 }} /> : null}
      </div>
      <label>{t("ops.branding.confidentiality")}<textarea className="input" rows={2} value={form.confidentiality} onChange={(e) => set("confidentiality", e.target.value)} /></label>
      <label>{t("ops.branding.footer")}<input className="input" value={form.footer} onChange={(e) => set("footer", e.target.value)} placeholder={t("ops.branding.footerPlaceholder")} /></label>
      <div><button className="btn sm primary" onClick={save}>{t("ops.branding.save")}</button></div>
    </div>
  );
}

/** Sections of plugins that could not be made (the report is made without them). */
interface PluginProblems {
  pluginProblems?: Array<{ plugin: string; section: string; error: string }>;
}
function warnPluginProblems(r: PluginProblems) {
  const list = r.pluginProblems ?? [];
  if (list.length) toast("bad", tn("ops.report.pluginProblems", list.length), list.map((p) => `${p.plugin} · ${p.section}: ${p.error}`).join("\n"));
}

/** Asks the Maestro through the agent sidebar, with whatever provider is selected there. */
export function askMaestro(text: string) {
  window.dispatchEvent(new CustomEvent("penteos:ask-maestro", { detail: text }));
}



function bytesToBlob(b64: string, type: string): Blob {
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return new Blob([bytes], { type });
}

function save(name: string, blob: Blob) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
}

export function ReportPanel() {
  const state = useOperation<ReportState>("report.get", {}, { refreshOn: (e) => e.kind === "finding" || e.type === "engagement.updated" || e.kind === "evidence" });
  const [step, setStepState] = useState<Step>(() => {
    try {
      return (localStorage.getItem(STEP_KEY) as Step) || "prepare";
    } catch {
      return "prepare";
    }
  });
  const setStep = (s: Step) => {
    setStepState(s);
    try {
      localStorage.setItem(STEP_KEY, s);
    } catch {
      /* a convenience only */
    }
  };
  const traces = useTraces();
  const pendingTraces = (traces.data ?? []).filter((x) => x.status === "pending").length;
  const r = state.data?.readiness;
  const open = r ? [r.deliverable === 0, r.drafts + r.inReview > 0, r.withoutEvidence.length > 0, r.withoutRemediation.length > 0, r.withoutReproduction.length > 0, !r.hasExecutiveSummary, !r.coverage?.determined, pendingTraces > 0].filter(Boolean).length : 0;
  const steps: Array<{ id: Step; label: string; badge?: number }> = [
    { id: "prepare", label: t("ops.report.step.prepare"), ...(open ? { badge: open } : {}) },
    { id: "write", label: t("ops.report.step.write") },
    { id: "generate", label: t("ops.report.step.generate") },
    { id: "versions", label: t("ops.report.step.versions") },
  ];
  return (
    <div className="panel">
      <div className="panel-toolbar">
        <FileText size={14} />
        <h3>{t("ops.report.title")}</h3>
        <HelpHint id="report" text={t("ops.report.hint")} />
      </div>
      <div className="report-steps">
        {steps.map((s, i) => (
          <button key={s.id} className={`report-step ${step === s.id ? "on" : ""}`} onClick={() => setStep(s.id)}>
            <span className="report-step-n">{i < 3 ? i + 1 : <History size={11} />}</span>
            {s.label}
            {s.badge ? <span className="report-step-badge">{s.badge}</span> : null}
          </button>
        ))}
      </div>
      <div className="panel-scroll">
        <div className="report">
          {step === "prepare" ? <Prepare state={state.data} pendingTraces={pendingTraces} onWrite={() => setStep("write")} onGenerate={() => setStep("generate")} /> : null}
          {step === "write" ? <Write draft={state.data?.draft ?? {}} onSaved={() => state.reload()} /> : null}
          {step === "generate" ? <Generate {...(r ? { readiness: r } : {})} /> : null}
          {step === "versions" ? <Versions /> : null}
        </div>
      </div>
    </div>
  );
}

/** What is missing before delivering, each with the way to fix it. */
function Prepare(props: { state?: ReportState; pendingTraces: number; onWrite: () => void; onGenerate: () => void }) {
  const { workbench } = useApp();
  const r = props.state?.readiness;
  if (!r) return null;
  const list = (xs: string[]) => xs.slice(0, 6).join(", ") + (xs.length > 6 ? ` (+${xs.length - 6})` : "");
  const toFindings = { label: t("ops.report.fix.review"), run: () => workbench.openPanel("findings") };
  const checks: Array<{ ok: boolean; text: string; actions?: Array<{ label: string; run: () => void; maestro?: boolean }> }> = [
    { ok: r.deliverable > 0, text: r.deliverable ? tn("ops.check.approved", r.deliverable) : t("ops.check.noneApproved"), ...(r.deliverable ? {} : { actions: [toFindings] }) },
    { ok: r.drafts + r.inReview === 0, text: r.drafts + r.inReview ? t("ops.check.pending", { drafts: r.drafts, review: r.inReview }) : t("ops.check.allReviewed"), ...(r.drafts + r.inReview ? { actions: [toFindings] } : {}) },
    {
      ok: r.withoutEvidence.length === 0,
      text: r.withoutEvidence.length ? t("ops.check.noEvidence", { list: list(r.withoutEvidence) }) : t("ops.check.allEvidence"),
      ...(r.withoutEvidence.length ? { actions: [{ label: t("ops.report.fix.askMaestro"), maestro: true, run: () => askMaestro(t("ops.report.ask.evidence", { list: r.withoutEvidence.join(", ") })) }, toFindings] } : {}),
    },
    {
      ok: r.withoutRemediation.length === 0,
      text: r.withoutRemediation.length ? t("ops.check.noRemediation", { list: list(r.withoutRemediation) }) : t("ops.check.allRemediation"),
      ...(r.withoutRemediation.length ? { actions: [{ label: t("ops.report.fix.askMaestro"), maestro: true, run: () => askMaestro(t("ops.report.ask.remediation", { list: r.withoutRemediation.join(", ") })) }, toFindings] } : {}),
    },
    {
      ok: r.withoutReproduction.length === 0,
      text: r.withoutReproduction.length ? t("ops.check.noReproduction", { list: list(r.withoutReproduction.map((x) => x.title)) }) : t("ops.check.allReproduction"),
      ...(r.withoutReproduction.length ? { actions: [{ label: t("ops.report.fix.askMaestro"), maestro: true, run: () => askMaestro(t("ops.report.ask.reproduction", { list: r.withoutReproduction.map((x) => x.title).join(", ") })) }] } : {}),
    },
    { ok: r.hasExecutiveSummary, text: r.hasExecutiveSummary ? t("ops.check.summaryDone") : t("ops.check.summaryMissing"), ...(r.hasExecutiveSummary ? {} : { actions: [{ label: t("ops.report.fix.write"), run: props.onWrite }] }) },
    ...(props.pendingTraces ? [{ ok: false, text: tn("ops.check.traces", props.pendingTraces) }] : []),
  ];
  const ready = checks.every((c) => c.ok);
  return (
    <>
      <section>
        <h2>{t("ops.check.title")}</h2>
        <div className="report-checks">
          {checks.map((c) => (
            <div key={c.text} className={`report-check ${c.ok ? "ok" : ""}`}>
              <span className="report-check-ic">{c.ok ? <CheckCircle2 size={14} /> : <CircleAlert size={14} />}</span>
              <span className="report-check-text">{c.text}</span>
              <span className="report-check-actions">
                {(c.actions ?? []).map((a) => (
                  <button key={a.label} className={`btn sm ${a.maestro ? "" : "ghost"}`} onClick={a.run}>
                    {a.maestro ? <Bot size={12} /> : null} {a.label}
                  </button>
                ))}
              </span>
            </div>
          ))}
        </div>
        {ready ? (
          <div className="report-ready">
            <CheckCircle2 size={14} /> {t("ops.report.ready")}
            <button className="btn sm primary" onClick={props.onGenerate}>{t("ops.report.toGenerate")}</button>
          </div>
        ) : null}
      </section>
      <section>
        <h2>{t("ops.report.qa.title")}</h2>
        <div className="report-qa">
          <ShieldCheck size={16} />
          <p>{t("ops.report.qa.body")}</p>
          <button className="btn sm" onClick={() => askMaestro(t("ops.report.ask.qa"))}><Bot size={12} /> {t("ops.report.qa.button")}</button>
        </div>
      </section>
      <TracesSection />
    </>
  );
}

const TEXT_FIELDS: Array<{ key: keyof Draft; rows: number }> = [
  { key: "executiveSummary", rows: 8 },
  { key: "methodology", rows: 4 },
  { key: "limitations", rows: 4 },
  { key: "conclusion", rows: 5 },
];

/** The parts of the deliverable people write; each one can be drafted by the Maestro. */
function Write(props: { draft: Draft; onSaved: () => void }) {
  const { client, engagement } = useApp();
  const [form, setForm] = useState<Draft>(props.draft);
  const [dirty, setDirty] = useState<Set<keyof Draft>>(new Set());
  const [showBranding, setShowBranding] = useState(false);
  useEffect(() => {
    // What the Maestro or someone else saved shows up, unless it is being edited here.
    setForm((cur) => {
      const next = { ...cur };
      for (const k of Object.keys(props.draft) as Array<keyof Draft>) if (!dirty.has(k)) (next as Record<string, unknown>)[k] = props.draft[k];
      return next;
    });
  }, [props.draft, dirty]);
  const set = (k: keyof Draft, v: string) => {
    setForm((f) => ({ ...f, [k]: v }));
    setDirty((d) => new Set(d).add(k));
  };
  async function saveAll() {
    const fields = Object.fromEntries([...dirty].map((k) => [k, form[k] ?? ""]));
    try {
      await client.call("report.set_draft", fields);
      setDirty(new Set());
      toast("ok", t("ops.report.saved"));
      props.onSaved();
    } catch (e) {
      toast("bad", t("common.notSaved"), (e as Error).message);
    }
  }
  return (
    <>
      <section>
        <h2>{t("ops.report.doc.title")}</h2>
        <div className="report-doc">
          <label>{t("ops.report.doc.version")}<input className="input" value={form.version ?? ""} placeholder="1.0" onChange={(e) => set("version", e.target.value)} /></label>
          <label>{t("ops.report.doc.testType")}
            <select className="input" value={form.testType ?? ""} onChange={(e) => set("testType", e.target.value)}>
              <option value="">{t("ops.report.doc.testTypeNone")}</option>
              <option value="black">{t("ops.report.doc.black")}</option>
              <option value="grey">{t("ops.report.doc.grey")}</option>
              <option value="white">{t("ops.report.doc.white")}</option>
            </select>
          </label>
          <label className="wide">{t("ops.report.doc.distribution")}<input className="input" value={form.distribution ?? ""} placeholder={t("ops.report.doc.distributionPh")} onChange={(e) => set("distribution", e.target.value)} /></label>
        </div>
      </section>
      {TEXT_FIELDS.map((f) => (
        <section key={f.key}>
          <div className="report-field-h">
            <h2>{t(`ops.report.field.${f.key}`)}</h2>
            <button className="btn sm" onClick={() => askMaestro(t(`ops.report.ask.${f.key}`))}><Wand2 size={12} /> {t("ops.report.writeWithMaestro")}</button>
          </div>
          <p className="muted report-field-hint">{t(`ops.report.fieldHint.${f.key}`)}</p>
          <textarea className="input" rows={f.rows} style={{ width: "100%" }} value={String(form[f.key] ?? "")} placeholder={t(`ops.report.fieldPh.${f.key}`)} onChange={(e) => set(f.key, e.target.value)} />
        </section>
      ))}
      <div className="report-save">
        <button className="btn primary" disabled={!dirty.size} onClick={() => void saveAll()}>{t("common.save")}</button>
        {dirty.size ? <span className="muted">{tn("ops.report.unsaved", dirty.size)}</span> : null}
      </div>
      <section>
        <h2 style={{ cursor: "pointer" }} onClick={() => setShowBranding((v) => !v)}>{t("ops.branding.title")} {showBranding ? "▾" : "▸"}</h2>
        {showBranding ? <BrandingEditor /> : <span className="muted" style={{ fontSize: 12 }}>{t("ops.branding.hint")}</span>}
      </section>
    </>
  );
}

/** Technical or executive; PDF, Word or markdown; and the preview of exactly what goes out. */
function Generate(props: { readiness?: ReportState["readiness"] }) {
  const { client, engagement } = useApp();
  const [limitations, setLimitations] = useState("");
  const [kind, setKind] = useState<"technical" | "executive">("technical");
  const [includeDrafts, setIncludeDrafts] = useState(false);
  const [busy, setBusy] = useState<string>();
  const [html, setHtml] = useState<string>();
  const desktop = window.penteosDesktop;
  const base = useMemo(() => `${t("ops.report.fileName")}${kind === "executive" ? `-${t("ops.report.executiveSuffix")}` : ""}-${(engagement?.name ?? t("ops.report.projectFallback")).toLowerCase().replace(/[^a-z0-9]+/g, "-")}`, [engagement?.name, kind]);
  async function run(what: string, work: Work) {
    setBusy(what);
    try {
      await work();
    } catch (e) {
      toast("bad", t("ops.report.exportFailed"), (e as Error).message);
    } finally {
      setBusy(undefined);
    }
  }
  function render(format: string, issue: boolean): Rendering {
    return client.call("report.render", { kind, includeDrafts, format, issue, ...(limitations.trim() ? { limitations: limitations.trim() } : {}) });
  }
  const preview = () =>
    run("preview", async () => {
      const r = await render("html", false);
      warnPluginProblems(r);
      setHtml(r.html ?? "");
    });
  const pdf = () =>
    run("pdf", async () => {
      const r = await render("html", true);
      warnPluginProblems(r);
      setHtml(r.html ?? "");
      if (!desktop?.savePdf) {
        // The browser: its own print dialog (save as PDF there).
        const w = window.open("", "_blank");
        w?.document.write(r.html ?? "");
        w?.document.close();
        w?.print();
        return;
      }
      const out = await desktop.savePdf(r.html ?? "", base);
      if (out.ok && out.path) {
        toast("ok", t("ops.report.pdfSaved"), out.path);
        void desktop.openFile?.(out.path);
      } else if (!out.canceled) throw new Error(out.error ?? t("ops.report.pdfFailed"));
    });
  const word = () =>
    run("docx", async () => {
      const r = await render("docx", true);
      warnPluginProblems(r);
      save(`${base}.docx`, bytesToBlob(r.docxBase64 ?? "", "application/vnd.openxmlformats-officedocument.wordprocessingml.document"));
    });
  const md = () =>
    run("md", async () => {
      const r = await render("markdown", true);
      save(`${base}.md`, new Blob([r.markdown ?? ""], { type: "text/markdown" }));
    });
  // Final or draft, and why: an unfinished report goes out marked as a draft on every page.
  const r = props.readiness;
  const noSummary = r ? !r.hasExecutiveSummary : false;
  const cov = r?.coverage;
  const coverageShort = cov ? !cov.determined && !limitations.trim() : false;
  const detail = cov ? [cov.phases.length ? t("ops.report.readiness.phases", { phases: cov.phases.join(", ") }) : "", cov.applicable && cov.untested ? t("ops.report.readiness.untested", { untested: cov.untested, applicable: cov.applicable }) : ""].filter(Boolean).join("; ") : "";
  return (
    <>
      {r ? (
        <section className={`report-readiness ${noSummary || coverageShort ? "draft" : "final"}`}>
          <b>{noSummary || coverageShort ? t("ops.report.readiness.draftTitle") : t("ops.report.readiness.finalTitle")}</b>
          {noSummary ? <p>{t("ops.report.readiness.noSummary")}</p> : null}
          {cov && !cov.determined ? (
            <>
              <p>{t("ops.report.readiness.coverage", { detail })}</p>
              <label className="report-limitations">
                {t("ops.report.readiness.limitationsLabel")}
                <textarea className="input" rows={2} value={limitations} placeholder={t("ops.report.readiness.limitationsPlaceholder")} onChange={(e) => { setLimitations(e.target.value); setHtml(undefined); }} />
              </label>
            </>
          ) : null}
        </section>
      ) : null}
      <section>
        <h2>{t("ops.report.kind.title")}</h2>
        <div className="report-kinds">
          {(["technical", "executive"] as const).map((k) => (
            <button key={k} className={`report-kind ${kind === k ? "on" : ""}`} onClick={() => { setKind(k); setHtml(undefined); }}>
              <b>{t(`ops.report.kind.${k}`)}</b>
              <span>{t(`ops.report.kind.${k}Hint`)}</span>
            </button>
          ))}
        </div>
        <label className="check" style={{ marginTop: 10 }}>
          <input type="checkbox" checked={includeDrafts} onChange={(e) => { setIncludeDrafts(e.target.checked); setHtml(undefined); }} />
          {t("ops.report.includeDrafts")}
        </label>
      </section>
      <section>
        <div className="report-actions">
          <button className="btn primary" disabled={Boolean(busy)} onClick={() => void pdf()}>
            {busy === "pdf" ? <RefreshCw size={13} className="spin" /> : <Download size={13} />} {t("ops.report.pdf")}
          </button>
          <button className="btn" disabled={Boolean(busy)} onClick={() => void word()}>
            {busy === "docx" ? <RefreshCw size={13} className="spin" /> : <Download size={13} />} {t("ops.report.docx")}
          </button>
          <button className="btn ghost" disabled={Boolean(busy)} onClick={() => void md()}><Download size={13} /> Markdown</button>
          <span className="grow" />
          <button className="btn ghost" disabled={Boolean(busy)} onClick={() => void preview()}>
            {busy === "preview" ? <RefreshCw size={13} className="spin" /> : <FileText size={13} />} {t("ops.report.previewButton")}
          </button>
        </div>
        <p className="muted report-note">{t("ops.report.issueNote")}</p>
        <PluginExports />
      </section>
      {html ? (
        <section>
          <h2>{t("ops.report.preview")}</h2>
          {/* Exactly what goes out: the same document the PDF is printed from. */}
          <iframe className="report-paper" title={t("ops.report.preview")} srcDoc={html} sandbox="" />
        </section>
      ) : null}
    </>
  );
}

/** What was delivered, when, and what changed since the previous version of the same kind. */
function Versions() {
  const { client, engagement } = useApp();
  const versions = useOperation<{ versions: Version[] }>("report.versions", {}, { refreshOn: (e) => e.type === "engagement.updated" });
  const list = versions.data?.versions ?? [];
  if (!list.length) return <p className="muted">{t("ops.report.versions.empty")}</p>;
  return (
    <section>
      <div className="report-field-h">
        <h2>{t("ops.report.versions.title")}</h2>
        {engagement ? (
          <button className="btn sm ghost" onClick={() => void revealProjectFolder(client, engagement.id)}><FolderOpen size={12} /> {t("ops.report.versions.folder")}</button>
        ) : null}
      </div>
      <div className="report-versions">
        {list.map((v) => (
          <div key={v.id} className="report-version">
            <div className="report-version-h">
              <b>{t(`ops.report.kind.${v.kind}`)} · {t("ops.report.versions.label", { label: v.label })}</b>
              <Badge>{v.format.toUpperCase()}</Badge>
              {v.includeDrafts ? <Badge tone="warn">{t("ops.report.versions.draft")}</Badge> : null}
              <span className="grow" />
              <span className="muted">{ago(v.at)} · {tn("ops.report.versions.findings", v.findings)}</span>
            </div>
            {v.diff ? (
              <div className="report-version-diff">
                {v.diff.added.length || v.diff.removed.length || v.diff.changed.length ? (
                  <>
                    {v.diff.added.length ? <div className="add">{t("ops.report.versions.added", { list: v.diff.added.join(", ") })}</div> : null}
                    {v.diff.removed.length ? <div className="del">{t("ops.report.versions.removed", { list: v.diff.removed.join(", ") })}</div> : null}
                    {v.diff.changed.map((c) => <div key={c.title} className="chg">{t("ops.report.versions.changed", { title: c.title, from: c.from, to: c.to })}</div>)}
                  </>
                ) : (
                  <div className="muted">{t("ops.report.versions.same")}</div>
                )}
              </div>
            ) : (
              <div className="muted report-version-diff">{t("ops.report.versions.first")}</div>
            )}
          </div>
        ))}
      </div>
    </section>
  );
}
