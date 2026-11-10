import { Ban, CalendarClock, Check, CheckCircle2, Loader2, Play, Upload } from "../ui/icons";
import { modeOf } from "../modes";
import { importFile } from "../ui/importFile";
import { PhasesSection } from "../ui/Phases";
import { type ReactNode, useEffect, useState } from "react";
import { type Run, useApp, useOperation } from "../state";
import { ActorBadge, relTime, toast, useTick } from "../ui/bits";
import { AUTONOMY_ES, label, risk } from "../labels";
import { t, tn } from "../i18n";
import { revealProjectFolder } from "../ui/files";

type Step = { title: string; text: ReactNode; done: boolean; action?: ReactNode; extra?: ReactNode };

/**
 * Where this project lives on disk, so the operator can find it, back it up or move it - and open
 * the folder in one click. Only in the desktop app and local mode; on the web or in team mode the
 * files are on the server, so there is nothing local to reveal.
 */
function ProjectLocation(props: { id: string }) {
  const { client } = useApp();
  const [info, setInfo] = useState<{ dir: string; home: string } | null>(null);
  useEffect(() => {
    let live = true;
    void (async () => {
      const where = await window.penteosDesktop?.projectDir?.().catch(() => undefined);
      if (!where || where.remote) return;
      // The folder the project really is in (it may be any folder the operator chose).
      const r = await client.call<{ dir: string }>("project.dir", { id: props.id }).catch(() => ({ dir: `${where.dataDir}/engagements/${props.id}` }));
      if (live) setInfo({ dir: r.dir, home: where.home });
    })();
    return () => {
      live = false;
    };
  }, [client, props.id]);
  if (!info) return null;
  const full = info.dir;
  const shown = full.startsWith(info.home) ? `~${full.slice(info.home.length)}` : full;
  return (
    <div className="project-loc">
      <span className="muted">{t("start.home.folder")}</span>
      <span className="mono path" title={full}>{shown}</span>
      <button className="link-btn" onClick={() => void revealProjectFolder(client, props.id)}>{t("start.home.reveal")}</button>
    </div>
  );
}

export function summarize(ingested: { created?: Record<string, number>; edges?: number }): string {
  const parts = Object.entries(ingested.created ?? {}).map(([k, n]) => `${n} ${k}`);
  return parts.length ? t("start.home.ingested", { list: parts.join(", ") }) : t("start.home.noNewEntities");
}

const RUN_ICON: Record<Run["status"], ReactNode> = {
  running: <Loader2 size={14} className="spin" />,
  finished: <CheckCircle2 size={14} />,
  failed: <Ban size={14} />,
  denied: <Ban size={14} />,
  cancelled: <Ban size={14} />,
};

/**
 * Start page of an engagement. It answers "where am I and what do I do next" with the steps of
 * the engagement, each one tied to the real state of the data.
 */
export function HomePanel() {
  const { engagement } = useApp();
  return <StepsHome />;
}

/** One line with how much of the OWASP checklist is covered, and the way to the matrix. */
function CoverageSummary() {
  const { workbench } = useApp();
  const m = useOperation<{ categories: unknown[]; apps: Array<{ origin: string; coverage: Array<{ status: string }> }> }>("coverage.matrix", {}, { refreshOn: (e) => e.kind === "webapp" });
  const apps = m.data?.apps ?? [];
  if (!apps.length) return null;
  const total = apps.length * (m.data?.categories.length ?? 0);
  const covered = apps.reduce((n, a) => n + a.coverage.filter((c) => c.status !== "untested" && c.status !== "in_progress").length, 0);
  const vuln = apps.reduce((n, a) => n + a.coverage.filter((c) => c.status === "vulnerable").length, 0);
  return (
    <section>
      <h2>{t("start.home.coverage")}</h2>
      <div className="clickable" onClick={() => workbench.openPanel("coverage")} title={t("start.home.coverage.open")}>
        <div style={{ display: "flex", alignItems: "baseline", gap: 10, marginBottom: 10 }}>
          <span><span className="mono" style={{ color: "var(--fg-0)" }}>{covered}</span> {t("start.home.coverage.of", { total })} · {tn("start.home.coverage.apps", apps.length)}{vuln ? <> · <span style={{ color: "var(--bad)" }}>{tn("start.home.coverage.vulnerable", vuln)}</span></> : null}</span>
          <span style={{ flex: 1 }} />
          <span className="muted">{t("start.home.coverage.missing")}</span>
        </div>
        <div className="cov-strip">
          {apps.map((a, i) => (
            <div key={i} className="app">
              {a.coverage.map((c, j) => <div key={j} className={`t ${c.status === "tested" ? "ok" : c.status === "partial" ? "part" : c.status === "vulnerable" ? "bad" : c.status === "in_progress" ? "doing" : c.status === "n/a" ? "na" : ""}`} />)}
            </div>
          ))}
        </div>
        <div className="cov-strip-labels">{apps.map((a, i) => <span key={i}>{a.origin.replace(/^https?:\/\//, "")}</span>)}</div>
      </div>
    </section>
  );
}

function StepsHome() {
  const { engagement, client, workbench } = useApp();
  const mode = engagement?.mode ?? "web";
  const round = engagement?.roundMode ?? "pentest";
  const schedules = useOperation<unknown[]>("schedule.list", {}, { refreshOn: (e) => e.type === "engagement.updated" });
  const findings = useOperation<Array<{ tags: string[]; attributes: Record<string, any> }>>("entity.query", { kind: "finding", limit: 5000 }, { refreshOn: (e) => e.kind === "finding" });
  const now = useTick();
  const runs = useOperation<Run[]>("run.list", { limit: 6 }, { refreshOn: (e) => e.type.startsWith("run.") });
  const services = useOperation<Array<{ attributes: Record<string, any> }>>("entity.query", { kind: "service", limit: 5000 }, { refreshOn: (e) => e.kind === "service" });
  const [target, setTarget] = useState("");
  const [busy, setBusy] = useState(false);
  const [guide, setGuide] = useState(false);

  if (!engagement) return null;
  const c = engagement.counts;
  const open = (services.data ?? []).filter((s) => s.attributes.state === "open").length;
  const includes = engagement.scope.filter((r) => r.effect === "include");

  async function scan() {
    const tgt = target.trim();
    if (!tgt) return;
    setBusy(true);
    try {
      const r = await client.call<{ runId?: string; status: string }>("tool.run", { tool: "nmap", preset: "quick", targets: [tgt] });
      if (r.runId) workbench.openRun(r.runId);
      else toast("info", t("start.home.scan.pending"), t("start.home.scan.pendingBody"));
      setTarget("");
    } catch (e) {
      toast("bad", t("start.home.scan.blocked"), (e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  const base: Step[] = [
    {
      title: t("start.home.step.scope"),
      text: includes.length
        ? tn("start.home.step.scope.set", includes.length, { list: `${includes.slice(0, 3).map((r) => r.target.value ?? r.target.from).join(", ")}${includes.length > 3 ? "…" : ""}` })
        : t("start.home.step.scope.empty"),
      done: includes.length > 0,
      action: <button className="btn sm" onClick={() => workbench.openPanel("scope")}>{t("start.home.step.scope.edit")}</button>,
    },
    {
      title: t("start.home.step.recon"),
      text: t("start.home.step.recon.text"),
      done: (c.host ?? 0) > 0,
      extra: (
        <div className="inline">
          <input className="input mono" placeholder={includes[0]?.target.value ?? t("start.home.step.recon.placeholder")} value={target} onChange={(e) => setTarget(e.target.value)} onKeyDown={(e) => e.key === "Enter" && scan()} />
          <button className="btn primary" onClick={scan} disabled={busy}>
            <Play size={13} /> {t("start.home.step.recon.scan")}
          </button>
        </div>
      ),
    },
    {
      title: t("start.home.step.surface"),
      text: (c.service ?? 0) > 0
        ? t("start.home.step.surface.found", { open, hosts: c.host ?? 0 })
        : t("start.home.step.surface.empty"),
      done: (c.service ?? 0) > 0 && (c.finding ?? 0) > 0,
      action: <button className="btn sm" onClick={() => workbench.openPanel("services")}>{t("start.home.step.surface.open")}</button>,
    },
    {
      title: t("start.home.step.findings"),
      text: t("start.home.step.findings.text"),
      done: (c.finding ?? 0) > 0,
      action: <button className="btn sm" onClick={() => workbench.openPanel("findings")}>{t("start.home.step.findings.open")}</button>,
    },
    {
      title: t("start.home.step.report"),
      text: t("start.home.step.report.text"),
      done: false,
      action: <button className="btn sm" onClick={() => workbench.openPanel("report")}>{t("start.home.step.report.open")}</button>,
    },
  ];
  const [scopeStep, reconStep, surfaceStep, findingsStep, reportStep] = base as [Step, Step, Step, Step, Step];
  const retestFindings = (findings.data ?? []).filter((f) => f.tags.includes("retest"));
  const toVerify = retestFindings.filter((f) => f.attributes.status === "reported").length;
  const steps: Step[] =
    round === "continuous"
      ? [
          scopeStep,
          { ...reconStep, title: t("start.home.step.firstScan") },
          {
            title: t("start.home.step.schedule"),
            text: (schedules.data ?? []).length
              ? tn("start.home.step.schedule.set", (schedules.data ?? []).length)
              : t("start.home.step.schedule.empty"),
            done: (schedules.data ?? []).length > 0,
            action: <button className="btn sm" onClick={() => workbench.openPanel("evolution")}><CalendarClock size={12} /> {t("start.home.step.schedule.open")}</button>,
          },
          { title: t("start.home.step.changes"), text: t("start.home.step.changes.text"), done: false, action: <button className="btn sm" onClick={() => workbench.openPanel("evolution")}>{t("start.home.step.changes.open")}</button> },
          reportStep,
        ]
      : round === "retest"
        ? [
            { ...scopeStep, title: t("start.home.step.confirmScope"), text: `${scopeStep.text} ${t("start.home.step.confirmScope.inherited")}` },
            {
              title: t("start.home.step.verify"),
              text: retestFindings.length
                ? toVerify
                  ? t("start.home.step.verify.pending", { pending: toVerify, total: retestFindings.length })
                  : tn("start.home.step.verify.done", retestFindings.length)
                : t("start.home.step.verify.none"),
              done: retestFindings.length > 0 && toVerify === 0,
              action: <button className="btn sm" onClick={() => workbench.openPanel("findings")}>{t("start.home.step.findings.open")}</button>,
            },
            { title: t("start.home.step.compare"), text: t("start.home.step.compare.text"), done: false, action: <button className="btn sm" onClick={() => workbench.openPanel("evolution")}>{t("start.home.step.compare.open")}</button> },
            reportStep,
          ]
        : mode === "infra"
          ? [
              scopeStep,
              {
                ...reconStep,
                text: t("start.home.step.recon.internal"),
                action: <button className="btn sm" onClick={() => importFile(client)}><Upload size={12} /> {t("start.home.step.import")}</button>,
              },
              surfaceStep,
              findingsStep,
              reportStep,
            ]
          : base;
  const current = steps.findIndex((s) => !s.done);
  // Once the project has data the guide has done its job: it folds, one click brings it back.
  const hasData = (c.host ?? 0) > 0 || (c.finding ?? 0) > 0 || (c.webapp ?? 0) > 0;

  return (
    <div className="home">
      <div className="home-inner">
        <div>
          <h1>{engagement.name}</h1>
          <div className="sub">
            <span>{engagement.clientName}</span>
            <span className="muted">·</span>
            <span>{modeOf(engagement.mode).title}</span>
            <span className="muted">·</span>
            <span>{t("start.home.maxRisk", { risk: risk(engagement.maxRisk) })}</span>
            <span className="muted">·</span>
            <span className="clickable-text" title={t("start.home.aiLevel.hint")} onClick={() => window.dispatchEvent(new Event("penteos:ai-level"))}>{t("start.home.aiLevel", { level: label(AUTONOMY_ES, engagement.autonomy) })}</span>
            {engagement.stopWork?.active ? <span style={{ color: "var(--bad)" }}>{t("start.home.stopWork")}</span> : null}
          </div>
          <ProjectLocation id={engagement.id} />
        </div>

        <PhasesSection />

        {mode === "web" ? <CoverageSummary /> : null}

        <section>
          <h2>
            {t("start.home.guide")}
            {hasData ? <button className="btn ghost sm" style={{ marginLeft: 8 }} onClick={() => setGuide((v) => !v)}>{guide ? t("common.hide") : t("common.show")}</button> : null}
          </h2>
          {hasData && !guide ? null : (
          <div className="steps">
            {steps.map((s, i) => (
              <div key={s.title} className={`step ${s.done ? "done" : ""} ${i === current ? "current" : ""}`}>
                <div className="num">{s.done ? <Check size={12} /> : i + 1}</div>
                <div>
                  <div className="t">{s.title}</div>
                  <div className="d">{s.text}</div>
                  {i === current && s.extra ? s.extra : null}
                </div>
                <div>{s.action}</div>
              </div>
            ))}
          </div>
          )}
        </section>

        <section>
          <h2>{t("start.home.surface")}</h2>
          <div className="stats">
            <div className="stat" onClick={() => workbench.openPanel("hosts")}><div className="v">{c.host ?? 0}</div><div className="l">{t("start.home.stat.hosts")}</div></div>
            <div className="stat" onClick={() => workbench.openPanel("services")}><div className="v">{open}</div><div className="l">{t("start.home.stat.openServices")}</div></div>
            <div className="stat" onClick={() => workbench.openPanel("domains")}><div className="v">{c.domain ?? 0}</div><div className="l">{t("start.home.stat.domains")}</div></div>
            <div className="stat" onClick={() => workbench.openPanel("findings")}><div className="v">{c.finding ?? 0}</div><div className="l">{t("start.home.stat.findings")}</div></div>
          </div>
        </section>

        <section>
          <h2>{t("start.home.runs")}</h2>
          <div className="list">
            {(runs.data ?? []).length === 0 ? (
              <div className="row"><span /><span className="muted">{t("start.home.runs.empty")}</span><span /></div>
            ) : (
              (runs.data ?? []).map((r) => (
                <div key={r.id} className="row clickable" onClick={() => workbench.openRun(r.id)}>
                  <span className={`ic ${r.status === "finished" ? "ok" : r.status === "denied" || r.status === "failed" ? "bad" : ""}`}>{RUN_ICON[r.status]}</span>
                  <div style={{ minWidth: 0 }}>
                    <div className="t mono">{r.command}</div>
                    <div className="s">{r.status === "denied" ? t("start.home.runs.denied", { reason: r.policy.reason }) : r.summary?.ingested ? summarize(r.summary.ingested) : r.targets.join(", ")}</div>
                  </div>
                  <div className="when"><ActorBadge actor={r.actor} />{relTime(r.startedAt, now)}</div>
                </div>
              ))
            )}
          </div>
        </section>
      </div>
    </div>
  );
}
