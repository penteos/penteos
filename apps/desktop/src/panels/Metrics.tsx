import { Activity, Plus, ShieldCheck, Trash2 } from "../ui/icons";
import { useState } from "react";
import { useApp, useOperation } from "../state";
import { toast } from "../ui/bits";
import { severity } from "../labels";
import { t, tn } from "../i18n";

/**
 * How the run went: measured on real engagements. What the agents found and
 * the verifier confirmed, what the operator says they missed, how they behaved, and how this run
 * compares with the others.
 */

interface Note {
  id: string;
  kind: "missed" | "note";
  text: string;
  at: string;
}

interface Summary {
  engagement: { id: string; name: string; client: string; mode: string };
  duration?: { from: string; to: string; minutes: number };
  surface: { hosts: number; webapps: number; endpoints: number };
  findings: { total: number; bySeverity: Record<string, number>; approved: number; inReview: number; draft: number; rejected: number };
  verifier: { reproduced: number; notReproduced: number; inconclusive: number; pending: number };
  coverage: { tested: number; total: number };
  traces: { pending: number; total: number };
  behaviour: { calls: number; errors: Record<string, number>; echoed: number; refused: number; repaired: number; stepLimit: number; wrapUp: number; ops: Record<string, number>; errorRate: number; outOfScope: number };
  missed: Note[];
  notes: Note[];
}

const SEVERITIES = ["critical", "high", "medium", "low", "info"];

const duration = (m?: number) => (m === undefined ? "-" : m < 60 ? `${m} min` : `${Math.floor(m / 60)} h ${m % 60} min`);

function Stat(props: { value: string | number; label: string; tone?: "ok" | "warn" | "bad" }) {
  return (
    <div className={`mt-stat ${props.tone ?? ""}`}>
      <div className="v">{props.value}</div>
      <div className="l">{props.label}</div>
    </div>
  );
}

function Notes(props: { kind: Note["kind"]; list: Note[] }) {
  const { client } = useApp();
  const [text, setText] = useState("");
  const add = () =>
    text.trim() &&
    client.call("run_note.add", { kind: props.kind, text: text.trim() }).then(
      () => setText(""),
      (e: Error) => toast("bad", t("ops.metrics.noteFailed"), e.message),
    );
  return (
    <div className="mt-notes">
      {props.list.map((n) => (
        <div key={n.id} className="mt-note">
          <span>{n.text}</span>
          <button className="icon-btn" title={t("common.delete")} aria-label={t("common.delete")} onClick={() => void client.call("run_note.remove", { id: n.id })}>
            <Trash2 size={12} />
          </button>
        </div>
      ))}
      <div className="mt-add">
        <input className="input" placeholder={t(`ops.metrics.${props.kind}.placeholder`)} value={text} onChange={(e) => setText(e.target.value)} onKeyDown={(e) => e.key === "Enter" && void add()} />
        <button className="btn sm" disabled={!text.trim()} onClick={() => void add()}><Plus size={12} /> {t("common.add")}</button>
      </div>
    </div>
  );
}

interface PrivacyInfo {
  level: "standard" | "off";
  masked: Record<string, number>;
  vault: { total: number };
  canaries: { total: number; leaked: number; rate: number };
  detected: Record<string, number>;
  chars: { system: number; prompt: number; tool: number };
}

/** What reached the AI models from this project, and the switch that decides it. */
function Privacy() {
  const { client } = useApp();
  const p = useOperation<PrivacyInfo>("privacy.report", {}, { refreshOn: (e: { type: string }) => e.type === "metrics.changed" });
  if (!p.data) return null;
  const d = p.data;
  const masked = Object.values(d.masked).reduce((a, b) => a + b, 0);
  const reached = Object.values(d.detected).reduce((a, b) => a + b, 0);
  const set = (level: PrivacyInfo["level"]) => client.call("privacy.set_level", { level }).then(() => p.reload(), (e: Error) => toast("bad", t("ops.metrics.noteFailed"), e.message));
  const kinds = Object.entries(d.masked).sort((a, b) => b[1] - a[1]);
  return (
    <section>
      <h2><ShieldCheck size={14} /> {t("ops.privacy.title")}</h2>
      <div className="pv-switch">
        <button className={`btn sm ${d.level === "standard" ? "primary" : ""}`} onClick={() => void set("standard")}>{t("ops.privacy.standard")}</button>
        <button className={`btn sm ${d.level === "off" ? "primary" : ""}`} onClick={() => void set("off")}>{t("ops.privacy.off")}</button>
        <span className="muted">{t(`ops.privacy.${d.level}.hint`)}</span>
      </div>
      <div className="mt-stats">
        <Stat value={masked} label={t("ops.privacy.masked")} tone={masked ? "ok" : undefined} />
        <Stat value={d.vault.total} label={t("ops.privacy.vault")} />
        <Stat value={reached} label={t("ops.privacy.reached")} tone={reached ? "warn" : "ok"} />
        {d.canaries.total ? <Stat value={`${d.canaries.rate}%`} label={t("ops.privacy.canaries")} tone={d.canaries.leaked ? "bad" : "ok"} /> : <Stat value={`${Math.round((d.chars.system + d.chars.prompt + d.chars.tool) / 1000)}k`} label={t("ops.privacy.chars")} />}
      </div>
      {kinds.length ? (
        <div className="mt-line">
          {kinds.map(([k, n]) => <span key={k} className="muted"><span className="mono">{k}</span> {n}</span>)}
        </div>
      ) : null}
    </section>
  );
}

export function MetricsPanel() {
  const { engagement } = useApp();
  const refresh = (e: { type: string; kind?: string }) => e.type === "metrics.changed" || e.kind === "finding";
  const summary = useOperation<Summary>("metrics.summary", {}, { refreshOn: refresh });
  const all = useOperation<Summary[]>("metrics.compare", {}, { refreshOn: refresh });
  const s = summary.data;
  if (!s) return <div className="panel"><div className="panel-scroll"><p className="muted" style={{ padding: 16 }}>{t("common.loading")}</p></div></div>;
  const b = s.behaviour;
  const topErrors = Object.entries(b.errors).sort((x, y) => y[1] - x[1]).slice(0, 6);
  const topOps = Object.entries(b.ops).sort((x, y) => y[1] - x[1]).slice(0, 8);
  const others = (all.data ?? []).filter((r) => r.engagement.id !== engagement?.id && (r.behaviour.calls > 0 || r.findings.total > 0));
  return (
    <div className="panel">
      <div className="panel-toolbar">
        <Activity size={14} />
        <h3>{t("ops.metrics.title")}</h3>
        <span className="hint">{s.duration ? t("ops.metrics.span", { time: duration(s.duration.minutes) }) : t("ops.metrics.noAgentYet")}</span>
      </div>
      <div className="panel-scroll">
        <div className="metrics">
          <section>
            <h2>{t("ops.metrics.results")}</h2>
            <div className="mt-stats">
              <Stat value={s.findings.total} label={t("ops.metrics.findings")} />
              <Stat value={s.findings.approved} label={t("ops.metrics.approved")} tone={s.findings.approved ? "ok" : undefined} />
              <Stat value={s.verifier.reproduced} label={t("ops.metrics.reproduced")} tone={s.verifier.reproduced ? "ok" : undefined} />
              <Stat value={s.verifier.notReproduced} label={t("ops.metrics.notReproduced")} tone={s.verifier.notReproduced ? "warn" : undefined} />
              <Stat value={s.missed.length} label={t("ops.metrics.missedCount")} tone={s.missed.length ? "bad" : undefined} />
            </div>
            <div className="mt-line">
              {SEVERITIES.filter((x) => s.findings.bySeverity[x]).map((x) => (
                <span key={x} className={`sev ${x}`}>{s.findings.bySeverity[x]} {severity(x)}</span>
              ))}
              <span className="muted">{t("ops.metrics.surface", { hosts: s.surface.hosts, apps: s.surface.webapps, endpoints: s.surface.endpoints })}</span>
              {s.coverage.total ? <span className="muted">{t("ops.metrics.coverage", { pct: Math.round((s.coverage.tested / s.coverage.total) * 100) })}</span> : null}
              {s.traces.pending ? <span className="warn-text">{tn("ops.metrics.traces", s.traces.pending)}</span> : null}
            </div>
          </section>

          <Privacy />

          <section>
            <h2>{t("ops.metrics.missedTitle")}</h2>
            <p className="muted">{t("ops.metrics.missedIntro")}</p>
            <Notes kind="missed" list={s.missed} />
          </section>

          <section>
            <h2>{t("ops.metrics.behaviour")}</h2>
            <div className="mt-stats">
              <Stat value={b.calls} label={t("ops.metrics.calls")} />
              <Stat value={`${b.errorRate}%`} label={t("ops.metrics.errorRate")} tone={b.errorRate > 15 ? "warn" : undefined} />
              <Stat value={b.echoed + b.refused} label={t("ops.metrics.loops")} tone={b.refused ? "warn" : undefined} />
              <Stat value={b.stepLimit} label={t("ops.metrics.stepLimit")} tone={b.stepLimit ? "warn" : undefined} />
              <Stat value={b.outOfScope} label={t("ops.metrics.outOfScope")} tone={b.outOfScope ? "bad" : "ok"} />
            </div>
            <div className="mt-cols">
              <div>
                <h3 className="mt-sub">{t("ops.metrics.errorsBy")}</h3>
                {topErrors.length ? topErrors.map(([code, n]) => <div key={code} className="mt-kv"><span className="mono">{code}</span><span>{n}</span></div>) : <p className="muted">{t("ops.metrics.noErrors")}</p>}
                {b.repaired ? <div className="mt-kv muted"><span>{t("ops.metrics.repaired")}</span><span>{b.repaired}</span></div> : null}
                {b.wrapUp ? <div className="mt-kv muted"><span>{t("ops.metrics.wrapUp")}</span><span>{b.wrapUp}</span></div> : null}
              </div>
              <div>
                <h3 className="mt-sub">{t("ops.metrics.topOps")}</h3>
                {topOps.map(([op, n]) => <div key={op} className="mt-kv"><span className="mono">{op}</span><span>{n}</span></div>)}
              </div>
            </div>
          </section>

          <section>
            <h2>{t("ops.metrics.notesTitle")}</h2>
            <Notes kind="note" list={s.notes} />
          </section>

          {others.length ? (
            <section>
              <h2>{t("ops.metrics.compare")}</h2>
              <div className="mt-table">
                <div className="mt-row head">
                  <span>{t("ops.metrics.col.project")}</span>
                  <span>{t("ops.metrics.col.time")}</span>
                  <span>{t("ops.metrics.col.findings")}</span>
                  <span>{t("ops.metrics.col.reproduced")}</span>
                  <span>{t("ops.metrics.col.missed")}</span>
                  <span>{t("ops.metrics.col.errors")}</span>
                  <span>{t("ops.metrics.col.stepLimit")}</span>
                </div>
                {[s, ...others].map((r) => (
                  <div key={r.engagement.id} className={`mt-row ${r.engagement.id === engagement?.id ? "current" : ""}`}>
                    <span title={`${r.engagement.client} / ${r.engagement.name}`}>{r.engagement.client} / {r.engagement.name}</span>
                    <span>{duration(r.duration?.minutes)}</span>
                    <span>{r.findings.total} <span className="muted">({r.findings.approved})</span></span>
                    <span>{r.verifier.reproduced}</span>
                    <span className={r.missed.length ? "bad-text" : ""}>{r.missed.length}</span>
                    <span>{r.behaviour.errorRate}%</span>
                    <span>{r.behaviour.stepLimit}</span>
                  </div>
                ))}
              </div>
            </section>
          ) : null}
        </div>
      </div>
    </div>
  );
}
