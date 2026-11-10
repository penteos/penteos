import { Bot, Grid3x3 } from "../ui/icons";
import { useState } from "react";
import { useApp, useOperation } from "../state";
import { Empty, toast } from "../ui/bits";
import { t, tn } from "../i18n";
import { HelpHint } from "../ui/HelpHint";
import { wstgName } from "../labels";

/**
 * Coverage: the OWASP WSTG checklist of every application at once. It answers
 * the question a professional asks before closing the analysis: what did nobody look at yet?
 */

/** `label` is a getter so it is read in the operator's language when shown. */
const coverageStatus = (key: string, short: string, tone: string) => ({
  short,
  tone,
  get label() {
    return t(`start.coverage.status.${key}`);
  },
});
export const COVERAGE: Record<string, { label: string; short: string; tone: string }> = {
  untested: coverageStatus("untested", "-", "untested"),
  in_progress: coverageStatus("in_progress", "…", "doing"),
  tested: coverageStatus("tested", "ok", "ok"),
  partial: coverageStatus("partial", "½", "part"),
  vulnerable: coverageStatus("vulnerable", "vuln", "bad"),
  "n/a": coverageStatus("na", "n/a", "na"),
};

interface Matrix {
  categories: Array<{ id: string; title: string; titleEn?: string }>;
  apps: Array<{ id: string; origin: string; findings: number; coverage: Array<{ id: string; status: string; note?: string }> }>;
}

function Cell(props: { appId: string; cat: { id: string; title: string; titleEn?: string }; cell: { status: string; note?: string } }) {
  const { client } = useApp();
  const [open, setOpen] = useState(false);
  const c = COVERAGE[props.cell.status] ?? COVERAGE.untested!;
  const set = (status: string) => {
    setOpen(false);
    client.call("webapp.set_coverage", { webappId: props.appId, category: props.cat.id, status }).catch((e: Error) => toast("bad", t("common.notSaved"), e.message));
  };
  return (
    <td className={`cov-cell ${c.tone}`} title={`${wstgName(props.cat)}: ${c.label}${props.cell.note ? `\n${props.cell.note}` : ""}`} onClick={() => setOpen((v) => !v)}>
      <span>{c.short}</span>
      {open ? (
        <div className="cov-menu" onMouseLeave={() => setOpen(false)}>
          {Object.entries(COVERAGE).map(([k, v]) => (
            <button key={k} className={`cov-opt ${v.tone} ${k === props.cell.status ? "on" : ""}`} onClick={(e) => { e.stopPropagation(); set(k); }}>{v.label}</button>
          ))}
          {props.cell.note ? <div className="cov-note">{props.cell.note}</div> : null}
        </div>
      ) : null}
    </td>
  );
}

export function CoveragePanel() {
  const { engagement } = useApp();
  const m = useOperation<Matrix>("coverage.matrix", {}, { refreshOn: (e) => e.kind === "webapp" || e.kind === "finding" });
  const data = m.data;
  const apps = data?.apps ?? [];
  const cats = data?.categories ?? [];
  const total = apps.length * cats.length;
  const covered = apps.reduce((n, a) => n + a.coverage.filter((c) => c.status !== "untested" && c.status !== "in_progress").length, 0);
  const vulnerable = apps.reduce((n, a) => n + a.coverage.filter((c) => c.status === "vulnerable").length, 0);
  const ask = (text: string) => window.dispatchEvent(new CustomEvent("penteos:ask-maestro", { detail: text }));

  return (
    <div className="panel">
      <div className="panel-toolbar">
        <Grid3x3 size={14} />
        <h3>{t("start.coverage.title")}</h3>
        {total ? <span className="count">{t("start.coverage.count", { covered, total, vulnerable })}</span> : null}
        <HelpHint id="coverage" text={t("start.coverage.hint")} />
        <div className="grow" />
        {total && covered < total && engagement ? (
          <button className="btn sm" onClick={() => ask(t("start.coverage.ask.prompt"))}>
            <Bot size={12} /> {t("start.coverage.ask")}
          </button>
        ) : null}
      </div>
      <div className="panel-scroll">
        {apps.length === 0 ? (
          <Empty icon={<Grid3x3 size={20} />} title={t("start.coverage.empty.title")}>
            {t("start.coverage.empty.text")}
          </Empty>
        ) : (
          <div className="cov-wrap">
            {total ? (
              <div className="cov-progress">
                <div className="bar"><div style={{ width: `${(covered / total) * 100}%` }} /></div>
                <span className="muted">{t("start.coverage.percent", { pct: Math.round((covered / total) * 100) })}</span>
              </div>
            ) : null}
            <table className="cov-table">
              <thead>
                <tr>
                  <th className="cat">{t("start.coverage.category")}</th>
                  {apps.map((a) => (
                    <th key={a.id} className="app" title={a.origin}>
                      <span className="mono">{a.origin.replace(/^https?:\/\//, "")}</span>
                      <span className="muted">{tn("start.coverage.findings", a.findings)}</span>
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {cats.map((cat) => (
                  <tr key={cat.id}>
                    <td className="cat"><span className="mono muted">{cat.id}</span> {wstgName(cat)}</td>
                    {apps.map((a) => <Cell key={a.id} appId={a.id} cat={cat} cell={a.coverage.find((c) => c.id === cat.id) ?? { status: "untested" }} />)}
                  </tr>
                ))}
              </tbody>
            </table>
            <div className="cov-legend">
              {Object.values(COVERAGE).map((v) => <span key={v.label} className={`cov-key ${v.tone}`}><i /> {v.label}</span>)}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
