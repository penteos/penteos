import { Calculator } from "./icons";
import { useEffect, useMemo, useState } from "react";
import { useApp } from "../state";
import { toast } from "./bits";
import { t } from "../i18n";
import { SEVERITY_ES as SEV_ES } from "../labels";

/** CVSS 4.0 base metrics, scored by the core with the official FIRST algorithm. */

/** Metric ids and their values, in CVSS order. Labels: work.cvss.<id> and work.cvss.<id>.<value>. */
const IMPACT = ["H", "L", "N"];
const METRICS: Array<{ id: string; options: string[] }> = [
  { id: "AV", options: ["N", "A", "L", "P"] },
  { id: "AC", options: ["L", "H"] },
  { id: "AT", options: ["N", "P"] },
  { id: "PR", options: ["N", "L", "H"] },
  { id: "UI", options: ["N", "P", "A"] },
  { id: "VC", options: IMPACT },
  { id: "VI", options: IMPACT },
  { id: "VA", options: IMPACT },
  { id: "SC", options: IMPACT },
  { id: "SI", options: IMPACT },
  { id: "SA", options: IMPACT },
];
const DEFAULTS: Record<string, string> = { AV: "N", AC: "L", AT: "N", PR: "N", UI: "N", VC: "N", VI: "N", VA: "N", SC: "N", SI: "N", SA: "N" };

function parse(vector?: string): Record<string, string> {
  const out = { ...DEFAULTS };
  if (!vector?.startsWith("CVSS:4.0/")) return out;
  for (const part of vector.slice(9).split("/")) {
    const [k, v] = part.split(":");
    if (k && v && k in out) out[k] = v;
  }
  return out;
}

export function CvssCalculator(props: { findingId: string; current?: { version: string; vector: string; score: number }; severity: string }) {
  const { client } = useApp();
  const [values, setValues] = useState(() => parse(props.current?.vector));
  const [score, setScore] = useState<{ score: number; severity: string }>();
  const [open, setOpen] = useState(Boolean(props.current));
  const vector = useMemo(() => `CVSS:4.0/${METRICS.map((m) => `${m.id}:${values[m.id]}`).join("/")}`, [values]);

  useEffect(() => {
    if (!open) return;
    client.call<{ score: number; severity: string }>("cvss.score", { vector }).then(setScore, () => setScore(undefined));
  }, [vector, open, client]);

  async function apply() {
    const r = await client.call<{ score: number; suggestedSeverity: string; severity: string }>("finding.set_cvss", { id: props.findingId, vector }).catch((e: Error) => {
      toast("bad", t("work.cvss.invalid"), e.message);
      return undefined;
    });
    if (r) toast("ok", t("work.cvss.saved", { score: r.score }), r.suggestedSeverity !== r.severity ? t("work.cvss.suggests", { severity: SEV_ES[r.suggestedSeverity] }) : undefined);
  }
  async function useSeverity() {
    if (!score) return;
    await client.call("finding.update", { id: props.findingId, severity: score.severity }).catch((e: Error) => toast("bad", t("common.error"), e.message));
  }

  return (
    <div className="cvss">
      <div className="section-title" style={{ cursor: "pointer" }} onClick={() => setOpen((v) => !v)}>
        <Calculator size={12} /> CVSS 4.0 {props.current ? <span className="mono" style={{ textTransform: "none", letterSpacing: 0 }}>· {props.current.score} ({props.current.version})</span> : null} {open ? "▾" : "▸"}
      </div>
      {open ? (
        <div className="cvss-body">
          <div className="cvss-grid">
            {METRICS.map((m) => (
              <div key={m.id} className="cvss-metric">
                <span className="lbl">{t(`work.cvss.${m.id}`)} <span className="mono muted">{m.id}</span></span>
                <div className="seg sm">
                  {m.options.map((v) => (
                    <button key={v} className={values[m.id] === v ? "on" : ""} onClick={() => setValues((x) => ({ ...x, [m.id]: v }))}>{t(`work.cvss.${m.id}.${v}`)}</button>
                  ))}
                </div>
              </div>
            ))}
          </div>
          <div className="cvss-result">
            {score ? <span className={`cvss-score sev-${score.severity}`}>{score.score.toFixed(1)}</span> : <span className="cvss-score">-</span>}
            <span>{score ? SEV_ES[score.severity] : ""}</span>
            <code className="mono vector">{vector}</code>
            <div className="grow" />
            {score && score.severity !== props.severity ? <button className="btn sm ghost" onClick={useSeverity}>{t("work.cvss.useSeverity", { severity: SEV_ES[score.severity] })}</button> : null}
            <button className="btn sm primary" onClick={apply}>{t("work.cvss.save")}</button>
          </div>
        </div>
      ) : null}
    </div>
  );
}
