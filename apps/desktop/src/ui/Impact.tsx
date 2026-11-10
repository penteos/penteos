import { ChevronDown, ChevronRight, Crosshair, Lightbulb } from "./icons";
import { useState } from "react";
import { useApp } from "../state";
import { Badge, toast } from "./bits";
import { Markdown } from "./Markdown";
import { t } from "../i18n";

/**
 * Deepening a finding: how far it reaches, what the exposed data allows and
 * what it chains with. Penteos opens the questions on serious findings; the agent answers them
 * with evidence, and the answers go into the report as demonstrated impact.
 */

type Key = "reach" | "exposed" | "chain";

export interface ImpactState {
  reason: string;
  questions: Array<{ key: Key; status: "open" | "answered" | "not_applicable"; answer?: string; evidenceIds?: string[] }>;
}

interface Leads {
  leads: Record<Key, Array<{ text: string; tool?: string }>>;
}

const TONE: Record<string, "ok" | "warn" | ""> = { answered: "ok", not_applicable: "", open: "warn" };

/** Small badge for lists: impact questions still open. */
export function ImpactBadge(props: { d?: ImpactState }) {
  const open = props.d?.questions.filter((q) => q.status === "open").length ?? 0;
  if (!props.d || !open) return null;
  return (
    <Badge tone="warn" title={t("work.impact.badgeHint")}>
      <Crosshair size={11} /> {t("work.impact.badge", { n: open })}
    </Badge>
  );
}

export function ImpactBox(props: { findingId: string; d?: ImpactState; closed: boolean }) {
  const { client } = useApp();
  const { d } = props;
  const [leads, setLeads] = useState<Leads["leads"]>();
  const [showLeads, setShowLeads] = useState(false);

  async function open() {
    const reason = window.prompt(t("work.impact.openPrompt"), t("work.impact.openDefault"));
    if (!reason?.trim()) return;
    await client.call("finding.deepen", { id: props.findingId, reason }).then(
      () => toast("ok", t("work.impact.opened")),
      (e: Error) => toast("bad", t("common.notSaved"), e.message),
    );
  }
  async function notApplicable(key: Key) {
    const answer = window.prompt(t("work.impact.naPrompt"), "");
    if (!answer?.trim()) return;
    await client.call("finding.answer_impact", { id: props.findingId, key, status: "not_applicable", answer }).then(
      () => toast("ok", t("work.impact.recorded")),
      (e: Error) => toast("bad", t("common.notSaved"), e.message),
    );
  }
  async function toggleLeads() {
    if (!showLeads && !leads) {
      try {
        const r = await client.call<Leads>("finding.impact", { id: props.findingId });
        setLeads(r.leads);
      } catch (e) {
        toast("bad", t("work.impact.leadsFailed"), (e as Error).message);
        return;
      }
    }
    setShowLeads(!showLeads);
  }

  if (!d) {
    if (props.closed) return null;
    return (
      <div className="verify-box impact-box">
        <div className="vb-head">
          <Crosshair size={15} />
          <div className="vb-title">{t("work.impact.none")}</div>
          <div className="grow" />
          <button className="btn sm" onClick={open} title={t("work.impact.openHint")}>{t("work.impact.open")}</button>
        </div>
      </div>
    );
  }

  const pending = d.questions.filter((q) => q.status === "open").length;
  return (
    <div className={`verify-box impact-box ${pending ? "warn" : "ok"}`}>
      <div className="vb-head">
        <Crosshair size={15} />
        <div className="vb-title">{pending ? t("work.impact.pending", { n: pending }) : t("work.impact.done")}</div>
        <div className="grow" />
        <button className="btn sm ghost" onClick={toggleLeads}>
          {showLeads ? <ChevronDown size={12} /> : <ChevronRight size={12} />} <Lightbulb size={12} /> {t("work.impact.leads")}
        </button>
      </div>
      <div className="impact-rows">
        {d.questions.map((q) => (
          <div key={q.key} className="impact-row">
            <div className="impact-q">
              <span className="impact-name">{t(`work.impact.key.${q.key}`)}</span>
              <Badge tone={TONE[q.status] ?? ""}>{t(`work.impact.status.${q.status}`)}</Badge>
              {q.status === "open" && !props.closed ? (
                <button className="btn sm ghost" onClick={() => notApplicable(q.key)}>{t("work.impact.markNa")}</button>
              ) : null}
            </div>
            {q.answer ? <div className="vb-summary"><Markdown text={q.answer} /></div> : <div className="vb-summary muted">{t(`work.impact.question.${q.key}`)}</div>}
          </div>
        ))}
      </div>
      {showLeads && leads ? (
        <div className="impact-leads">
          {(["reach", "exposed", "chain"] as const).flatMap((k) =>
            leads[k].map((l, i) => (
              <div key={`${k}-${i}`} className="impact-lead">
                <span className="impact-name">{t(`work.impact.key.${k}`)}</span>
                <span>{l.text}</span>
              </div>
            )),
          )}
        </div>
      ) : null}
    </div>
  );
}
