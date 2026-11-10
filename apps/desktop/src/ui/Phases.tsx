import { Lock, Unlock } from "./icons";
import { useState } from "react";
import { can, useApp, useOperation } from "../state";
import { Markdown } from "./Markdown";
import { toast } from "./bits";
import { t } from "../i18n";

export interface Phase {
  id: string;
  title: string;
  goal: string;
  status: "pending" | "current" | "done";
  plan?: string;
  summary?: string;
  exploitation: boolean;
}
export interface Plan {
  phases: Phase[];
  current: string | null;
}

export function usePlan() {
  return useOperation<Plan>("plan.get", {}, { refreshOn: (e) => e.type === "engagement.updated" });
}

/** Compact strip above the conversation: where the work is, at a glance. */
export function PhaseStrip() {
  const { workbench } = useApp();
  const plan = usePlan();
  const phases = plan.data?.phases ?? [];
  if (phases.length === 0) return null;
  const idx = phases.findIndex((p) => p.id === plan.data?.current);
  const cur = phases[idx];
  return (
    <button className="phase-strip" onClick={() => workbench.openPanel("home")} title={t("start.phases.open")}>
      <div className="dots">
        {phases.map((p) => (
          <span key={p.id} className={`dot ${p.status}`} title={p.title} />
        ))}
      </div>
      <span className="label">
        {t("start.phases.strip", { i: idx + 1, n: phases.length })} · <b>{cur?.title}</b>
      </span>
      {cur ? cur.exploitation ? <Unlock size={11} className="lock open" /> : <Lock size={11} className="lock" /> : null}
    </button>
  );
}

/** The phases in full, on the start page: goal, plan, results; a human can move between them. */
export function PhasesSection() {
  const { client, me } = useApp();
  const plan = usePlan();
  const [open, setOpen] = useState<string>();
  const phases = plan.data?.phases ?? [];
  if (phases.length === 0) return null;
  const mayMove = can(me, "operator");
  async function move(p: Phase) {
    try {
      await client.call("phase.set", { phase: p.id });
      toast("ok", t("start.phases.moved", { title: p.title }), p.exploitation ? t("start.phases.moved.exploit") : undefined);
    } catch (e) {
      toast("bad", t("start.phases.moveFailed"), (e as Error).message);
    }
  }
  const shown = phases.find((p) => p.id === open) ?? phases.find((p) => p.status === "current") ?? phases[0]!;
  const idx = phases.indexOf(shown);
  return (
    <section>
      <h2 style={{ display: "flex", alignItems: "baseline", gap: 10 }}>
        {t("start.phases.title")} <span className="mono" style={{ color: "var(--fg-3)", fontSize: 12 }}>{String(phases.findIndex((p) => p.status === "current") + 1).padStart(2, "0")} / {String(phases.length).padStart(2, "0")}</span>
      </h2>
      <div className="ruler" style={{ ["--n" as string]: phases.length }}>
        {phases.map((p) => (
          <div key={p.id} className={`seg ${p.status === "current" ? "current" : p.status === "done" ? "done" : p.exploitation ? "exploit" : ""}`} title={p.title} />
        ))}
      </div>
      <div className="ruler-labels" style={{ ["--n" as string]: phases.length }}>
        {phases.map((p) => (
          <button key={p.id} className={`${p.id === shown.id ? "on" : ""}`} onClick={() => setOpen(p.id)} title={p.goal}>
            {p.title}{p.exploitation ? <span className="exp"> ·</span> : null}
          </button>
        ))}
      </div>
      <div className="phase-card">
        <div className="pc-head">
          <span className="mono" style={{ color: shown.status === "current" ? "var(--accent)" : "var(--fg-3)" }}>{String(idx + 1).padStart(2, "0")}</span>
          <span className="pc-title">{shown.title}</span>
          {shown.status === "current" ? <span style={{ color: "var(--accent)" }}>{t("start.phases.current")}</span> : shown.status === "done" ? <span style={{ color: "var(--ok)" }}>{t("start.phases.done")}</span> : null}
          {shown.exploitation ? <span style={{ color: "var(--amber)", fontStyle: "italic" }}>{t("start.phases.exploitation")}</span> : null}
          <span style={{ flex: 1 }} />
          {mayMove && shown.status !== "current" ? (
            <button className="btn sm ghost" onClick={() => void move(shown)}>{shown.status === "done" ? t("start.phases.back") : t("start.phases.move")}</button>
          ) : null}
        </div>
        <div className="pc-goal">{shown.goal}</div>
        {shown.plan ? <div className="pc-block"><div className="lbl">{t("start.phases.plan")}</div><Markdown text={shown.plan} /></div> : null}
        {shown.summary ? <div className="pc-block"><div className="lbl">{t("start.phases.result")}</div><Markdown text={shown.summary} /></div> : null}
        {!shown.plan && !shown.summary && shown.status === "current" ? <div className="pc-block muted">{t("start.phases.pending")}</div> : null}
      </div>
    </section>
  );
}
