import { Ban, Bot, Database, FileWarning, History, Link2, Play, ShieldCheck, ShieldOff, Square } from "../ui/icons";
import { useState } from "react";
import { type Actor, useApp, useOperation } from "../state";
import { ActorBadge, relTime, useTick } from "../ui/bits";
import { t } from "../i18n";
import { HelpHint } from "../ui/HelpHint";

interface AuditEvent {
  seq: number;
  at: string;
  actor: Actor;
  action: string;
  subject?: Record<string, unknown>;
  hash: string;
}

/** Audit actions the panel knows; the text comes from the catalog key ops.activity.action.<action>. */
const LABELS: Record<string, { tone: string; icon: React.ReactNode }> = {
  "engagement.create": { tone: "accent", icon: <ShieldCheck size={13} /> },
  "engagement.update": { tone: "", icon: <ShieldCheck size={13} /> },
  "engagement.stop_work": { tone: "bad", icon: <Square size={13} /> },
  "engagement.resume_work": { tone: "ok", icon: <Play size={13} /> },
  "scope.add_rule": { tone: "ok", icon: <ShieldCheck size={13} /> },
  "scope.remove_rule": { tone: "bad", icon: <ShieldOff size={13} /> },
  "run.start": { tone: "accent", icon: <Play size={13} /> },
  "run.finish": { tone: "", icon: <Play size={13} /> },
  "run.denied": { tone: "bad", icon: <Ban size={13} /> },
  "ingest.batch": { tone: "ok", icon: <Database size={13} /> },
  "approval.request": { tone: "agent", icon: <Bot size={13} /> },
  "approval.approve": { tone: "ok", icon: <ShieldCheck size={13} /> },
  "approval.reject": { tone: "bad", icon: <Ban size={13} /> },
  "finding.create": { tone: "accent", icon: <FileWarning size={13} /> },
  "evidence.create": { tone: "", icon: <Link2 size={13} /> },
};

export function ActivityPanel() {
  const { client } = useApp();
  const now = useTick();
  const events = useOperation<AuditEvent[]>("audit.query", { limit: 300 }, { refreshOn: (e) => e.type === "audit.appended" });
  const [verify, setVerify] = useState<{ ok: boolean; events?: number; brokenAt?: number }>();

  const runVerify = () => client.call<typeof verify>("audit.verify").then(setVerify); // i18n-ignore

  return (
    <div className="panel">
      <div className="panel-toolbar">
        <HelpHint id="activity" text={t("ops.activity.hint")} />
        <div className="grow" />
        {verify ? (
          <span className={`badge ${verify.ok ? "ok" : "bad"}`}>{verify.ok ? t("ops.activity.chainOk", { n: verify.events }) : t("ops.activity.chainBroken", { seq: verify.brokenAt })}</span>
        ) : null}
        <button className="btn sm" onClick={runVerify}>
          {t("ops.activity.verify")}
        </button>
      </div>
      <div className="panel-scroll">
        {(events.data ?? []).map((e) => {
          const l = LABELS[e.action] ?? { tone: "", icon: <History size={13} /> };
          const text = LABELS[e.action] ? t(`ops.activity.action.${e.action}`) : e.action;
          const tone = e.actor.type === "agent" && l.tone === "accent" ? "agent" : l.tone;
          return (
            <div key={e.seq} className="row">
              <div className={`ic ${tone === "accent" ? "" : tone}`}>{l.icon}</div>
              <div style={{ minWidth: 0 }}>
                <div className="t">{text}</div>
                <div className="s mono">
                  #{e.seq} · {e.hash.slice(0, 12)}
                </div>
              </div>
              <div className="when" style={{ display: "flex", gap: 8, alignItems: "center" }}>
                <ActorBadge actor={e.actor} />
                {relTime(e.at, now)}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
