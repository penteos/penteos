import { CircleCheck, CircleHelp, CircleX, Eye, EyeOff, Loader2, RotateCw, ShieldCheck, Square, UserCheck } from "./icons";
import { useEffect, useState } from "react";
import type { AgentEvent } from "../client";
import { useApp } from "../state";
import { Badge, toast } from "./bits";
import { Markdown } from "./Markdown";
import { t } from "../i18n";
import { appendDelta } from "./stream";

/**
 * The independent verification of a finding: a separate agent tries to reproduce it
 * without knowing how it was found. Shown in the finding and as a badge in the list.
 */

export interface VerificationState {
  state: "pending" | "running" | "done" | "failed";
  verdict?: "reproduced" | "not_reproduced" | "inconclusive";
  summary?: string;
  by?: { type: string; id: string };
  at?: string;
  evidenceIds?: string[];
}

export const VERDICT: Record<string, { readonly label: string; tone: "ok" | "bad" | "warn"; icon: typeof CircleCheck }> = {
  reproduced: { get label() { return t("agent.verdict.reproduced"); }, tone: "ok", icon: CircleCheck },
  not_reproduced: { get label() { return t("agent.verdict.not_reproduced"); }, tone: "bad", icon: CircleX },
  inconclusive: { get label() { return t("agent.verdict.inconclusive"); }, tone: "warn", icon: CircleHelp },
};

/** Small badge for lists. */
export function VerificationBadge(props: { v?: VerificationState }) {
  const v = props.v;
  if (!v) return null;
  if (v.state === "pending" || v.state === "running") return <Badge tone="accent"><Loader2 size={11} className="spin" /> {t("agent.verify.badge.running")}</Badge>;
  if (v.state === "failed") return <Badge tone="warn" title={v.summary}><CircleHelp size={11} /> {t("agent.verify.badge.unverified")}</Badge>;
  const d = VERDICT[v.verdict ?? "inconclusive"]!;
  const Icon = d.icon;
  return <Badge tone={d.tone} title={v.summary}><Icon size={11} /> {d.label.toLowerCase()}</Badge>;
}

const TOOL = (name: string) => name.replace(/^mcp__penteos__/, "").replace(/^penteos_/, "");

/** What an agent that runs alongside did (or is doing), compact. */
export function Transcript(props: { events: AgentEvent[] }) {
  return (
    <div className="transcript">
      {props.events.map((e, i) => {
        if (e.kind === "text") return <div key={i} className="tx-text"><Markdown text={e.text} /></div>;
        if (e.kind === "tool") {
          return (
            <div key={i} className={`tx-tool ${e.status}`}>
              <span className="mono">{TOOL(e.name)}</span>
              {e.summary ? <span className="muted">{e.summary}</span> : e.status === "running" ? <Loader2 size={11} className="spin" /> : null}
            </div>
          );
        }
        if (e.kind === "notice" || e.kind === "status") return <div key={i} className="tx-note muted">{e.text}</div>;
        if (e.kind === "error") return <div key={i} className="tx-note bad">{e.text}</div>;
        return null;
      })}
      {props.events.length === 0 ? <div className="muted">{t("agent.verify.transcriptEmpty")}</div> : null}
    </div>
  );
}

/** Tool events arrive twice (running, then done): keep the latest of each. */
function fold(events: AgentEvent[], e: AgentEvent): AgentEvent[] {
  if (e.kind === "tool") {
    const i = events.findIndex((x) => x.kind === "tool" && x.id === e.id && x.status === "running");
    if (i >= 0) return [...events.slice(0, i), e, ...events.slice(i + 1)];
  }
  if (e.kind === "delta") return appendDelta(events, "text", e.text);
  if (e.kind === "done") return events;
  return [...events, e];
}

export function VerificationBox(props: { findingId: string; v?: VerificationState; evidence: (ids: string[]) => React.ReactNode }) {
  const { client } = useApp();
  const { findingId, v } = props;
  const key = `verifier-${findingId}`;
  const [events, setEvents] = useState<AgentEvent[]>([]);
  const [open, setOpen] = useState(false);
  const [unavailable, setUnavailable] = useState<string>();
  const busy = v?.state === "pending" || v?.state === "running";

  useEffect(() => {
    client.request<{ roles?: { verifier?: { reason?: string } } }>("agent.roles").then((r) => setUnavailable(r.roles?.verifier?.reason), () => {});
  }, [client]);
  useEffect(() => {
    let alive = true;
    client.request<{ events: AgentEvent[] }>("subagent.transcript", { key }).then((r) => alive && setEvents(r.events ?? []), () => {});
    const off = client.onSubagentEvent((k, e) => k === key && setEvents((cur) => fold(cur, e)));
    return () => {
      alive = false;
      off();
    };
  }, [client, key, v?.state]);

  async function verify() {
    try {
      await client.call("finding.request_verification", { id: findingId });
      setOpen(true);
    } catch (e) {
      toast("bad", t("agent.verify.failed"), (e as Error).message);
    }
  }
  async function mine(verdict: string) {
    const summary = window.prompt(t("agent.verify.prompt"), "");
    if (!summary?.trim()) return;
    await client.call("finding.verdict", { id: findingId, verdict, summary }).then(
      () => toast("ok", t("agent.verify.recorded")),
      (e: Error) => toast("bad", t("agent.verify.recordFailed"), e.message),
    );
  }

  const verdict = v?.state === "done" ? VERDICT[v.verdict ?? "inconclusive"] : undefined;
  const Icon = verdict?.icon ?? ShieldCheck;
  const byHuman = v?.by?.type === "human";

  return (
    <div className={`verify-box ${verdict ? verdict.tone : busy ? "busy" : ""}`}>
      <div className="vb-head">
        {busy ? <Loader2 size={15} className="spin" /> : <Icon size={15} />}
        <div className="vb-title">
          {busy
            ? t("agent.verify.running")
            : verdict
              ? t(byHuman ? "agent.verify.byOperator" : "agent.verify.byVerifier", { verdict: verdict.label })
              : v?.state === "failed"
                ? t("agent.verify.failed")
                : t("agent.verify.none")}
        </div>
        <div className="grow" />
        {busy ? (
          <button className="btn sm ghost" onClick={() => client.notify("verification.cancel", { findingId })}><Square size={11} /> {t("common.cancel")}</button>
        ) : (
          <button className="btn sm" disabled={Boolean(unavailable)} title={unavailable ?? t("agent.verify.hint")} onClick={verify}>
            {v ? <RotateCw size={12} /> : <ShieldCheck size={12} />} {v ? t("agent.verify.again") : t("agent.verify.start")}
          </button>
        )}
        {events.length ? (
          <button className="btn sm ghost" onClick={() => setOpen(!open)}>{open ? <EyeOff size={12} /> : <Eye size={12} />} {open ? t("common.hide") : busy ? t("agent.verify.watchLive") : t("agent.verify.watchDone")}</button>
        ) : null}
      </div>
      {v?.summary && !busy ? <div className="vb-summary">{v.summary}</div> : null}
      {unavailable && !busy ? <div className="vb-summary muted">{unavailable}</div> : null}
      {!v && !unavailable ? <div className="vb-summary muted">{t("agent.verify.auto")}</div> : null}
      {verdict && v?.evidenceIds?.length ? <div className="vb-evidence">{props.evidence(v.evidenceIds)}</div> : null}
      {!busy ? (
        <div className="vb-mine">
          <UserCheck size={12} /> <span className="muted">{t("agent.verify.manual")}</span>
          <button className="btn sm ghost" onClick={() => mine("reproduced")}>{t("agent.verify.markReproduced")}</button>
          <button className="btn sm ghost" onClick={() => mine("not_reproduced")}>{t("agent.verify.markNotReproduced")}</button>
        </div>
      ) : null}
      {open ? <Transcript events={events} /> : null}
    </div>
  );
}
