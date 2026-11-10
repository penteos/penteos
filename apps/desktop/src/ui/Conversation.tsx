/** The conversation with the Maestro: turns, tool calls, approvals in place, notices and Sala cards. */
import { Bell, Maximize2, RotateCw, CheckCircle2, ChevronDown, Loader2, ShieldCheck, Wrench, XCircle, Hand } from "./icons";
import { useEffect, useRef, useState } from "react";
import type { AgentEvent, SalaCard } from "../client";
import { type Approval, useApp } from "../state";
import { approvalSummary } from "./approvalText";
import { ApprovalCard, type ApprovalResult, InstallFollowUp } from "../ui/ApprovalCard";
import { Markdown } from "../ui/Markdown";
import { AgentTranscript } from "../panels/Team";

import type { Provider } from "./Providers";
import { t, tn } from "../i18n";
import { useTick } from "./bits";
import { appendDelta } from "./stream";
import { PathsCard } from "./PathsCard";
export function shortInput(input: unknown): string {
  if (!input || typeof input !== "object") return "";
  const values = Object.entries(input as Record<string, unknown>)
    .filter(([k]) => k !== "engagementId" && k !== "intent")
    .map(([, v]) => (typeof v === "string" ? v : Array.isArray(v) ? v.join(" ") : JSON.stringify(v)));
  const text = values.join(" · ");
  return text.length > 70 ? `${text.slice(0, 70)}…` : text;
}

/** What the agent said it was after with a call (its optional "intent"), if it said it. */
export function intentOf(input: unknown): string | undefined {
  const v = input && typeof input === "object" ? (input as Record<string, unknown>).intent : undefined;
  return typeof v === "string" && v.trim() ? v.trim() : undefined;
}

// ---------------------------------------------------------------------------------------------
// Conversation
// ---------------------------------------------------------------------------------------------

export type Entry =
  | { kind: "user"; text: string; auto?: boolean; by?: string }
  | { kind: "notice"; text: string }
  | { kind: "assistant"; text: string }
  | { kind: "tool"; id: string; name: string; input: unknown; status: "running" | "ok" | "error"; summary?: string; approvalId?: string; startedAt?: number }
  | { kind: "status"; text: string }
  | { kind: "card"; card: SalaCard }
  | { kind: "error"; text: string };

export function reduce(entries: Entry[], e: AgentEvent): Entry[] {
  switch (e.kind) {
    case "card":
      return [...entries, { kind: "card", card: e.card }];
    case "user":
      return [...entries, { kind: "user", text: e.text, ...(e.auto ? { auto: true } : {}), ...(e.by ? { by: e.by } : {}) }];
    case "notice":
      return [...entries, { kind: "notice", text: e.text }];
    case "delta":
    case "text":
      return appendDelta(entries, "assistant", e.text);
    case "tool": {
      const i = entries.findIndex((x) => x.kind === "tool" && x.id === e.id);
      const prev = i >= 0 ? (entries[i] as ToolEntry) : undefined;
      const entry: Entry = { kind: "tool", id: e.id, name: e.name, input: e.input, status: e.status, startedAt: prev?.startedAt ?? Date.now(), ...(e.summary ? { summary: e.summary } : {}), ...(e.approvalId ? { approvalId: e.approvalId } : {}) };
      if (i >= 0) return entries.map((x, j) => (j === i ? entry : x));
      return [...entries, entry];
    }
    case "status":
      return [...entries, { kind: "status", text: e.text }];
    case "error":
      return [...entries, { kind: "error", text: e.text }];
    default:
      return entries;
  }
}

type ToolEntry = Extract<Entry, { kind: "tool" }>;
type Segment = { kind: "entry"; entry: Entry } | { kind: "tools"; tools: ToolEntry[]; key: string } | { kind: "approval"; id: string } | { kind: "paths"; id: string; input: unknown };

/** Consecutive tool calls become one collapsible block, so the conclusions stay readable. */
function segments(entries: Entry[]): Segment[] {
  const out: Segment[] = [];
  for (const entry of entries) {
    const last = out.at(-1);
    if (entry.kind === "tool") {
      if (last?.kind === "tools") last.tools.push(entry);
      else out.push({ kind: "tools", tools: [entry], key: entry.id });
    } else out.push({ kind: "entry", entry });
  }
  // Each approval the agent asked for is shown right after the calls that created it.
  return out.flatMap<Segment>((seg) =>
    seg.kind === "tools"
      ? [
          seg,
          ...seg.tools.filter((t) => t.approvalId).map((t) => ({ kind: "approval" as const, id: t.approvalId! })),
          // Where we stand and where to go: a card the operator acts on, not a line in the tool block.
          ...seg.tools.filter((t) => t.name === "plan.propose_paths" && t.status === "ok").map((t) => ({ kind: "paths" as const, id: t.id, input: t.input })),
        ]
      : [seg],
  );
}

export function approvalIdsOf(entries: Entry[]): Set<string> {
  return new Set(entries.flatMap((e) => (e.kind === "tool" && e.approvalId ? [e.approvalId] : [])));
}

type Decision = { state: "pending" | "approved" | "rejected" | "withdrawn" | "expired"; summary?: string; request?: Approval["request"] };

/** An approval inside the conversation: decide in place, and the agent hears about it. */
function ApprovalInline(props: { id: string; onDecided: (approved: boolean, summary: string) => void }) {
  const { client, approvals } = useApp();
  const pending = approvals.find((a) => a.id === props.id);
  const [decision, setDecision] = useState<Decision>();
  const [followUp, setFollowUp] = useState<ApprovalResult>();
  useEffect(() => {
    if (pending) return;
    client.call<Record<string, Decision>>("approval.status", { ids: [props.id] }).then((r) => setDecision(r[props.id]), () => {});
  }, [client, props.id, Boolean(pending)]);

  // The card itself is pinned under the conversation (it used to scroll away unseen): here, a
  // one-line pointer that takes the operator to it.
  if (pending) {
    return (
      <button className="approval-pointer" onClick={() => focusApproval(props.id)}>
        <Hand size={12} />
        <span className="ap-k">{t("agent.approval.pointer")}</span>
        <span className="ap-sum">{approvalSummary(pending)}</span>
        <span className="ap-go">{t("agent.approval.pointerGo")}</span>
      </button>
    );
  }
  if (followUp) return <InstallFollowUp result={followUp} inline />;
  if (!decision) return null;
  const label = t(`agent.decision.${decision.state}`);
  return (
    <div className={`approval-done ${decision.state}`}>
      {decision.state === "approved" ? <CheckCircle2 size={12} /> : <XCircle size={12} />}
      <span>{label}</span>
      {decision.summary ? <span className="muted">· {decision.request ? approvalSummary({ summary: decision.summary, request: decision.request } as Approval) : decision.summary}</span> : null}
    </div>
  );
}

/** m:ss since a tool call started. */
function elapsed(since: number, now: number): string {
  const s = Math.max(0, Math.floor((now - since) / 1000));
  return `${Math.floor(s / 60)}:${String(s % 60).padStart(2, "0")}`;
}

function ToolRow(props: { e: ToolEntry }) {
  const { e } = props;
  const running = e.status === "running";
  const now = useTick(running ? 1000 : 60_000);
  // A call that blocks for a while says so: how long, and where its output is.
  const long = running && e.startedAt !== undefined && now - e.startedAt > 4000;
  return (
    <div className={`tool-row ${e.status}`}>
      {running ? <Loader2 size={12} className="spin" /> : e.status === "ok" ? <CheckCircle2 size={12} /> : <XCircle size={12} />}
      <span className="mono name">{e.name}</span>
      {intentOf(e.input) ? (
        <span className="args intent" title={shortInput(e.input)}>
          {intentOf(e.input)}
        </span>
      ) : (
        <span className="args">{shortInput(e.input)}</span>
      )}
      {e.summary ? <span className="res">→ {toolSummary(e.summary)}</span> : null}
      {long ? (
        <span className="res running-for">
          <span className="mono">{t("agent.tool.runningFor", { time: elapsed(e.startedAt!, now) })}</span>
          <button className="link-btn" onClick={() => window.dispatchEvent(new Event("penteos:open-runs"))}>{t("agent.tool.showOutput")}</button>
        </span>
      ) : null}
    </div>
  );
}

function ToolGroup(props: { tools: ToolEntry[] }) {
  const [open, setOpen] = useState(false);
  const { tools } = props;
  if (tools.length <= 2) return <>{tools.map((t) => <ToolRow key={t.id} e={t} />)}</>;
  const running = tools.filter((t) => t.status === "running");
  const errors = tools.filter((t) => t.status === "error").length;
  const names = [...new Set(tools.map((t) => t.name))];
  return (
    <div className="tool-group">
      <button className="tool-group-head" onClick={() => setOpen((v) => !v)}>
        <ChevronDown size={12} style={{ transform: open ? "none" : "rotate(-90deg)" }} />
        {running.length ? <Loader2 size={12} className="spin" /> : <Wrench size={12} />}
        <span>{tn("agent.tools.count", tools.length)}</span>
        {errors ? <span style={{ color: "var(--bad)" }}>· {t("agent.tools.errors", { n: errors })}</span> : null}
        <span className="names">{names.slice(0, 4).join(", ")}{names.length > 4 ? "…" : ""}</span>
      </button>
      {open ? tools.map((t) => <ToolRow key={t.id} e={t} />) : running.map((t) => <ToolRow key={t.id} e={t} />)}
    </div>
  );
}

/** What Penteos told the Maestro: one line for the human, the whole text on click. */
function Notice(props: { text: string }) {
  const [open, setOpen] = useState(false);
  const first = props.text.split("\n")[0] ?? props.text;
  const long = props.text.length > 110 || props.text.includes("\n");
  return (
    <div className={`turn-notice ${open ? "open" : ""}`} onClick={() => long && setOpen((v) => !v)} title={long ? (open ? t("agent.notice.collapse") : t("agent.notice.expand")) : undefined}>
      <Bell size={12} />
      <span>{open || !long ? props.text : `${first.slice(0, 110)}${first.length > 110 || props.text.includes("\n") ? "…" : ""}`}</span>
    </div>
  );
}

/** A card in the Sala: the verifier's verdict, with its transcript one click away. */
function SalaCardView(props: { card: SalaCard }) {
  const { workbench } = useApp();
  const { card } = props;
  const [open, setOpen] = useState(false);
  const [more, setMore] = useState(false);
  const tone = /no reproducido|not reproduced/i.test(card.title) || /no concluyente|inconclusive/i.test(card.title) ? "warn" : "ok";
  const title = card.title.replace(/^(Verificador|Verifier): /, "");
  const long = card.text.length > 220;
  return (
    <div className={`sala-card ${tone}`}>
      <div className="sc-who">
        <span className="sc-avatar"><ShieldCheck size={11} /></span>
        <span className="sc-name">{card.who ?? t("common.verifier")}</span>
        <span className="muted">· {t("agent.card.informs")}</span>
      </div>
      <div className="sc-title">{title}</div>
      <div className="sc-text">{long && !more ? `${card.text.slice(0, 220)}…` : card.text}{long ? <button className="btn ghost sm sc-more" onClick={() => setMore(!more)}>{more ? t("agent.card.less") : t("agent.card.more")}</button> : null}</div>
      <div className="sc-actions">
        {card.findingId ? <button className="btn ghost sm" onClick={() => workbench.openFinding(card.findingId!, title.replace(/^[^·]+· /, ""))}>{t("agent.card.openFinding")}</button> : null}
        {card.key ? <button className="btn ghost sm" onClick={() => setOpen(!open)}>{open ? t("common.hide") : t("agent.card.transcript")}</button> : null}
      </div>
      {open && card.key ? <AgentTranscript transcriptKey={card.key} /> : null}
    </div>
  );
}

export function Conversation(props: { entries: Entry[]; running: boolean; providerLabel?: string; onlyConversation?: boolean; onDecided: (approved: boolean, summary: string) => void }) {
  const { workbench } = useApp();
  const end = useRef<HTMLDivElement>(null);
  // Braces matter: in recent Chromium scrollIntoView returns a promise, which React would take for a cleanup.
  useEffect(() => {
    void end.current?.scrollIntoView({ block: "end" });
  }, [props.entries, props.running]);
  return (
    <>
      {segments(props.entries).map((seg, i) => {
        if (seg.kind === "tools") return <ToolGroup key={seg.key} tools={seg.tools} />;
        if (seg.kind === "approval") return <ApprovalInline key={`a-${seg.id}`} id={seg.id} onDecided={props.onDecided} />;
        if (seg.kind === "paths") return <PathsCard key={`p-${seg.id}`} input={seg.input} />;
        const e = seg.entry;
        if (e.kind === "user" && e.auto) return <div key={i} className="turn-status"><RotateCw size={12} /> {t("agent.conv.resumes")}</div>;
        if (e.kind === "user")
          return (
            <div key={i} className="turn-user">
              {e.by ? <div className="by">{e.by}</div> : null}
              <Markdown text={e.text} />
            </div>
          );
        if (e.kind === "notice") return props.onlyConversation ? null : <Notice key={i} text={e.text} />;
        if (e.kind === "assistant")
          return (
            <div key={i} className="turn-agent">
              <button className="expand" title={t("agent.conv.expand")} onClick={() => workbench.openDoc(e.text.split("\n").find((l) => l.trim())?.replace(/^[#*\s]+/, "").slice(0, 40) || t("agent.conv.answerDoc"), e.text)}>
                <Maximize2 size={12} />
              </button>
              <Markdown text={e.text} />
            </div>
          );
        if (e.kind === "status") return <div key={i} className="turn-status">{e.text}</div>;
        if (e.kind === "card") return props.onlyConversation ? null : <SalaCardView key={i} card={e.card} />;
        if (e.kind === "error") return <div key={i} className="turn-error">{e.text}</div>;
        return null;
      })}
      {props.running ? (
        <div className="turn-status"><Loader2 size={12} className="spin" /> {t("agent.conv.maestroWorking")}</div>
      ) : null}
      <div ref={end} />
    </>
  );
}

/** A tool call's one-word result from the server (English tokens), in the operator's language. */
function toolSummary(s: string): string {
  const run = /^running · run (\w+)$/.exec(s);
  if (run) return t("agent.tool.runningRun", { id: run[1] });
  const n = /^(\d+) results$/.exec(s);
  if (n) return tn("agent.tool.results", Number(n[1]));
  const key = { pending_approval: "pendingApproval", running: "running", "unknown tool": "unknown", "not allowed": "notAllowed", repeated: "repeated", REPEATED: "refusedRepeated", ok: "ok", allow: "allow", ask: "ask", deny: "deny" }[s];
  return key ? t(`agent.tool.${key}`) : s;
}

/** Brings a pinned approval card into view and marks it for a moment. */
export function focusApproval(id: string): void {
  // The tray shows one card at a time: bring this one up first, then point at it.
  window.dispatchEvent(new CustomEvent("penteos:focus-approval", { detail: id }));
  setTimeout(() => highlight(id), 60);
}

function highlight(id: string): void {
  const el = document.getElementById(`approval-${id}`);
  if (!el) return;
  el.scrollIntoView({ block: "nearest", behavior: "smooth" });
  el.classList.add("focused");
  setTimeout(() => el.classList.remove("focused"), 1600);
}
