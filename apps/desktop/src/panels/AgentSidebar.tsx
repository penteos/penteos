import { ArrowUp, Ban, CheckCircle2, ChevronDown, ChevronLeft, ChevronRight, Copy, Loader2, Plug, Square, SquarePen, Users, Wrench, X } from "../ui/icons";
import { MaestroBadge, Mascot } from "../ui/Mascot";
import { ClientQuestions, useClientQuestions } from "../ui/ClientQuestions";
import { type ReactNode, useCallback, useEffect, useRef, useState } from "react";
import type { AgentEvent, SalaCard } from "../client";
import { can, type Run, useApp, useOperation } from "../state";
import { ApprovalCard, type ApprovalResult, InstallFollowUp } from "../ui/ApprovalCard";
import { PhaseStrip } from "../ui/Phases";
import { relTime, toast, useTick } from "../ui/bits";
import { summarize } from "./Home";
import { RoleSettingsModal } from "../ui/RoleSettings";

import { type Provider, ProviderPicker, ProviderSettings, useOutside } from "../ui/Providers";
import { Conversation, type Entry, reduce } from "../ui/Conversation";
import { WaitingStrip } from "../ui/Waiting";
import { t, tn } from "../i18n";
// ---------------------------------------------------------------------------------------------
// Types and helpers
// ---------------------------------------------------------------------------------------------

type AgentId = "maestro" | "external";

export type { Provider };
const AGENTS: Array<{ id: AgentId | "team"; readonly name: string; readonly desc: string; icon: ReactNode; disabled?: boolean }> = [
  { id: "maestro", get name() { return t("common.maestro"); }, get desc() { return t("agent.picker.maestro.desc"); }, icon: <MaestroBadge size={18} /> },
  { id: "external", get name() { return t("agent.picker.external.name"); }, get desc() { return t("agent.picker.external.desc"); }, icon: <Plug size={12} /> },
  { id: "team", get name() { return t("agent.picker.team.name"); }, get desc() { return t("agent.picker.team.desc"); }, icon: <Users size={12} /> },
];

function AgentPicker(props: { value: AgentId; onChange: (v: AgentId) => void; onTeam: () => void; active?: boolean }) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);
  useOutside(ref, useCallback(() => setOpen(false), []));
  const current = AGENTS.find((a) => a.id === props.value)!;
  return (
    <div className="agent-picker" ref={ref}>
      <button onClick={() => setOpen((v) => !v)}>
        <span className={`avatar${current.id === "maestro" ? " on-badge" : ""}`}>{current.id === "maestro" ? <MaestroBadge size={26} active={props.active} title={t("common.maestro")} /> : current.icon}</span>
        <span style={{ flex: 1, textAlign: "left", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{current.name}</span>
        <ChevronDown size={14} color="var(--fg-3)" />
      </button>
      {open ? (
        <div className="menu">
          {AGENTS.map((a) => (
            <div
              key={a.id}
              className={`agent-opt ${a.disabled ? "disabled" : ""}`}
              onClick={() => {
                if (a.disabled) return;
                if (a.id === "team") {
                  props.onTeam();
                  setOpen(false);
                  return;
                }
                props.onChange(a.id as AgentId);
                setOpen(false);
              }}
            >
              <span className="avatar">{a.icon}</span>
              <div>
                <div className="n">{a.name}</div>
                <div className="d">{a.desc}</div>
              </div>
            </div>
          ))}
        </div>
      ) : null}
    </div>
  );
}

/**
 * In auto mode the Maestro runs on its own and gathers the decisions that need you; this is the
 * header of that tray, with the count (approvals + open questions). Only rendered in auto.
 */
function AutoTrayHead(props: { running: boolean }) {
  const { approvals } = useApp();
  const { data } = useClientQuestions();
  const openQ = (data ?? []).filter((q) => q.status === "open").length;
  const n = approvals.length + openQ;
  return (
    <div className="auto-tray-head">
      <span className="auto-dot" />
      <span className="auto-label">{props.running ? t("agent.auto.working") : t("agent.auto.idle")}</span>
      <span className="grow" />
      {n > 0 ? <span className="auto-count">{tn("agent.auto.decisions", n)}</span> : <span className="auto-none">{t("agent.auto.none")}</span>}
    </div>
  );
}

function Suggestions(props: { onPick: (t: string) => void }) {
  // A short chip is the label; the full question is what gets sent.
  const items = [
    { label: t("agent.suggestions.scope.label"), text: t("agent.suggestions.scope") },
    { label: t("agent.suggestions.recon.label"), text: t("agent.suggestions.recon") },
    { label: t("agent.suggestions.services.label"), text: t("agent.suggestions.services") },
  ];
  return (
    <div className="suggestions">
      <span className="sg-title">{t("agent.suggestions.title")}</span>
      <div className="sg-chips">
        {items.map((s) => (
          <button key={s.label} className="chip" title={s.text} onClick={() => props.onPick(s.text)}>{s.label}</button>
        ))}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------------------------
// Approvals and external agents
// ---------------------------------------------------------------------------------------------

/**
 * What waits on the operator, as a tray under the conversation: a one-line header with how many
 * decisions wait, and one card at a time with arrows to go through them. Stacked in full they took
 * the whole bar and the conversation disappeared; pinned they are never lost (they used to scroll
 * away and expire). The pointer in the conversation opens the tray on its card.
 */
function Approvals() {
  const { approvals } = useApp();
  const [followUps, setFollowUps] = useState<Array<{ id: string; result: ApprovalResult }>>([]);
  const [open, setOpen] = useState(true);
  const [index, setIndex] = useState(0);
  const seen = useRef(approvals.length);
  // A new request opens the tray on it; deciding one keeps the index in range.
  useEffect(() => {
    if (approvals.length > seen.current) {
      setOpen(true);
      setIndex(approvals.length - 1);
    } else if (index > approvals.length - 1) setIndex(Math.max(0, approvals.length - 1));
    seen.current = approvals.length;
  }, [approvals.length]);
  useEffect(() => {
    const onFocus = (e: Event) => {
      const i = approvals.findIndex((a) => a.id === (e as CustomEvent<string>).detail);
      if (i < 0) return;
      setOpen(true);
      setIndex(i);
    };
    window.addEventListener("penteos:focus-approval", onFocus);
    return () => window.removeEventListener("penteos:focus-approval", onFocus);
  }, [approvals]);
  if (approvals.length === 0 && followUps.length === 0) return null;
  const current = approvals[Math.min(index, approvals.length - 1)];
  return (
    <div className="approvals">
      {followUps.map((f) => (
        <div key={f.id} style={{ position: "relative" }}>
          <InstallFollowUp result={f.result} />
          <button className="icon-btn" style={{ position: "absolute", top: 4, right: 4 }} onClick={() => setFollowUps((l) => l.filter((x) => x.id !== f.id))}>
            <X size={12} />
          </button>
        </div>
      ))}
      {approvals.length ? (
        <div className="tray-head">
          <button className="tray-toggle" onClick={() => setOpen((v) => !v)}>
            <ChevronDown size={13} style={{ transform: open ? "none" : "rotate(-90deg)" }} />
            <span className="tray-dot" />
            {tn("agent.tray.waiting", approvals.length)}
          </button>
          {open && approvals.length > 1 ? (
            <span className="tray-pager">
              <button className="icon-btn" disabled={index === 0} aria-label={t("agent.tray.prev")} onClick={() => setIndex((i) => Math.max(0, i - 1))}><ChevronLeft size={13} /></button>
              <span className="mono">{Math.min(index, approvals.length - 1) + 1}/{approvals.length}</span>
              <button className="icon-btn" disabled={index >= approvals.length - 1} aria-label={t("agent.tray.next")} onClick={() => setIndex((i) => Math.min(approvals.length - 1, i + 1))}><ChevronRight size={13} /></button>
            </span>
          ) : null}
        </div>
      ) : null}
      {open && current ? <ApprovalCard key={current.id} approval={current} onDecided={(_ok, _s, result) => result && setFollowUps((l) => [...l, { id: current.id, result }])} /> : null}
    </div>
  );
}

function ExternalAgents() {
  const { workbench } = useApp();
  const now = useTick();
  const runs = useOperation<Run[]>("run.list", { limit: 200 }, { refreshOn: (e) => e.type.startsWith("run.") });
  // How any MCP client starts the bridge here (the core knows: installed app or sources).
  const mcp = useOperation<{ json: unknown; clients: Record<string, string> }>("agent.mcp_config", {});
  const json = mcp.data ? JSON.stringify(mcp.data.json, null, 2) : "";
  const copy = (text: string) => navigator.clipboard.writeText(text).then(() => toast("ok", t("agent.commandCopied")));
  const agentRuns = (runs.data ?? []).filter((r) => r.actor.type === "agent").reverse();
  return (
    <>
      <div className="callout">
        <div className="t"><Plug size={14} /> {t("agent.external.title")}</div>
        {t("agent.external.body")}
        <pre className="mcp-json mono">{json}</pre>
        <button className="btn sm" style={{ marginTop: 8 }} disabled={!json} onClick={() => void copy(json)}>{t("agent.external.copyJson")}</button>
        {mcp.data ? (
          <div className="mcp-clients">
            <div className="muted">{t("agent.external.orClient")}</div>
            {Object.entries(mcp.data.clients).map(([name, cmd]) => (
              <div key={name} className="mcp-client">
                <span>{name}</span>
                <code title={cmd}>{cmd}</code>
                <button className="btn sm ghost" onClick={() => void copy(cmd)}>{t("common.copy")}</button>
              </div>
            ))}
          </div>
        ) : null}
      </div>
      {agentRuns.map((r) => (
        <div key={r.id} className="tool-row ok" style={{ cursor: "pointer" }} onClick={() => workbench.openRun(r.id)}>
          {r.status === "denied" ? <Ban size={12} color="var(--bad)" /> : r.status === "running" ? <Loader2 size={12} className="spin" /> : <CheckCircle2 size={12} />}
          <span className="mono name">{r.command}</span>
          <span className="res">{r.status === "denied" ? t("agent.external.denied", { time: relTime(r.startedAt, now) }) : r.summary?.ingested ? summarize(r.summary.ingested) : relTime(r.startedAt, now)}</span>
        </div>
      ))}
    </>
  );
}

// ---------------------------------------------------------------------------------------------
// Sidebar
// ---------------------------------------------------------------------------------------------

export function AgentSidebar(props: { width: number; ask?: string; onAskConsumed?: () => void }) {
  const { client, engagement, me, workbench, refreshEngagement } = useApp();
  const mayInstruct = can(me, "operator");
  const [agent, setAgent] = useState<AgentId>(() => {
    try {
      return (localStorage.getItem("penteos.agent") as AgentId) || "maestro";
    } catch {
      return "maestro";
    }
  });
  const [providers, setProviders] = useState<Provider[]>([]);
  const [provider, setProvider] = useState<string>();
  const [configuring, setConfiguring] = useState<Provider>();
  const [verifierOpen, setVerifierOpen] = useState(false);
  const [entries, setEntries] = useState<Entry[]>([]);
  const [running, setRunning] = useState(false);
  // The Maestro used up its self-continuations and has news it has not seen yet.
  const [parked, setParked] = useState(false);
  const [text, setText] = useState("");
  // Another part of the interface starts a message for the Maestro (e.g. "ask for a plugin"); the operator finishes it.
  useEffect(() => {
    const onPrefill = (e: Event) => setText(String((e as CustomEvent).detail ?? ""));
    window.addEventListener("penteos:agent-prefill", onPrefill);
    return () => window.removeEventListener("penteos:agent-prefill", onPrefill);
  }, []);
  // "Conversación" hides the cards and notices; "todo" shows what the verifier and the system said.
  const [onlyConversation, setOnlyConversation] = useState(false);

  useEffect(() => {
    try {
      localStorage.setItem("penteos.agent", agent);
    } catch {
      /* storage unavailable */
    }
  }, [agent]);

  const loadProviders = useCallback(
    (refresh = false) =>
      client.request<{ selected?: string; providers: Provider[] }>("agent.providers", { refresh }).then((r) => {
        setProviders(r.providers);
        setProvider((current) => current ?? (r.providers.find((p) => p.id === r.selected && p.available) ?? r.providers.find((p) => p.available))?.id);
      }),
    [client],
  );

  // The project assistant may choose the provider (and start the Maestro) before this panel does.
  useEffect(() => {
    const onPick = (e: Event) => {
      void loadProviders(true).then(() => setProvider((e as CustomEvent<string>).detail)); // i18n-ignore: generic types, not text
    };
    window.addEventListener("penteos:provider-selected", onPick);
    return () => window.removeEventListener("penteos:provider-selected", onPick);
  }, [loadProviders]);

  // Conversation of the active engagement: replay history, then follow live events.
  useEffect(() => {
    let alive = true;
    void loadProviders();
    client.request<{ events: AgentEvent[]; running: boolean; parked?: boolean }>("agent.history").then((h) => {
      if (!alive) return;
      setEntries(h.events.reduce(reduce, [] as Entry[]));
      setRunning(h.running);
      setParked(Boolean(h.parked));
    });
    const off = client.onAgentEvent((e) => {
      if (e.kind === "reset") {
        setEntries([]);
        setRunning(false);
        return;
      }
      if (e.kind === "user") {
        setRunning(true);
        setParked(false);
      }
      if (e.kind === "done") setRunning(false);
      if (e.kind === "status" && /novedades sin ver/.test(e.text)) setParked(true);
      setEntries((list) => reduce(list, e));
    });
    return () => {
      alive = false;
      off();
    };
  }, [client, loadProviders, engagement?.id]);

  const current = providers.find((p) => p.id === provider);
  const canSend = Boolean(current?.available) && !running && text.trim().length > 0;

  // Requests from other panels ("ask the Maestro to write the executive summary").
  useEffect(() => {
    if (!props.ask || providers.length === 0) return;
    setAgent("maestro");
    if (!current?.available) toast("info", t("agent.ask.noProvider.title"), t("agent.ask.noProvider.body"));
    else if (running) toast("info", t("agent.ask.busy.title"), t("agent.ask.busy.body"));
    else client.notify("agent.send", { provider: current.id, text: props.ask });
    props.onAskConsumed?.();
  }, [props.ask, providers.length]);

  function send(message = text) {
    if (!current?.available || running || !message.trim()) return;
    client.notify("agent.send", { provider: current.id, text: message.trim() });
    setText("");
  }

  return (
    <div className="agentbar" style={{ width: props.width }}>
      <div className="agent-head">
        <AgentPicker value={agent} onChange={setAgent} onTeam={() => workbench.openPanel("team")} active={running} />
        {agent === "maestro" ? (
          <>
            {engagement && engagement.autonomy !== "copilot" ? (
              (() => {
                const auto = engagement.autonomy === "maestro_auto";
                return (
                  <button
                    className={`mode-toggle${auto ? " auto" : ""}`}
                    title={auto ? t("agent.mode.auto.hint") : t("agent.mode.interactive.hint")}
                    onClick={() => void client.call("engagement.update", { autonomy: auto ? "maestro" : "maestro_auto" }).then(() => refreshEngagement?.()).catch(() => undefined)}
                  >
                    {auto ? t("agent.mode.auto") : t("agent.mode.interactive")}
                  </button>
                );
              })()
            ) : null}
            <button className={`icon-btn ${onlyConversation ? "" : "on"}`} title={onlyConversation ? t("agent.head.showAll") : t("agent.head.showConversation")} onClick={() => setOnlyConversation((v) => !v)}>
              <Users size={14} />
            </button>
            <button className="icon-btn" title={t("agent.head.new")} onClick={() => client.notify("agent.reset")}>
              <SquarePen size={14} />
            </button>
          </>
        ) : null}
      </div>

      {agent === "maestro" ? <PhaseStrip /> : null}
      <div className="chat">
        {agent === "external" ? (
          <ExternalAgents />
        ) : entries.length === 0 && !running ? (
          <div className="intro">
            <Mascot state="idle" size={120} title={t("common.maestro")} />
            <div className="intro-name">{t("common.maestro")}</div>
            <div className="intro-tagline">{t("agent.intro.tagline")}</div>
            <details className="intro-more">
              <summary>{t("agent.intro.more")}</summary>
              <p>{t("agent.intro.body")}</p>
            </details>
            {current?.available ? <Suggestions onPick={(s) => send(s)} /> : null}
          </div>
        ) : (
          <Conversation
            entries={entries}
            running={running}
            {...(current ? { providerLabel: current.label } : {})}
            onlyConversation={onlyConversation}
            // The core tells the agent about decisions (even mid-turn), so nothing to send from here.
            onDecided={() => undefined}
          />
        )}
      </div>

      {/* What waits on the operator: its own scroll, so the conversation always keeps room. */}
      <div className={`decisions${agent === "maestro" && engagement?.autonomy === "maestro_auto" ? " auto" : ""}`}>
      {agent === "maestro" && engagement?.autonomy === "maestro_auto" ? <AutoTrayHead running={running} /> : null}
      <Approvals />
      {agent === "maestro" && engagement?.autonomy === "maestro_auto" ? <ClientQuestions /> : null}

      {agent === "maestro" ? (
        <WaitingStrip
          running={running}
          parked={parked}
          hasConversation={entries.length > 0}
          inlineApprovals={0}
          onResume={() => {
            setParked(false);
            client.notify("agent.resume");
          }}
        />
      ) : null}
      </div>

      {agent === "maestro" ? (
        <div className="composer">
          <textarea
            value={text}
            disabled={!current?.available || !mayInstruct}
            placeholder={
              !mayInstruct
                ? t("agent.composer.readOnly")
                : current?.available
                  ? t("agent.composer.default")
                  : t("agent.composer.noProvider")
            }
            onChange={(e) => setText(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter" && !e.shiftKey) {
                e.preventDefault();
                send();
              }
            }}
          />
          <div className="bar">
            <ProviderPicker
              providers={providers}
              {...(provider ? { value: provider } : {})}
              onChange={(id) => {
                setProvider(id);
                client.notify("agent.select", { provider: id });
              }}
              onConfigure={setConfiguring}
              onVerifier={() => setVerifierOpen(true)}
            />
            <div style={{ flex: 1 }} />
            {running ? (
              <button className="btn sm" onClick={() => client.notify("agent.stop")} title={t("common.stop")}>
                <Square size={11} /> {t("common.stop")}
              </button>
            ) : (
              <button className="send-btn" disabled={!canSend} onClick={() => send()} title={t("common.send")}>
                <ArrowUp size={14} />
              </button>
            )}
          </div>
        </div>
      ) : (
        <div className="composer">
          <div className="bar"><Wrench size={12} /> {t("agent.external.footer")}</div>
        </div>
      )}

      {verifierOpen ? <RoleSettingsModal role="verifier" providers={providers} onClose={() => setVerifierOpen(false)} /> : null}
      {configuring ? (
        <ProviderSettings
          provider={configuring}
          onClose={() => setConfiguring(undefined)}
          onSaved={(list) => {
            setProviders(list);
            const p = list.find((x) => x.id === configuring.id);
            if (p?.available) setProvider(p.id);
          }}
        />
      ) : null}
    </div>
  );
}
