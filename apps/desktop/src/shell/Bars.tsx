import { Bot, Check, ChevronDown, FolderOpen, Loader2, Network, OctagonX, Pause, PanelBottom, PanelRight, Play, Plus, Search, Shield, ShieldCheck, SquareTerminal, Users, X , Mark } from "../ui/icons";
import { useCallback, useEffect, useRef, useState } from "react";
import type { CoreClient } from "../client";
import { ActivityPanel } from "../panels/Activity";
import { OperatorLogPanel } from "../panels/OperatorLog";
import { ProjectWizard } from "../ProjectWizard";
import { modeOf } from "../modes";
import { type Menu, MenuBar } from "../ui/MenuBar";
import { asksOperator, questionOf } from "../tasks";
import { RunsPanel, useRunningRuns } from "../panels/Runs";
import { TerminalPanel } from "../panels/Terminal";
import { type BottomTab, can, type EditorPanelId, type Entity, useApp, useOperation } from "../state";
import { toast } from "../ui/bits";
import { t, tn } from "../i18n";

import { BOTTOM, EDITOR, type Sizes } from "./registry";
import { groupOf } from "./groups";
import { useHasPluginHub } from "../ui/plugins";
// ---------------------------------------------------------------------------------------------
// Title bar, engagement switcher, activity bar, status bar
// ---------------------------------------------------------------------------------------------

export interface EngagementSummary {
  id: string;
  clientName: string;
  name: string;
  mode: string;
  createdAt?: string;
  missing?: boolean;
}

/** Projects grouped by client: the current client first, then alphabetical; newest project first. */
function byClient(list: EngagementSummary[], currentClient?: string): Array<{ client: string; items: EngagementSummary[] }> {
  const groups = new Map<string, EngagementSummary[]>();
  for (const e of list) groups.set(e.clientName, [...(groups.get(e.clientName) ?? []), e]);
  return [...groups.entries()]
    .map(([client, items]) => ({ client, items: [...items].sort((a, b) => (b.createdAt ?? "").localeCompare(a.createdAt ?? "")) }))
    .sort((a, b) => (a.client === currentClient ? -1 : b.client === currentClient ? 1 : a.client.localeCompare(b.client)));
}

function EngagementSwitcher(props: { onNew: () => void; onOpen: () => void }) {
  const { engagement, client, teamMode } = useApp();
  const [open, setOpen] = useState(false);
  const [list, setList] = useState<EngagementSummary[]>([]);
  const [query, setQuery] = useState("");
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (!open) return;
    setQuery("");
    client.call<{ engagements: EngagementSummary[] }>("engagement.list").then((r) => setList(r.engagements));
    const close = (e: MouseEvent) => ref.current && !ref.current.contains(e.target as Node) && setOpen(false);
    window.addEventListener("mousedown", close);
    return () => window.removeEventListener("mousedown", close);
  }, [open, client]);
  if (!engagement) return null;
  const q = query.trim().toLowerCase();
  const filtered = q ? list.filter((e) => `${e.clientName} ${e.name}`.toLowerCase().includes(q)) : list;
  const groups = byClient(filtered, engagement.clientName);
  return (
    <div ref={ref}>
      <button className="switcher" onClick={() => setOpen((v) => !v)} title={t("shell.switcher.title")}>
        <span>{engagement.clientName}</span>
        <span className="sep">/</span>
        <b>{engagement.name}</b>
        <span className="mode">{modeOf(engagement.mode).title}</span>
        <ChevronDown size={13} color="var(--fg-3)" />
      </button>
      {open ? (
        <div className="dropdown switcher-menu">
          {list.length > 6 ? (
            <div className="switcher-search">
              <Search size={12} color="var(--fg-3)" />
              {/* i18n-ignore: user text input, not UI copy */}
              <input autoFocus value={query} onChange={(e) => setQuery(e.target.value)} placeholder={t("shell.switcher.search")} />
            </div>
          ) : null}
          <div className="switcher-list">
            {groups.map((g) => (
              <div key={g.client} className="switcher-group">
                <div className="group-header">{g.client} <span className="gcount">{g.items.length}</span></div>
                {g.items.map((e) => e.missing ? (
                  <div key={e.id} className="item missing" title={t("shell.switcher.missing")}>
                    <span style={{ width: 13 }} />
                    <span className="n">{e.name}</span>
                    <button className="forget" title={t("shell.switcher.forget")} onClick={(ev) => { ev.stopPropagation(); void client.call("project.forget", { id: e.id }).then(() => setList((l) => l.filter((x) => x.id !== e.id))).catch(() => undefined); }}><X size={12} /></button>
                  </div>
                ) : (
                  <div key={e.id} className={`item ${e.id === engagement.id ? "on" : ""}`} onClick={() => { client.activate(e.id); setOpen(false); }}>
                    {e.id === engagement.id ? <Check size={13} color="var(--accent)" /> : <span style={{ width: 13 }} />}
                    <span className="n">{e.name}</span>
                    <span className="c">{modeOf(e.mode).title}</span>
                  </div>
                ))}
              </div>
            ))}
            {groups.length === 0 ? <div className="switcher-empty">{t("shell.switcher.empty")}</div> : null}
          </div>
          <div className="sepline" />
          <div className="item new" onClick={() => { setOpen(false); props.onNew(); }}>
            <Plus size={13} /> <span className="n">{t("shell.file.newProject")}</span>
          </div>
          {!teamMode && window.penteosDesktop?.openProjectDialog ? (
            <div className="item new" onClick={() => { setOpen(false); props.onOpen(); }}>
              <FolderOpen size={13} /> <span className="n">{t("shell.file.open")}</span>
            </div>
          ) : null}
        </div>
      ) : null}
    </div>
  );
}

export function TopBar(props: { onStop: () => void; onNew: () => void; onOpen: () => void; openApprovals: () => void; sizes: Sizes; toggle: (k: "bottomOpen" | "agentOpen") => void; menus: Menu[] }) {
  const { engagement, workbench } = useApp();
  const stopped = Boolean(engagement?.stopWork?.active);
  return (
    <div className="topbar">
      <div className="brand-mark" title="Penteos"><Mark size={22} title="Penteos" /></div>
      <MenuBar menus={props.menus} />
      <EngagementSwitcher onNew={props.onNew} onOpen={props.onOpen} />
      <div className="topbar-spacer" />
      <button className="search-trigger" onClick={workbench.openPalette}>
        <Search size={13} />
        <span className="label">{t("shell.search.label")}</span>
        <span className="kbd">Ctrl K</span>
      </button>
      <div className="topbar-spacer" />
      <button className={`icon-btn ${props.sizes.bottomOpen ? "on" : ""}`} title={`${t("shell.view.bottomPanel")} (Ctrl+J)`} onClick={() => props.toggle("bottomOpen")}>
        <PanelBottom size={15} />
      </button>
      <button className={`icon-btn ${props.sizes.agentOpen ? "on" : ""}`} title={`${t("shell.view.agent")} (Ctrl+L)`} onClick={() => props.toggle("agentOpen")}>
        <PanelRight size={15} />
      </button>
      <div className="controls">
        {/* With the agent bar open, its tray already shows them. */}
        {props.sizes.agentOpen ? null : <ApprovalsButton onClick={props.openApprovals} />}
        <EmergencyMenu stopped={stopped} onStop={props.onStop} />
      </div>
    </div>
  );
}

/** Pending approvals live in the agent bar; this is the way in when the bar is closed. */
function ApprovalsButton(props: { onClick: () => void }) {
  const { approvals } = useApp();
  if (!approvals.length) return null;
  return (
    <button className="approvals-btn" onClick={props.onClick} title={t("shell.approvals.title")}>
      <Bot size={13} /> {tn("shell.approvals.count", approvals.length)}
    </button>
  );
}

/** Sections whose tooltip says more than the title. */
const TIPS = new Set<EditorPanelId>(["identities", "evolution", "team", "coverage"]);
const tipOf = (id: EditorPanelId): string => (TIPS.has(id) ? t(`shell.tip.${id}`) : EDITOR[id].title);

interface Attention {
  count: number;
  urgent: boolean;
  /** One line: what is waiting, in words. */
  summary: string;
  /** What exactly: task titles, findings (a few). */
  items: string[];
}

/**
 * What each section needs from the operator right now (not its totals): questions and tasks
 * assigned to them and findings waiting for a human decision.
 */
function useAttention(): Partial<Record<EditorPanelId, Attention>> {
  const { me } = useApp();
  const tasks = useOperation<Entity[]>("entity.query", { kind: "task", limit: 2000 }, { refreshOn: (e) => e.kind === "task" });
  const findings = useOperation<Entity[]>("entity.query", { kind: "finding", limit: 2000 }, { refreshOn: (e) => e.kind === "finding" });
  const out: Partial<Record<EditorPanelId, Attention>> = {};
  const open = (t: Entity) => !["done", "cancelled"].includes(String(t.attributes.status));
  const mine = (t: Entity) => {
    const a = t.attributes.assignee as { type: string; id: string } | null | undefined;
    return a?.type === "human" && (a.id === me?.id || a.id === "01JA0000000000000000000HMN");
  };
  const asks = (tasks.data ?? []).filter(asksOperator);
  const todo = (tasks.data ?? []).filter((t) => open(t) && mine(t) && !asksOperator(t));
  if (asks.length || todo.length) {
    const n = asks.length + todo.length;
    out.board = {
      count: n,
      urgent: asks.length > 0 || todo.some((t) => ["urgent", "high"].includes(String(t.attributes.priority))),
      summary: asks.length ? tn("shell.attention.asks", asks.length) : tn("shell.attention.todo", todo.length),
      items: [...asks, ...todo].slice(0, 4).map((t) => questionOf(t).question),
    };
  }
  const review = (findings.data ?? []).filter((f) => f.attributes.status === "in_review");
  if (review.length) {
    const doubtful = review.filter((f) => (f.attributes.verification as { verdict?: string } | undefined)?.verdict === "not_reproduced").length;
    out.findings = {
      count: review.length,
      urgent: false,
      summary: [tn("shell.attention.review", review.length), doubtful ? tn("shell.attention.notReproduced", doubtful) : ""].filter(Boolean).join(" · "),
      items: review.slice(0, 4).map((f) => String(f.attributes.title)),
    };
  }
  return out;
}

/**
 * A faint "there is something new" dot on Findings and Board: set when their count grows beyond what
 * you last saw, cleared when you open that section. Per project, remembered in localStorage.
 */
function useNovelty(active?: EditorPanelId): Set<EditorPanelId> {
  const { engagement } = useApp();
  const tasks = useOperation<Entity[]>("entity.query", { kind: "task", limit: 2000 }, { refreshOn: (e) => e.kind === "task" });
  const findings = useOperation<Entity[]>("entity.query", { kind: "finding", limit: 2000 }, { refreshOn: (e) => e.kind === "finding" });
  const eid = engagement?.id ?? "";
  const counts: Partial<Record<EditorPanelId, number>> = { findingsGroup: (findings.data ?? []).length, boardGroup: (tasks.data ?? []).length };
  const [novel, setNovel] = useState<Set<EditorPanelId>>(new Set());
  useEffect(() => {
    if (!eid) return;
    const key = (p: EditorPanelId) => `penteos.seen.${eid}.${p}`;
    const next = new Set<EditorPanelId>();
    for (const p of ["findingsGroup", "boardGroup"] as const) {
      const c = counts[p] ?? 0;
      let raw: string | null = null;
      try { raw = localStorage.getItem(key(p)); } catch { /* ignore */ }
      // The active section, and the first time we ever see a section, count as "seen": no dot for what is already there.
      if (p === active || raw === null) { try { localStorage.setItem(key(p), String(c)); } catch { /* ignore */ } continue; }
      if (c > Number(raw)) next.add(p);
    }
    setNovel(next);
  }, [active, counts.findingsGroup, counts.boardGroup, eid]);
  return novel;
}

/** The activity bar's order: daily work first, the project's configuration last. */
const PLACES: EditorPanelId[] = ["home", "surface", "proxy", "findingsGroup", "boardGroup", "operation", "report", "extensions", "projectGroup"];

export function ActivityBar(props: { active?: string; sections: EditorPanelId[]; showTeam: boolean }) {
  const { workbench } = useApp();
  const raw = useAttention();
  // What a panel needs from the operator shows on the place that holds it.
  const attention: Partial<Record<EditorPanelId, Attention>> = {};
  for (const [id, a] of Object.entries(raw) as Array<[EditorPanelId, Attention]>) {
    const place = groupOf(id) ?? id;
    const prev = attention[place];
    attention[place] = prev ? { count: prev.count + a.count, urgent: prev.urgent || a.urgent, summary: `${prev.summary} · ${a.summary}`, items: [...prev.items, ...a.items].slice(0, 4) } : a;
  }
  // Extensions: only when the project's plugins bring panels or actions.
  const hub = useHasPluginHub();
  const used = new Set<EditorPanelId>(["home", ...props.sections.map((id) => groupOf(id) ?? id), "projectGroup", ...(hub ? (["extensions"] as const) : [])]);
  const items = PLACES.filter((id) => used.has(id)).map((id) => ({ id, tip: tipOf(id) }));
  const bottom: Array<{ id: EditorPanelId; tip: string }> = props.showTeam ? [{ id: "team", tip: tipOf("team") }] : [];
  const activePlace = props.active ? (groupOf(props.active as EditorPanelId) ?? props.active) : undefined;
  const novelty = useNovelty(activePlace as EditorPanelId | undefined);
  const button = (i: { id: EditorPanelId; tip: string }) => {
    const a = attention[i.id];
    return (
      <button key={i.id} className={`ab-btn ${activePlace === i.id ? "active" : ""} ${a ? "needs" : ""}`} aria-label={a ? `${i.tip}: ${a.summary}` : i.tip} onClick={() => workbench.openPanel(i.id)}>
        {EDITOR[i.id].icon(18)}
        <span className="ab-label">{EDITOR[i.id].title}</span>
        {!a && novelty.has(i.id) ? <span className="ab-new" title={t("shell.attention.new")} /> : null}
        {a ? <span className={`count ${a.urgent ? "urgent" : ""}`}>{a.count}</span> : null}
        {a ? <span className={`ab-line ${a.urgent ? "urgent" : ""}`} /> : null}
        {a ? (
          <span className="ab-tip" role="tooltip">
            <span className="ab-tip-title">{EDITOR[i.id].title}</span>
            <span className={`ab-tip-sum ${a.urgent ? "urgent" : ""}`}>{a.summary}</span>
            {a.items.map((x, k) => <span key={k} className="ab-tip-item">{x}</span>)}
            {a.items.length < a.count ? <span className="ab-tip-more">{t("shell.attention.more", { n: a.count - a.items.length })}</span> : null}
          </span>
        ) : null}
      </button>
    );
  };
  return (
    <div className="activitybar">
      {items.map(button)}
      <div className="grow" />
      {bottom.map(button)}
    </div>
  );
}

/** Intercepted messages hold the browser: never let that go unnoticed. */
function InterceptIndicator() {
  const { workbench, teamMode, client } = useApp();
  const state = useOperation<{ settings: { requests: boolean; responses: boolean; wsMessages: boolean }; pending: unknown[] }>("intercept.state", {}, { refreshOn: (e) => e.type === "intercept.changed" });
  // What the Maestro changes in the proxy, the operator sees at once.
  useEffect(
    () =>
      client.onEvent((e) => {
        if (e.type === "proxy.agent_changed") toast("info", t("shell.proxy.agentChanged"), proxyChange(e as Record<string, unknown>));
        if (e.type === "host.unreachable") toast("bad", t("shell.hostUnreachable.title", { host: String((e as Record<string, unknown>).host ?? "") }), t("shell.hostUnreachable.body"));
      }),
    [client],
  );
  if (teamMode || client.remote || !state.data) return null;
  const on = state.data.settings.requests || state.data.settings.responses || state.data.settings.wsMessages;
  if (!on && state.data.pending.length === 0) return null;
  return (
    <div
      className={`item clickable ${state.data.pending.length ? "alert" : ""}`}
      title={t("shell.intercept.title")}
      onClick={() => {
        workbench.openPanel("proxy");
        setTimeout(() => window.dispatchEvent(new CustomEvent("penteos:proxy-tab", { detail: "intercept" })), 50);
      }}
    >
      <Network size={12} /> {state.data.pending.length ? t("shell.intercept.held", { n: state.data.pending.length }) : t("shell.intercept.on")}
    </div>
  );
}

/**
 * The emergency controls in one place: pause the agents (people keep
 * working) or stop-work (everything stops). Quiet while nothing is on; in colour while one is.
 */
function EmergencyMenu(props: { stopped: boolean; onStop: () => void }) {
  const { client, engagement, me } = useApp();
  const [paused, setPaused] = useState(false);
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);
  const load = useCallback(
    () =>
      client.call<{ paused: boolean }>("team.status").then((s) => setPaused(Boolean(s.paused)), () => {}),
    [client],
  );
  useEffect(() => {
    void load();
    return client.onEvent((e) => {
      if (e.type === "agents.paused") setPaused(Boolean(e.paused));
    });
  }, [client, load, engagement?.id]);
  useEffect(() => {
    if (!open) return;
    const close = (e: MouseEvent) => ref.current && !ref.current.contains(e.target as Node) && setOpen(false);
    window.addEventListener("mousedown", close);
    return () => window.removeEventListener("mousedown", close);
  }, [open]);
  if (!engagement) return null;
  const agents = can(me, "operator");
  const togglePause = () =>
    client.call(paused ? "agents.resume" : "agents.pause").then(
      () => toast(paused ? "ok" : "info", paused ? t("shell.panic.resumed") : t("shell.panic.paused"), paused ? undefined : t("shell.panic.pausedBody")),
      (e: Error) => toast("bad", t("shell.panic.failed"), e.message),
    );
  const state = props.stopped ? "stopped" : paused ? "paused" : "";
  return (
    <div className="emergency" ref={ref}>
      <button className={`emergency-btn ${state}`} onClick={() => setOpen((v) => !v)} title={t("shell.emergency.title")}>
        {props.stopped ? <OctagonX size={14} /> : paused ? <Pause size={13} /> : <OctagonX size={14} />}
        {props.stopped ? t("shell.stop.active") : paused ? t("shell.panic.paused") : t("shell.emergency.label")}
        <ChevronDown size={12} />
      </button>
      {open ? (
        <div className="dropdown emergency-menu">
          {agents ? (
            <div className="item" onClick={() => { setOpen(false); void togglePause(); }}>
              {paused ? <Play size={13} /> : <Pause size={13} />}
              <div>
                <div className="n">{paused ? t("shell.panic.resume") : t("shell.panic.pause")}</div>
                <div className="c">{t("shell.emergency.pauseHint")}</div>
              </div>
            </div>
          ) : null}
          <div className="item danger" onClick={() => { setOpen(false); props.onStop(); }}>
            <OctagonX size={13} />
            <div>
              <div className="n">{props.stopped ? t("shell.stop.resumeTitle") : t("shell.stop.activateTitle")}</div>
              <div className="c">{t("shell.emergency.stopHint")}</div>
            </div>
          </div>
        </div>
      ) : null}
    </div>
  );
}

/** Informative only: what the agents are doing (the controls are in the top bar). */
function AgentsIndicator() {
  const { client, engagement, workbench } = useApp();
  const [s, setS] = useState<{ paused: boolean; maestro: boolean }>();
  useEffect(() => {
    const load = () =>
      client
        .call<{ paused: boolean; maestro: { running: boolean } }>("team.status")
        .then((r) => setS({ paused: r.paused, maestro: r.maestro.running }), () => {});
    void load();
    const off = client.onEvent((e) => {
      if (e.type === "agents.paused") void load();
    });
    const offA = client.onAgentEvent((e) => {
      if (e.kind === "done" || e.kind === "user") void load();
    });
    return () => {
      off();
      offA();
    };
  }, [client, engagement?.id]);
  if (!engagement || !s) return null;
  const text = s.paused ? t("shell.agents.paused") : s.maestro ? t("shell.agents.maestro") : null;
  if (!text) return null;
  return (
    <div className={`item clickable ${s.paused ? "alert" : ""}`} onClick={() => workbench.openPanel("team")} title={t("shell.agents.title")}>
      <Users size={12} /> {text}
    </div>
  );
}

export function StatusBar(props: { openBottom: (t: BottomTab) => void; openAgent: () => void; bottomOpen?: boolean }) {
  const { connected, engagement, workbench, client, me, online, teamMode } = useApp();
  const running = useRunningRuns();
  const c = engagement?.counts ?? {};
  const where = client.remote ? t("shell.status.teamServer") : teamMode ? t("shell.status.localTeam") : t("shell.status.local");
  return (
    <div className="statusbar">
      <div className="item" title={connected ? t("shell.status.connected") : t("shell.status.reconnectingTitle")}>
        <span className={`led ${connected ? "ok" : engagement ? "warn" : "bad"}`} /> {connected ? where : engagement ? t("shell.status.reconnecting") : t("shell.status.connecting")}
      </div>
      {running && !props.bottomOpen ? (
        <div className="item clickable running-item" onClick={() => props.openBottom("runs")}>
          <Loader2 size={12} className="spin" /> {tn("shell.runs.running", running)}
        </div>
      ) : null}
      {teamMode || client.remote ? (
        <div className="item clickable" title={online.map((o) => `${o.name} (${o.role})`).join("\n")} onClick={() => workbench.openPanel("team")}>
          <Users size={12} /> {me?.name ?? t("common.you")} · {tn("shell.status.online", online.length)}
        </div>
      ) : null}
      {engagement ? (
        <>
          <div className="item clickable" onClick={() => workbench.openPanel("scope")}>
            <ShieldCheck size={12} /> {tn("shell.status.scopeRules", engagement.scope.length)}
          </div>
          <div className="item">
            {t("shell.status.counts", { hosts: c.host ?? 0, services: c.service ?? 0, findings: c.finding ?? 0 })}
          </div>
        </>
      ) : null}
      <div className="grow" />
      <InterceptIndicator />
      <AgentsIndicator />
      {engagement?.stopWork?.active ? (
        <div className="item" style={{ color: "var(--bad)" }}>
          <span className="led bad" /> {t("shell.status.stopWork")}
        </div>
      ) : null}
      <div className="item clickable" onClick={() => props.openBottom("terminal")}>
        <SquareTerminal size={12} /> {t("shell.status.terminal")}
      </div>
    </div>
  );
}

export function BottomPanel(props: { tab: BottomTab; tabs: BottomTab[]; setTab: (t: BottomTab) => void; height: number; onClose: () => void }) {
  const running = useRunningRuns();
  return (
    <div className="bottom" style={{ height: props.height }}>
      <div className="strip">
        <div className="tabs">
          {props.tabs.map((t) => (
            <button key={t} className={`tab-btn ${props.tab === t ? "on" : ""}`} onClick={() => props.setTab(t)}>
              {BOTTOM[t].title}
              {t === "runs" && running ? <span className="tab-running" title={tn("shell.runs.running", running)}><Loader2 size={11} className="spin" /> <span className="mono">{running}</span></span> : null}
            </button>
          ))}
        </div>
        <div className="grow" />
        <button className="icon-btn" title={t("shell.bottom.close")} onClick={props.onClose}>
          <X size={14} />
        </button>
      </div>
      <div className="bottom-body">
        {/* All panes stay mounted so the shell session survives tab switches. */}
        <div className="pane" style={{ display: props.tab === "terminal" ? "flex" : "none" }}><TerminalPanel /></div>
        {props.tabs.includes("log") ? <div className="pane" style={{ display: props.tab === "log" ? "flex" : "none" }}><OperatorLogPanel /></div> : null}
        <div className="pane" style={{ display: props.tab === "runs" ? "flex" : "none" }}><RunsPanel /></div>
        <div className="pane" style={{ display: props.tab === "activity" ? "flex" : "none" }}><ActivityPanel /></div>
      </div>
    </div>
  );
}

/** What an agent changed in the proxy, in the operator's language (the event's own text is English). */
function proxyChange(e: Record<string, unknown>): string {
  const reason = typeof e.reason === "string" && e.reason ? `: ${e.reason}` : "";
  const n = Number(e.count ?? 0);
  if (e.change === "intercept") {
    const on = Array.isArray(e.on) ? e.on.map((x) => t(`shell.proxy.intercepting.${String(x)}`)) : [];
    return (on.length ? t("shell.proxy.interceptOn", { what: on.join(", ") }) : t("shell.proxy.interceptOff")) + reason;
  }
  if (e.change === "release") return tn("shell.proxy.released", n) + reason;
  if (e.change === "rules") return (n ? tn("shell.proxy.rulesOn", n) : t("shell.proxy.rulesOff")) + reason;
  return String(e.text ?? "");
}
