import { Copy, Loader2, Pause, Plug, Server, Settings2, UserPlus, Users } from "../ui/icons";
import { Helmet } from "../ui/Helmet";
import { useCallback, useEffect, useState } from "react";
import type { AgentEvent } from "../client";
import type { Provider } from "./AgentSidebar";
import { can, useApp, useOperation } from "../state";
import { Badge, Modal, relTime, toast, useTick } from "../ui/bits";
import { RoleSettingsModal } from "../ui/RoleSettings";
import { Transcript } from "../ui/Verification";
import { AUTONOMY_ES } from "../labels";
import { t, tn } from "../i18n";
import { appendDelta } from "../ui/stream";

interface Operator {
  id: string;
  name: string;
  role: string;
  createdAt: string;
  disabled: boolean;
}

const ROLES = ["observer", "reviewer", "operator", "lead"];
const roleName = (r: string): string => (ROLES.includes(r) ? t(`team.role.${r}`) : r);
const roleHelp = (r: string): string => (ROLES.includes(r) ? t(`team.roleHelp.${r}`) : "");

declare global {
  interface Window {
    penteosDesktop?: {
      getConnection(): Promise<{ mode: "local" } | { mode: "remote"; url: string }>;
      setConnection(c: { mode: "local" } | { mode: "remote"; url: string; token: string; fingerprint?: string }): Promise<void>;
      /** The operator's interface language, for the start-up dialogs. */
      setLanguage?(language: "es" | "en"): Promise<void>;
      /** Opens the project browser (through Penteos's proxy). */
      openBrowser?(options: Record<string, unknown>): Promise<void>;
      /** Where projects live on disk. */
      projectDir?(): Promise<{ dataDir: string; home: string; remote: boolean }>;
      /** Save dialog for exporting a .penteos; resolves to the path or null. */
      exportProject?(suggestedName: string): Promise<string | null>;
      /** Open dialog for importing a .penteos; resolves to the path or null. */
      importProject?(): Promise<string | null>;
      /** Pick a project folder to open; resolves to the directory or null. */
      openProjectDialog?(): Promise<string | null>;
      /** Saves the deliverable as a PDF: asks where, lays it out page by page, prints it. */
      savePdf?(html: string, fileName: string): Promise<{ ok: boolean; path?: string; size?: number; canceled?: boolean; error?: string }>;
      /** Opens a file a plugin made with the system's program for it (documents, data, images). */
      openFile?(path: string): Promise<{ ok: boolean; error?: string }>;
      /** Shows a file in its folder (or opens a folder) in the OS file manager. */
      revealFile?(path: string): Promise<{ ok: boolean; error?: string }>;
      /** Restarts the app, in safe mode (every plugin off) or out of it. */
      restart?(opts: { safeMode: boolean }): Promise<void>;
      /** Pick the folder where new projects are created; resolves to the directory or null. */
      chooseProjectsRoot?(): Promise<string | null>;
      /** The workbench is connected: the splash window gives way to it. */
      appReady?(): void;
      /** Progress or closing of the Maestro's note in the project browser. */
      updateBrowserNote?(update: { engagementId: string; taskId: string; exchanges?: number; hosts?: string[]; sent?: string }): Promise<void>;
      /** Save / open dialogs for tool kits (.penteos-tools). */
      exportToolsKit?(suggestedName?: string): Promise<string | null>;
      importToolsKit?(): Promise<string | null>;
      /** "Done" pressed on the note inside the browser. */
      onBrowserNoteAction?(cb: (p: { engagementId: string; taskId: string; action: string }) => void): () => void;
      /** A way out of a page the proxy blocked, chosen in the browser. */
      onBrowserBlockAction?(cb: (p: { engagementId: string; action: string; host: string; url?: string; kind: string }) => void): () => void;
      /** Tells the browser the way out was taken (it reloads) or why not. */
      resolveBrowserBlock?(p: { engagementId: string; done?: boolean; error?: string }): Promise<void>;
    };
  }
}

// ---------------------------------------------------------------------------------------------
// Agents: one card per agent, with its state
// ---------------------------------------------------------------------------------------------

interface TeamStatus {
  autonomy: "copilot" | "maestro" | "maestro_auto";
  paused: boolean;
  maestro: { running: boolean; provider: string | null; parked: boolean };
  verifier: { active: number; provider?: string; reason?: string };
}

export const LEVEL_ES = AUTONOMY_ES;

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

/** The transcript of a sub-agent (the verifier), live. Used from the Sala cards. */
export function AgentTranscript(props: { transcriptKey: string }) {
  const { client } = useApp();
  const [events, setEvents] = useState<AgentEvent[]>([]);
  useEffect(() => {
    let alive = true;
    client.request<{ events: AgentEvent[] }>("subagent.transcript", { key: props.transcriptKey }).then((r) => alive && setEvents(r.events ?? []), () => {});
    const off = client.onSubagentEvent((k, e) => k === props.transcriptKey && setEvents((cur) => fold(cur, e)));
    return () => {
      alive = false;
      off();
    };
  }, [client, props.transcriptKey]);
  return <Transcript events={events} />;
}

function AgentsSection(props: { providers: Provider[] }) {
  const { client, me, engagement } = useApp();
  const [status, setStatus] = useState<TeamStatus>();
  const [role, setRole] = useState<"verifier">();
  const isLead = can(me, "lead");
  const load = useCallback(() => client.call<TeamStatus>("team.status").then(setStatus), [client]); // i18n-ignore
  useEffect(() => {
    void load();
    return client.onEvent((e) => {
      if (e.type === "agents.paused" || e.type === "engagement.updated" || e.type === "approval.changed") void load();
    });
  }, [client, load, engagement?.id]);
  useEffect(() => client.onAgentEvent((e) => { if (e.kind === "done" || e.kind === "user") void load(); }), [client, load]);
  if (!status) return null;
  const level = status.autonomy;
  return (
    <section>
      <h2>{t("team.agents.title")}</h2>
      {status.paused ? <div className="callout" style={{ borderColor: "var(--warn)", marginBottom: 10 }}><div className="t"><Pause size={14} /> {t("team.agents.paused.title")}</div>{t("team.agents.paused.body")}</div> : null}
      <div className="agent-cards">
        <div className="agent-card">
          <div className="ac-head">
            <span className="avatar"><Helmet role="maestro" size={22} active={status.maestro.running} /></span>
            <div className="ac-name">{t("common.maestro")}</div>
            <Badge tone={status.maestro.running ? "accent" : ""}>{status.maestro.running ? <><Loader2 size={11} className="spin" /> {t("team.maestro.working")}</> : status.maestro.parked ? t("team.maestro.parked") : t("team.maestro.idle")}</Badge>
            <div className="grow" />
            <span className="muted" style={{ fontSize: 11 }}>{LEVEL_ES[level]}{status.maestro.provider ? ` · ${status.maestro.provider}` : ""}</span>
          </div>
          <div className="ac-last muted">{level === "copilot" ? t("team.maestro.desc.copilot") : t("team.maestro.desc.maestro")}</div>
        </div>
        <div className="agent-card">
          <div className="ac-head">
            <span className="avatar"><Helmet role="verifier" size={20} active={status.verifier.active > 0} /></span>
            <div className="ac-name">{t("common.verifier")}</div>
            <Badge tone={status.verifier.active ? "accent" : ""}>{status.verifier.active ? tn("team.verifier.active", status.verifier.active) : t("team.verifier.idle")}</Badge>
            <div className="grow" />
            {isLead ? <button className="btn sm ghost" onClick={() => setRole("verifier")}><Settings2 size={12} /> {t("team.model")}</button> : null}
          </div>
          <div className="ac-last muted">{status.verifier.reason ?? t("team.verifier.desc", { provider: status.verifier.provider })}</div>
        </div>
      </div>

      {role ? <RoleSettingsModal role={role} providers={props.providers} onClose={() => { setRole(undefined); void load(); }} /> : null}
    </section>
  );
}

// ---------------------------------------------------------------------------------------------
// Humans: connection and operators
// ---------------------------------------------------------------------------------------------

function ConnectionCard() {
  const { teamMode } = useApp();
  const [connection, setConnection] = useState<{ mode: string; url?: string }>();
  const [editing, setEditing] = useState(false);
  const [url, setUrl] = useState("");
  const [token, setToken] = useState("");
  const [fingerprint, setFingerprint] = useState("");
  useEffect(() => {
    window.penteosDesktop?.getConnection().then(setConnection);
  }, []);
  const remote = connection?.mode === "remote";
  return (
    <div className="callout">
      <div className="t"><Server size={14} /> {t("team.connection.title")}</div>
      {remote ? (
        <>{t("team.connection.remote")} <span className="mono" style={{ color: "var(--fg-0)" }}>{connection?.url}</span>.</>
      ) : (
        <>{t("team.connection.local")}{teamMode ? t("team.connection.localExposed") : ""}.</>
      )}
      <div style={{ display: "flex", gap: 8, marginTop: 10 }}>
        <button className="btn sm" onClick={() => setEditing(true)}><Plug size={12} /> {t("team.connection.connect")}</button>
        {remote ? <button className="btn sm ghost" onClick={() => window.penteosDesktop?.setConnection({ mode: "local" })}>{t("team.connection.backToLocal")}</button> : null}
      </div>
      {editing ? (
        <Modal
          title={t("team.connection.connect")}
          icon={<Plug size={16} />}
          onClose={() => setEditing(false)}
          footer={
            <>
              <button className="btn ghost" onClick={() => setEditing(false)}>{t("common.cancel")}</button>
              <button
                className="btn primary"
                disabled={!/^https?:\/\/.+/.test(url) || !token.startsWith("pnt_")}
                onClick={() => window.penteosDesktop?.setConnection({ mode: "remote", url: url.trim(), token: token.trim(), ...(fingerprint.trim() ? { fingerprint: fingerprint.trim() } : {}) })}
              >
                {t("team.connection.connectRestart")}
              </button>
            </>
          }
        >
          <span>{t("team.connection.help")}</span>
          <label>{t("team.connection.url")}<input className="input mono" autoFocus placeholder={t("team.connection.urlPlaceholder")} value={url} onChange={(e) => setUrl(e.target.value)} /></label>
          <label>{t("team.connection.token")}<input className="input mono" type="password" placeholder={t("team.connection.tokenPlaceholder")} value={token} onChange={(e) => setToken(e.target.value)} /></label>
          <label>{t("team.connection.fingerprint")}
            <input className="input mono" placeholder={t("team.connection.fingerprintPlaceholder")} value={fingerprint} onChange={(e) => setFingerprint(e.target.value)} />
          </label>
        </Modal>
      ) : null}
    </div>
  );
}

export function TeamPanel() {
  const { client, me, online, teamMode, engagement } = useApp();
  const now = useTick();
  const team = useOperation<{ operators: Operator[] }>("team.list", {}, { refreshOn: () => false });
  const [name, setName] = useState("");
  const [role, setRole] = useState("operator");
  const [created, setCreated] = useState<{ name: string; token: string }>();
  const [providers, setProviders] = useState<Provider[]>([]);
  const onlineIds = new Set(online.map((o) => o.id));
  const isLead = can(me, "lead");
  // Remote collaboration (operators, presence, the team server) is deferred: show it only when a
  // team/remote setup is actually active, so a solo operator sees just the AI agents here.
  const collaborative = teamMode || client.remote;
  useEffect(() => {
    client.request<{ providers: Provider[] }>("agent.providers").then((r) => setProviders(r.providers), () => {});
  }, [client]);

  async function add() {
    try {
      const r = await client.call<{ operator: Operator; token: string }>("team.add", { name: name.trim(), role });
      setCreated({ name: r.operator.name, token: r.token });
      setName("");
      team.reload();
    } catch (e) {
      toast("bad", t("team.panel.createFailed"), (e as Error).message);
    }
  }
  async function toggle(o: Operator) {
    await client.call("team.set_disabled", { id: o.id, disabled: !o.disabled }).catch((e: Error) => toast("bad", t("common.error"), e.message));
    team.reload();
  }

  return (
    <div className="panel">
      <div className="panel-toolbar">
        <Users size={14} />
        <h3>{t("team.panel.title")}</h3>
        {collaborative ? <span className="count">{tn("team.panel.online", online.length)}</span> : null}
        {collaborative && me ? <span className="hint">{t("team.panel.you", { name: me.name, role: roleName(me.role) })}</span> : null}
        {engagement ? <span className="hint">{t("team.panel.ai", { level: LEVEL_ES[engagement.autonomy] ?? engagement.autonomy })}</span> : null}
      </div>
      <div className="panel-scroll">
        <div className="report">
          <AgentsSection providers={providers} />
          {collaborative ? (
          <>
          <ConnectionCard />

          <section>
            <h2>{t("team.panel.onlineNow")}</h2>
            <div className="list">
              {online.map((o) => (
                <div key={o.id} className="row" style={{ gridTemplateColumns: "20px 1fr auto" }}>
                  <span className="led ok" />
                  <span>{o.name}</span>
                  <Badge>{roleName(o.role)}</Badge>
                </div>
              ))}
            </div>
          </section>

          <section>
            <h2>{t("team.panel.operators")}</h2>
            {!teamMode && (team.data?.operators ?? []).length === 0 ? (
              <div className="muted" style={{ marginBottom: 10, lineHeight: 1.5 }}>
                {t("team.panel.localBefore")}<span className="mono">{t("team.panel.serverCommand")}</span>{t("team.panel.localAfter")}
              </div>
            ) : null}
            <div className="list">
              {(team.data?.operators ?? []).map((o) => (
                <div key={o.id} className="row" style={{ gridTemplateColumns: "20px 1fr auto" }}>
                  <span className={`led ${onlineIds.has(o.id) ? "ok" : ""}`} />
                  <div style={{ minWidth: 0 }}>
                    <div className="t" style={o.disabled ? { color: "var(--fg-3)", textDecoration: "line-through" } : undefined}>{o.name}</div>
                    <div className="s">{roleHelp(o.role)} · {t("team.panel.added", { time: relTime(o.createdAt, now) })}</div>
                  </div>
                  <div className="when">
                    <Badge>{roleName(o.role)}</Badge>
                    {isLead ? <button className="btn sm ghost" onClick={() => toggle(o)}>{o.disabled ? t("team.panel.enable") : t("team.panel.disable")}</button> : null}
                  </div>
                </div>
              ))}
            </div>
          </section>

          {isLead ? (
            <section>
              <h2>{t("team.panel.addOperator")}</h2>
              <div style={{ display: "flex", gap: 8 }}>
                <input className="input" placeholder={t("team.panel.namePlaceholder")} value={name} onChange={(e) => setName(e.target.value)} style={{ flex: 1 }} />
                <select className="input" value={role} onChange={(e) => setRole(e.target.value)}>
                  {ROLES.map((r) => <option key={r} value={r}>{roleName(r)}</option>)}
                </select>
                <button className="btn primary" disabled={!name.trim()} onClick={add}><UserPlus size={13} /> {t("common.add")}</button>
              </div>
              <div className="muted" style={{ fontSize: 12, marginTop: 6 }}>{roleHelp(role)}</div>
            </section>
          ) : null}
          </>
          ) : null}
        </div>
      </div>

      {created ? (
        <Modal
          title={t("team.token.title", { name: created.name })}
          icon={<UserPlus size={16} />}
          onClose={() => setCreated(undefined)}
          footer={<button className="btn primary" onClick={() => setCreated(undefined)}>{t("team.token.saved")}</button>}
        >
          <span>{t("team.token.before")}<b style={{ color: "var(--fg-0)" }}>{t("team.token.once")}</b>{t("team.token.after")}</span>
          <code className="mono" style={{ display: "block", padding: "8px 10px", background: "var(--bg-2)", border: "1px solid var(--line-2)", borderRadius: 4, color: "var(--fg-0)", wordBreak: "break-all" }}>{created.token}</code>
          <button className="btn sm" style={{ alignSelf: "flex-start" }} onClick={() => navigator.clipboard.writeText(created.token).then(() => toast("ok", t("team.token.copied")))}>
            <Copy size={12} /> {t("common.copy")}
          </button>
        </Modal>
      ) : null}
    </div>
  );
}
