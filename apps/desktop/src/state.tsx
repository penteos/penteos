import { createContext, type ReactNode, useCallback, useContext, useEffect, useRef, useState } from "react";
import { type CoreClient, type CoreEvent } from "./client";

/** Shapes returned by core operations (subset used by the UI). */
export interface Actor {
  type: "human" | "agent" | "parser" | "system";
  id: string;
}

export interface Entity {
  id: string;
  kind: string;
  naturalKey: string;
  attributes: Record<string, any>;
  conflicts: Array<{ field: string; values: Array<{ value: unknown; source: Actor; observedAt: string }> }>;
  tags: string[];
  outOfScope: boolean;
  createdAt: string;
  createdBy: Actor;
  updatedAt: string;
  revision: number;
  /** Plugin annotations, by plugin id (single-entity reads). */
  ext?: Record<string, Record<string, unknown>>;
}

export interface Run {
  id: string;
  actor: Actor;
  origin: string;
  tool?: string;
  command?: string;
  targets: string[];
  risk: string;
  policy: { result: string; ruleId?: string; reason?: string };
  runner: string;
  status: "running" | "finished" | "failed" | "denied" | "cancelled";
  startedAt: string;
  endedAt?: string;
  exitCode?: number;
  rawIds: string[];
  summary?: Record<string, any>;
}

export interface ScopeRule {
  id: string;
  effect: "include" | "exclude";
  target: { type: string; value?: string; from?: string; to?: string };
  ports?: string;
  maxRisk?: string;
  reason?: string;
  networkContext?: string;
}

export interface EngagementInfo {
  id: string;
  name: string;
  clientName: string;
  mode: string;
  /** When/how in time: pentest (default), retest or continuous. */
  roundMode?: "pentest" | "retest" | "continuous";
  status: string;
  maxRisk: string;
  dataPolicy: string;
  /** How autonomous the AI is: copilot, maestro or maestro_auto. */
  autonomy: "copilot" | "maestro" | "maestro_auto";
  /** Language of the deliverable (findings, report, tasks). The interface follows the operator's. */
  language?: "es" | "en";
  stopWork?: { active: boolean; reason: string; at: string };
  /** Plugins enabled in this project. */
  plugins?: string[];
  counts: Record<string, number>;
  scope: ScopeRule[];
}

export interface Approval {
  id: string;
  request?: {
    kind: "nmap" | "exec" | "scope" | "install" | "manifest" | "phase" | "http" | "fuzz" | "ws" | "proxy_rules" | "findings" | "plugin" | "install_kit" | "capability";
    /** A plugin the Maestro built (kind "plugin"). */
    proposal?: {
      pluginId: string;
      name: string;
      version: string;
      description?: unknown;
      update?: { from?: string };
      permissions: string[];
      sendsTo: string[];
      operations: Array<{ name: string; title: unknown; agent: boolean }>;
      menus: number;
      events: string[];
      entityTypes: string[];
      providers: string[];
      test: { operation: string; at: string; steps: number; requests: number };
      /** A code plugin: its files to review, and what changed against the installed version. */
      code?: { runtime: "node" | "python"; main: string; files: Array<{ path: string; size: number; lines: number }>; diff?: string };
      /** It worked against the real service: with what, what it asked and what came back. */
      live?: { operation: string; input: Record<string, unknown>; sample: string; requests: string[]; checks: string[] };
      /** The Maestro's account of what it checked. */
      evidence?: string;
    };
    findings?: Array<{ id: string; title: string; severity: string; verdict?: string }>;
    tool?: string;
    command?: string;
    manifest?: unknown;
    to?: string;
    summary?: string;
    targets?: string[];
    risk?: string;
    title?: string;
    rule?: { effect: "include" | "exclude"; target: { type: string; value?: string; from?: string; to?: string; entityId?: string }; ports?: string };
    rules?: Array<{ enabled?: boolean; target: string; match: string; replace: string; regex?: boolean }>;
  };
  createdAt: string;
  expiresAt?: string;
  requestedBy: Actor;
  reason: string;
  summary: string;
  warnings: string[];
  localFiles?: string[];
  covers?: number;
  why?: { code: "autonomy"; autonomy: string } | { code: "agent_risk"; risk: string; ceiling: string } | { code: "review" } | { code: "unverifiable"; targets: string } | { code: "no_targets" };
}

/** Sections that open as tabs in the editor area. */
export type EditorPanelId = "plugins" | "extensions" | "home" | "services" | "hosts" | "domains" | "findings" | "scope" | "tools" | "report" | "team" | "identities" | "evolution" | "secrets" | "web" | "notes" | "board" | "memory" | "proxy" | "coverage" | "surface" | "findingsGroup" | "boardGroup" | "projectGroup" | "operation" | "metrics";
/** Tabs of the bottom panel, which is always docked below the editor. */
export type BottomTab = "terminal" | "log" | "runs" | "activity";

export interface Workbench {
  openPanel(id: EditorPanelId | BottomTab): void;
  openEntity(id: string, title: string): void;
  openRun(id: string): void;
  newFinding(prefill?: { entityId: string; label: string }): void;
  openDoc(title: string, markdown: string): void;
  openFinding(id: string, title: string): void;
  openPalette(): void;
  closeActive(): void;
  openRequest(params: { origin: string; raw: string }): void;
  openFuzzer(params: { origin: string; template: string }): void;
  /** A plugin's own panel, in a tab. */
  openPluginPanel(pluginId: string, panelId: string, title: string): void;
  openWsRepeater(params: { url: string; headers: string }): void;
}

export interface Me {
  id: string;
  name: string;
  role: string;
}

const ROLE_ORDER = ["observer", "reviewer", "operator", "lead"];
/** Whether the connected operator has at least this role (solo mode: always lead). */
export function can(me: Me | undefined, role: "observer" | "reviewer" | "operator" | "lead"): boolean {
  return ROLE_ORDER.indexOf(me?.role ?? "lead") >= ROLE_ORDER.indexOf(role);
}

interface Ctx {
  client: CoreClient;
  connected: boolean;
  me?: Me;
  teamMode: boolean;
  online: Me[];
  engagement?: EngagementInfo;
  approvals: Approval[];
  workbench: Workbench;
  refreshEngagement(): void;
}

const AppContext = createContext<Ctx | null>(null);

export function AppProvider(props: { client: CoreClient; workbench: Workbench; children: ReactNode }) {
  const { client } = props;
  const [connected, setConnected] = useState(client.connected);
  const [engagement, setEngagement] = useState<EngagementInfo>();
  const [approvals, setApprovals] = useState<Approval[]>([]);
  const [presence, setPresence] = useState({ me: client.me, teamMode: client.teamMode, online: client.online });
  useEffect(() => client.onPresence(() => setPresence({ me: client.me, teamMode: client.teamMode, online: client.online })), [client]);

  const refreshEngagement = useCallback(() => {
    client.call<EngagementInfo>("engagement.get").then(setEngagement).catch(() => {});
    client.call<Approval[]>("approval.list").then(setApprovals).catch(() => {});
  }, [client]);

  // The socket may have opened before this effect ran: read the flag once, then follow changes.
  useEffect(() => {
    setConnected(client.connected);
    return client.onStatus(setConnected);
  }, [client]);
  useEffect(() => {
    refreshEngagement();
    let timer: ReturnType<typeof setTimeout> | undefined;
    return client.onEvent((e) => {
      if (e.type === "run.output") return;
      // Coalesce bursts (an ingest emits one event per entity).
      clearTimeout(timer);
      timer = setTimeout(refreshEngagement, 120);
    });
  }, [client, refreshEngagement]);

  return (
    <AppContext.Provider
      value={{ client, connected, engagement, approvals, workbench: props.workbench, refreshEngagement, teamMode: presence.teamMode, online: presence.online, ...(presence.me ? { me: presence.me } : {}) }}
    >
      {props.children}
    </AppContext.Provider>
  );
}

export function useApp(): Ctx {
  const ctx = useContext(AppContext);
  if (!ctx) throw new Error("AppContext missing");
  return ctx;
}

/** The app's context when there is one: components also rendered outside the workbench (the report document) use this. */
export function useAppOptional(): Ctx | undefined {
  return useContext(AppContext) ?? undefined;
}

/**
 * Calls an operation and re-runs it when relevant core events arrive. `refreshOn` filters
 * events; by default any change (except streaming output) triggers a refresh.
 */
export function useOperation<T>(
  op: string,
  input: unknown,
  options: { refreshOn?: (e: CoreEvent) => boolean; deps?: unknown[] } = {},
): { data: T | undefined; error?: string; loading: boolean; reload: () => void } {
  const { client } = useApp();
  const [data, setData] = useState<T>();
  const [error, setError] = useState<string>();
  const [loading, setLoading] = useState(true);
  const inputKey = JSON.stringify(input);
  const filter = useRef(options.refreshOn);
  filter.current = options.refreshOn;

  const load = useCallback(() => {
    client
      .call<T>(op, JSON.parse(inputKey))
      .then((d) => {
        setData(d);
        setError(undefined);
      })
      .catch((e: Error) => setError(e.message))
      .finally(() => setLoading(false));
  }, [client, op, inputKey]);

  useEffect(() => {
    load();
    let timer: ReturnType<typeof setTimeout> | undefined;
    return client.onEvent((e) => {
      if (e.type === "run.output") return;
      if (e.type !== "engagement.switched" && filter.current && !filter.current(e)) return;
      clearTimeout(timer);
      timer = setTimeout(load, 150);
    });
  }, [client, load, ...(options.deps ?? [])]);

  return { data, error, loading, reload: load };
}
