/** What the shell knows about: the sections, their icons and components, and the layout sizes. */
import { ErrorBoundary } from "../ui/ErrorBoundary";
import { type DockviewTheme, type IDockviewPanelHeaderProps, type IDockviewPanelProps } from "dockview-react";
import { Bug, Crosshair, GitCompareArrows, FileText, Globe, History, AppWindow, Zap, PlugZap, Network, KanbanSquare, Brain, NotebookPen, Send, KeyRound, House, Play, Radar, Route, ScrollText, Server, ShieldCheck, SquareTerminal, Users, Wrench, X, Grid3x3, Settings2, Activity, Puzzle } from "../ui/icons";
import { type ReactNode, useEffect, useState } from "react";
import type { CoreClient } from "../client";
import { DomainsPanel, HostsPanel, ServicesPanel } from "../panels/Assets";
import { DocPanel } from "../panels/Doc";
import { EntityDetailPanel } from "../panels/EntityDetail";
import { FindingDetailPanel } from "../panels/FindingDetail";
import { FindingsPanel } from "../panels/Findings";
import { ReportPanel } from "../panels/Report";
import { TeamPanel } from "../panels/Team";
import { IdentitiesPanel } from "../panels/Identities";
import { ProjectWizard } from "../ProjectWizard";
import { CoveragePanel } from "../panels/Coverage";
import { MetricsPanel } from "../panels/Metrics";
import { EvolutionPanel } from "../panels/Evolution";
import { SecretsPanel } from "../panels/Secrets";
import { WebPanel } from "../panels/Web";
import { ProxyPanel } from "../panels/Proxy";
import { NotesPanel } from "../panels/Notes";
import { BoardPanel } from "../panels/Board";
import { MemoryPanel } from "../panels/Memory";
import { RequestEditorPanel } from "../panels/RequestEditor";
import { FuzzerPanel } from "../panels/Fuzzer";
import { WsRepeaterPanel } from "../panels/WebSocket";
import { HomePanel } from "../panels/Home";
import { RunDetailPanel } from "../panels/Runs";
import { ScopePanel } from "../panels/Scope";
import { ToolsPanel } from "../panels/Tools";
import { PluginsPanel } from "../panels/Plugins";
import { PluginHubPanel, PluginPanelTab } from "../ui/plugins";
import { type BottomTab, type EditorPanelId } from "../state";
import { createElement } from "react";
import { groupComponent, type GroupId } from "./groups";
import { t } from "../i18n";

export const theme: DockviewTheme = { name: "penteos", className: "dockview-theme-penteos", colorScheme: "dark", gap: 0 };

/** A section whose title is read in the operator's language each time it is shown. */
const section = (id: EditorPanelId, icon: (s: number) => ReactNode) => ({
  get title() {
    return t(`shell.section.${id}`);
  },
  icon,
});

export const EDITOR: Record<EditorPanelId, { title: string; icon: (s: number) => ReactNode }> = {
  home: section("home", (s) => <House size={s} />),
  services: section("services", (s) => <Radar size={s} />),
  hosts: section("hosts", (s) => <Server size={s} />),
  domains: section("domains", (s) => <Globe size={s} />),
  findings: section("findings", (s) => <Bug size={s} />),
  scope: section("scope", (s) => <ShieldCheck size={s} />),
  tools: section("tools", (s) => <Wrench size={s} />),
  report: section("report", (s) => <FileText size={s} />),
  team: section("team", (s) => <Users size={s} />),
  identities: section("identities", (s) => <Route size={s} />),
  secrets: section("secrets", (s) => <KeyRound size={s} />),
  web: section("web", (s) => <AppWindow size={s} />),
  proxy: section("proxy", (s) => <Network size={s} />),
  notes: section("notes", (s) => <NotebookPen size={s} />),
  board: section("board", (s) => <KanbanSquare size={s} />),
  memory: section("memory", (s) => <Brain size={s} />),
  evolution: section("evolution", (s) => <GitCompareArrows size={s} />),
  coverage: section("coverage", (s) => <Grid3x3 size={s} />),
  metrics: section("metrics", (s) => <Activity size={s} />),
  plugins: section("plugins", (s) => <Puzzle size={s} />),
  extensions: section("extensions", (s) => <Puzzle size={s} />),
  // The seven places of the activity bar group the panels above as tabs (shell/groups.tsx).
  surface: section("surface", (s) => <Radar size={s} />),
  findingsGroup: section("findingsGroup", (s) => <Bug size={s} />),
  boardGroup: section("boardGroup", (s) => <KanbanSquare size={s} />),
  projectGroup: section("projectGroup", (s) => <Settings2 size={s} />),
  operation: section("operation", (s) => <Crosshair size={s} />),
};

export const BOTTOM: Record<BottomTab, { title: string; icon: ReactNode }> = {
  terminal: { get title() { return t("shell.bottom.terminal"); }, icon: <SquareTerminal size={13} /> },
  log: { get title() { return t("shell.bottom.log"); }, icon: <ScrollText size={13} /> },
  runs: { get title() { return t("shell.bottom.runs"); }, icon: <Play size={13} /> },
  activity: { get title() { return t("shell.bottom.activity"); }, icon: <History size={13} /> },
};

export const ICONS: Record<string, (s: number) => ReactNode> = {
  ...Object.fromEntries(Object.entries(EDITOR).map(([k, v]) => [k, v.icon])),
  entity: (s) => <Crosshair size={s} />,
  run: (s) => <Play size={s} />,
  doc: (s) => <FileText size={s} />,
  finding: (s) => <Bug size={s} />,
  request: (s) => <Send size={s} />,
  fuzzer: (s) => <Zap size={s} />,
  wsrepeater: (s) => <PlugZap size={s} />,
  pluginPanel: (s) => <Puzzle size={s} />,
};

// v3: the activity bar groups panels into seven sections; older layouts open the old panels loose.
export const LAYOUT_KEY = "penteos.layout.v3";
export const SIZES_KEY = "penteos.sizes.v1";

export const components: Record<string, React.FunctionComponent<IDockviewPanelProps<any>>> = {
  home: () => <ErrorBoundary area="home"><HomePanel /></ErrorBoundary>,
  services: () => <ErrorBoundary area="services"><ServicesPanel /></ErrorBoundary>,
  hosts: () => <ErrorBoundary area="hosts"><HostsPanel /></ErrorBoundary>,
  domains: () => <ErrorBoundary area="domains"><DomainsPanel /></ErrorBoundary>,
  findings: (p) => <ErrorBoundary area="findings"><FindingsPanel params={p.params} /></ErrorBoundary>,
  scope: () => <ErrorBoundary area="scope"><ScopePanel /></ErrorBoundary>,
  tools: () => <ErrorBoundary area="tools"><ToolsPanel /></ErrorBoundary>,
  entity: (p) => <ErrorBoundary area="entity"><EntityDetailPanel params={p.params} /></ErrorBoundary>,
  run: (p) => <ErrorBoundary area="run"><RunDetailPanel params={p.params} /></ErrorBoundary>,
  doc: (p) => <ErrorBoundary area="doc"><DocPanel params={p.params} /></ErrorBoundary>,
  finding: (p) => <ErrorBoundary area="finding"><FindingDetailPanel params={p.params} /></ErrorBoundary>,
  report: () => <ErrorBoundary area="report"><ReportPanel /></ErrorBoundary>,
  team: () => <ErrorBoundary area="team"><TeamPanel /></ErrorBoundary>,
  identities: () => <ErrorBoundary area="identities"><IdentitiesPanel /></ErrorBoundary>,
  secrets: () => <ErrorBoundary area="secrets"><SecretsPanel /></ErrorBoundary>,
  web: () => <ErrorBoundary area="web"><WebPanel /></ErrorBoundary>,
  proxy: () => <ErrorBoundary area="proxy"><ProxyPanel /></ErrorBoundary>,
  notes: () => <ErrorBoundary area="notes"><NotesPanel /></ErrorBoundary>,
  board: () => <ErrorBoundary area="board"><BoardPanel /></ErrorBoundary>,
  memory: () => <ErrorBoundary area="memory"><MemoryPanel /></ErrorBoundary>,
  request: (p) => <ErrorBoundary area="request"><RequestEditorPanel params={p.params} /></ErrorBoundary>,
  fuzzer: (p) => <ErrorBoundary area="fuzzer"><FuzzerPanel params={p.params} /></ErrorBoundary>,
  wsrepeater: (p) => <ErrorBoundary area="wsrepeater"><WsRepeaterPanel params={p.params} /></ErrorBoundary>,
  evolution: () => <ErrorBoundary area="evolution"><EvolutionPanel /></ErrorBoundary>,
  coverage: () => <ErrorBoundary area="coverage"><CoveragePanel /></ErrorBoundary>,
  metrics: () => <ErrorBoundary area="metrics"><MetricsPanel /></ErrorBoundary>,
  pluginPanel: (p) => <ErrorBoundary area="plugin-panel"><PluginPanelTab params={p.params} /></ErrorBoundary>,
  plugins: () => <ErrorBoundary area="plugins"><PluginsPanel /></ErrorBoundary>,
  extensions: () => <ErrorBoundary area="extensions"><PluginHubPanel /></ErrorBoundary>,
};

/** A panel inside its group: the same component, given the group's parameters (e.g. a finding to prefill). */
type Inner = React.FunctionComponent<{ params: unknown }>;
const inner = (id: EditorPanelId, params: Record<string, unknown>) => createElement(components[id] as Inner, { key: id, params });
for (const g of ["surface", "findingsGroup", "boardGroup", "projectGroup", "operation"] as GroupId[]) components[g] = groupComponent(g, inner);

export function Tab(props: IDockviewPanelHeaderProps<{ icon?: string }>) {
  const [title, setTitle] = useState(props.api.title);
  useEffect(() => {
    const d = props.api.onDidTitleChange((e) => setTitle(e.title));
    return () => d.dispose();
  }, [props.api]);
  const icon = ICONS[props.params?.icon ?? props.api.id];
  return (
    <div className="tab">
      {icon?.(13)}
      <span>{title}</span>
      <button className="tab-close" onMouseDown={(e) => e.stopPropagation()} onClick={() => props.api.close()}>
        <X size={12} />
      </button>
    </div>
  );
}


export interface Sizes {
  bottom: number;
  agent: number;
  bottomOpen: boolean;
  agentOpen: boolean;
}

export function loadSizes(): Sizes {
  // The bottom panel opens by itself with the first execution; the content gets the screen until then.
  const fallback = { bottom: 220, agent: 360, bottomOpen: false, agentOpen: true };
  try {
    return { ...fallback, ...(JSON.parse(localStorage.getItem(SIZES_KEY) ?? "{}") as Partial<Sizes>) };
  } catch {
    return fallback;
  }
}
