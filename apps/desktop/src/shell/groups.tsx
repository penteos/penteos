/**
 * The sections of the activity bar: seven places instead of fifteen.
 * Each groups panels that are the same thing seen from different angles - hosts, services and
 * domains are one inventory; notes and memory are what the team knows - as tabs. Every panel still
 * exists and every old way in still works: opening "hosts" opens Superficie on its Hosts tab.
 */
import { useEffect, useState } from "react";
import type { IDockviewPanelProps } from "dockview-react";
import type { EditorPanelId } from "../state";
import { t } from "../i18n";

export type GroupId = "surface" | "findingsGroup" | "boardGroup" | "projectGroup" | "operation";

/** Which group each panel lives in, and in what order its tabs appear. Panels not listed stand alone. */
export const GROUPS: Record<GroupId, EditorPanelId[]> = {
  surface: ["web", "hosts", "services", "domains", "evolution"],
  findingsGroup: ["findings", "coverage"],
  boardGroup: ["board", "notes", "memory"],
  projectGroup: ["scope", "secrets", "tools", "metrics", "plugins"],
  operation: ["identities"],
};

export const groupOf = (id: EditorPanelId): GroupId | undefined => (Object.keys(GROUPS) as GroupId[]).find((g) => GROUPS[g].includes(id));

/** The tabs a group shows in this mode: only its panels the mode uses (all of them with "show all"). */
export function tabsFor(group: GroupId, visible: EditorPanelId[] | "all"): EditorPanelId[] {
  const tabs = GROUPS[group].filter((id) => visible === "all" || visible.includes(id) || (group === "projectGroup" && (id === "scope" || id === "tools" || id === "metrics" || id === "plugins")));
  return tabs.length ? tabs : GROUPS[group].slice(0, 1);
}

let visibleNow: EditorPanelId[] | "all" = "all";
/** The shell tells the groups which panels the current mode shows. */
export function setVisiblePanels(v: EditorPanelId[] | "all"): void {
  visibleNow = v;
  window.dispatchEvent(new Event("penteos:visible-panels"));
}

export function GroupPanel(props: {
  group: GroupId;
  params: { tab?: EditorPanelId; at?: number } & Record<string, unknown>;
  render: (id: EditorPanelId, params: Record<string, unknown>) => React.ReactNode;
}) {
  const [visible, setVisible] = useState(visibleNow);
  useEffect(() => {
    const on = () => setVisible(visibleNow);
    window.addEventListener("penteos:visible-panels", on);
    return () => window.removeEventListener("penteos:visible-panels", on);
  }, []);
  const tabs = tabsFor(props.group, visible);
  const [tab, setTab] = useState<EditorPanelId>(props.params.tab && tabs.includes(props.params.tab) ? props.params.tab : tabs[0]!);
  // Opening the group again on a given tab (from a link, the palette, a card) switches to it.
  useEffect(() => {
    if (props.params.tab && tabs.includes(props.params.tab)) setTab(props.params.tab);
  }, [props.params.tab, props.params.at]);
  const current = tabs.includes(tab) ? tab : tabs[0]!;
  return (
    <div className="group-panel">
      {tabs.length > 1 ? (
        <div className="group-tabs" role="tablist">
          {tabs.map((id) => (
            <button key={id} role="tab" aria-selected={id === current} className={`group-tab ${id === current ? "on" : ""}`} onClick={() => setTab(id)}>
              {t(`shell.section.${id}`)}
            </button>
          ))}
        </div>
      ) : null}
      <div className="group-body">
        {/* Only the current tab is mounted: each panel loads its own data when shown. */}
        {props.render(current, props.params)}
      </div>
    </div>
  );
}

type Render = (id: EditorPanelId, params: Record<string, unknown>) => React.ReactNode;
type DockPanel = React.FunctionComponent<IDockviewPanelProps<any>>;

export function groupComponent(group: GroupId, render: Render): DockPanel {
  return (p) => <GroupPanel group={group} params={(p.params ?? {}) as never} render={render} />;
}
