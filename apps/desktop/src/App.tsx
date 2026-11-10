import { type DockviewApi, DockviewReact } from "dockview-react";
import { OctagonX, X } from "./ui/icons";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { CoreClient } from "./client";
import { AgentSidebar } from "./panels/AgentSidebar";
import { ErrorBoundary } from "./ui/ErrorBoundary";
import { importFile } from "./ui/importFile";
import { ModePicker, ProjectWizard } from "./ProjectWizard";
import { ALL_SECTIONS, loadShowAll, modeOf, saveShowAll } from "./modes";
import { type Menu } from "./ui/MenuBar";
import { openProjectBrowser } from "./panels/Proxy";
import { AppProvider, type BottomTab, type EditorPanelId, useApp, type Workbench } from "./state";
import { AiLevelPicker, LEVELS } from "./ProjectWizard";
import { toast, Toasts } from "./ui/bits";
import { PluginNotices } from "./ui/PluginNotices";
import { openPluginMenu, PluginAlerts, PluginRunHost, ptext, usePluginCatalog, usePluginNotifications } from "./ui/plugins";
import { startBrowseBridge } from "./browse";
import { lang, LANGS, setLang, t, tn, type Lang } from "./i18n";

import { TopBar, ActivityBar, StatusBar, BottomPanel, type EngagementSummary } from "./shell/Bars";
import { GROUPS, type GroupId, groupOf, setVisiblePanels } from "./shell/groups";
import { Palette } from "./shell/Palette";
import { revealProjectFolder } from "./ui/files";
import { HelpModal, StopWorkModal } from "./shell/Modals";
import { BOTTOM, components, EDITOR, LAYOUT_KEY, loadSizes, SIZES_KEY, type Sizes, Tab, theme } from "./shell/registry";
// ---------------------------------------------------------------------------------------------
// Resizable regions
// ---------------------------------------------------------------------------------------------


function Sash(props: { axis: "x" | "y"; onDrag: (delta: number) => void }) {
  const [dragging, setDragging] = useState(false);
  return (
    <div
      className={`${props.axis === "x" ? "sash-v" : "sash-h"} ${dragging ? "dragging" : ""}`}
      onPointerDown={(e) => {
        e.preventDefault();
        (e.target as HTMLElement).setPointerCapture(e.pointerId);
        setDragging(true);
        let last = props.axis === "x" ? e.clientX : e.clientY;
        const move = (ev: PointerEvent) => {
          const now = props.axis === "x" ? ev.clientX : ev.clientY;
          props.onDrag(now - last);
          last = now;
        };
        const up = () => {
          setDragging(false);
          window.removeEventListener("pointermove", move);
          window.removeEventListener("pointerup", up);
        };
        window.addEventListener("pointermove", move);
        window.addEventListener("pointerup", up);
      }}
    />
  );
}

// ---------------------------------------------------------------------------------------------
// Workbench
// ---------------------------------------------------------------------------------------------

function makeWorkbench(
  getApi: () => DockviewApi | undefined,
  showBottom: (t: BottomTab) => void,
  openPalette: () => void,
): Workbench {
  function place(id: string, component: string, title: string, params: Record<string, unknown>) {
    const api = getApi();
    if (!api) return;
    const existing = api.getPanel(id);
    if (existing) {
      existing.api.updateParameters(params);
      existing.api.setActive();
      return;
    }
    const reference = api.activePanel ?? api.panels[0];
    api.addPanel({ id, component, title, params, ...(reference ? { position: { referencePanel: reference.id, direction: "within" as const } } : {}) });
  }
  return {
    openPanel: (id) => {
      if (id in BOTTOM) return showBottom(id as BottomTab);
      // A group id (the activity bar) opens the group on its PRIMARY tab, resetting it: clicking
      // "Findings" always lands on Findings, not on the last sub-tab (Coverage) you had open.
      if (id in GROUPS) {
        const g = id as GroupId;
        return place(g, g, EDITOR[g].title, { icon: g, tab: GROUPS[g][0], at: Date.now() });
      }
      // A panel that lives in a group (a link, a card, the palette) opens its group on THAT tab.
      const group = groupOf(id as EditorPanelId);
      if (group) place(group, group, EDITOR[group].title, { icon: group, tab: id, at: Date.now() });
      else place(id, id, EDITOR[id as EditorPanelId].title, { icon: id });
    },
    openEntity: (id, title) => place(`entity:${id}`, "entity", title, { id, icon: "entity" }),
    openRun: (id) => place(`run:${id}`, "run", t("shell.tab.run", { id: id.slice(-6) }), { runId: id, icon: "run" }),
    openFinding: (id, title) => place(`finding:${id}`, "finding", title.length > 32 ? `${title.slice(0, 32)}…` : title, { id, icon: "finding" }),
    openDoc: (title, markdown) => place(`doc:${Date.now()}`, "doc", title, { markdown, icon: "doc" }),
    newFinding: (prefill) => place("findingsGroup", "findingsGroup", EDITOR.findingsGroup.title, { icon: "findingsGroup", tab: "findings", at: Date.now(), ...(prefill ? { prefill } : {}) }),
    openPalette,
    closeActive: () => getApi()?.activePanel?.api.close(),
    openPluginPanel: (pluginId, panelId, title) => place(`plugin-panel:${pluginId}:${panelId}`, "pluginPanel", title, { pluginId, panelId, icon: "pluginPanel" }),
    openWsRepeater: (params) => place(`wsrepeater:${Date.now()}`, "wsrepeater", `WS ${(() => { try { return new URL(params.url).host; } catch { return ""; } })()}`, { ...params, icon: "wsrepeater" }),
    openFuzzer: (params) => place(`fuzzer:${Date.now()}`, "fuzzer", `Fuzzer ${(() => { try { return new URL(params.origin).host; } catch { return ""; } })()}`, { ...params, icon: "fuzzer" }),
    openRequest: (params) => place(`request:${Date.now()}`, "request", `${params.raw.split(" ")[0] ?? "GET"} ${(() => { try { return new URL(params.origin).host; } catch { return t("shell.tab.request"); } })()}`, { ...params, icon: "request" }),
  };
}

function Shell(props: {
  onReady: (api: DockviewApi) => void;
  active?: string;
  palette: boolean;
  setPalette: (v: boolean) => void;
  sizes: Sizes;
  setSizes: (fn: (s: Sizes) => Sizes) => void;
  bottomTab: BottomTab;
  setBottomTab: (t: BottomTab) => void;
  ask?: string;
  onAskConsumed: () => void;
}) {
  const { engagement, client, workbench, connected, teamMode, refreshEngagement } = useApp();
  const [stopModal, setStopModal] = useState(false);
  const [wizard, setWizard] = useState<"first" | "new">();
  const [modePicker, setModePicker] = useState(false);
  const [levelPicker, setLevelPicker] = useState(false);
  useEffect(() => {
    const open = () => setLevelPicker(true);
    window.addEventListener("penteos:ai-level", open);
    return () => window.removeEventListener("penteos:ai-level", open);
  }, []);
  const [help, setHelp] = useState<"modes" | "keys" | "about">();
  const [showAll, setShowAllState] = useState(loadShowAll);
  const [workStyle, setWorkStyle] = useState<string>();
  const [recent, setRecent] = useState<EngagementSummary[]>([]);
  const { sizes, setSizes } = props;
  const toggle = (k: "bottomOpen" | "agentOpen") => setSizes((s) => ({ ...s, [k]: !s[k] }));
  const setShowAll = (v: boolean) => {
    saveShowAll(v);
    setShowAllState(v);
  };

  // First run: the assistant instead of an empty workspace.
  useEffect(() => {
    if (!connected) return;
    client
      .call<{ onboarded: boolean; workStyle?: string; language?: Lang; languageSet?: boolean }>("workspace.prefs")
      .then((p) => {
        setWorkStyle(p.workStyle);
        // The operator's language lives in the core (the Maestro answers in it); this window follows it.
        if (p.languageSet && p.language && p.language !== lang()) setLang(p.language);
        else if (!p.languageSet) void client.call("operator.set_language", { language: lang() }).catch(() => undefined);
        // Keep the desktop's copy in step too (its start-up dialogs speak before this window loads).
        void window.penteosDesktop?.setLanguage?.(p.languageSet && p.language ? p.language : lang())?.catch(() => undefined);
        if (!p.onboarded) setWizard("first");
      })
      .catch(() => undefined);
  }, [connected, client, wizard]);

  async function changeLanguage(next: Lang) {
    if (next === lang()) return;
    try {
      await client.call("operator.set_language", { language: next });
    } catch (e) {
      toast("bad", t("common.error"), (e as Error).message);
      return;
    }
    setLang(next);
  }

  /**
   * The deliverable's language: what agents write from now on. What is already written stays as it
   * is; when there is some, the operator can ask the Maestro to rewrite it, so the report is not
   * left half in each language (through the usual operations: audited, and reviewable as always).
   */
  async function changeDeliverableLanguage() {
    if (!engagement) return;
    const next = engagement.language === "es" ? "en" : "es";
    const name = t(`labels.lang.${next}`);
    if (!window.confirm(t("shell.project.deliverableLanguage.confirm", { name }))) return;
    try {
      await client.call("engagement.update", { language: next });
      refreshEngagement();
      toast("ok", t("shell.project.deliverableLanguage.done", { name }));
    } catch (e) {
      toast("bad", t("common.error"), (e as Error).message);
      return;
    }
    const written = (engagement.counts.finding ?? 0) + (engagement.counts.task ?? 0);
    if (written > 0 && window.confirm(t("shell.project.deliverableLanguage.translate", { name }))) {
      window.dispatchEvent(new CustomEvent("penteos:ask-maestro", { detail: t("shell.project.deliverableLanguage.translatePrompt", { name }) }));
    }
  }

  const mode = modeOf(engagement?.mode);
  // A retest or a monitoring round compares against the previous one: it gets Evolution too.
  const comparing = engagement?.roundMode === "retest" || engagement?.roundMode === "continuous";
  const modeSections = comparing && !mode.sections.includes("evolution") ? [...mode.sections, "evolution" as const] : mode.sections;
  const sections = showAll ? ALL_SECTIONS : modeSections;
  // Groups show only the tabs this mode uses.
  useEffect(() => setVisiblePanels(showAll ? "all" : modeSections), [showAll, mode.id, comparing]);
  const bottomTabs: BottomTab[] = showAll ? ["terminal", "log", "runs", "activity"] : mode.bottom;
  // The Team panel holds the agents too: anyone with AI in the project gets it.
  const showTeam = workStyle === "team" || teamMode || client.remote || engagement !== undefined;
  useEffect(() => {
    if (!bottomTabs.includes(props.bottomTab)) props.setBottomTab("terminal");
  }, [bottomTabs, props]);

  const openBottom = (t: BottomTab) => {
    setSizes((s) => ({ ...s, bottomOpen: true }));
    props.setBottomTab(t);
  };
  // The first run of the session in each project (usually the Maestro starting to work) brings up
  // the Executions tab, even if the panel was closed or on another tab. Only once: after that the
  // operator decides where the panel stays.
  const runsShown = useRef(new Set<string>());
  // Browsing requests: live progress in the browser's note, and "Done" pressed there.
  useEffect(() => startBrowseBridge(client, (id) => workbench.openPanel(id)), [client, workbench]);
  // "Show output" on a running tool in the conversation.
  useEffect(() => {
    const open = () => openBottom("runs");
    window.addEventListener("penteos:open-runs", open);
    return () => window.removeEventListener("penteos:open-runs", open);
  });
  useEffect(
    () =>
      client.onEvent((e) => {
        if (e.type !== "run.started" || !engagement || runsShown.current.has(engagement.id)) return;
        runsShown.current.add(engagement.id);
        openBottom("runs");
      }),
    [client, engagement?.id],
  );
  async function retest() {
    if (!engagement) return;
    try {
      const r = await client.call<{ id: string; findingsToVerify: number }>("engagement.retest", { sourceEngagementId: engagement.id });
      client.activate(r.id);
      toast("ok", t("shell.retest.created"), tn("shell.retest.toVerify", r.findingsToVerify));
    } catch (e) {
      toast("bad", t("shell.retest.failed"), (e as Error).message);
    }
  }
  async function snapshot() {
    await client.call("snapshot.create", { label: `manual ${new Date().toLocaleDateString()}` }).catch(() => undefined);
    toast("ok", t("shell.snapshot.saved"), t("shell.snapshot.where"));
  }
  async function exportProject() {
    if (!engagement) return;
    const safe = `${engagement.clientName}-${engagement.name}`.replace(/[^\p{L}\p{N}._-]+/gu, "-");
    const dest = await window.penteosDesktop?.exportProject?.(`${safe}.penteos`);
    if (!dest) return; // cancelled, or not available (web/team mode)
    try {
      const r = await client.call<{ secretsStripped: number }>("project.export", { engagementId: engagement.id, dest });
      toast("ok", t("shell.export.done"), r.secretsStripped > 0 ? tn("shell.export.secretsStripped", r.secretsStripped) : t("shell.export.where"));
    } catch (e) {
      toast("bad", t("shell.export.failed"), (e as Error).message);
    }
  }
  async function importProject() {
    const src = await window.penteosDesktop?.importProject?.();
    if (!src) return;
    try {
      const r = await client.call<{ id: string; name: string }>("project.import", { src });
      client.activate(r.id);
      toast("ok", t("shell.import.done"), t("shell.import.secretsHint"));
    } catch (e) {
      toast("bad", t("shell.import.failed"), (e as Error).message);
    }
  }
  async function openProject() {
    const dir = await window.penteosDesktop?.openProjectDialog?.();
    if (!dir) return;
    try {
      const r = await client.call<{ id: string }>("project.open", { dir });
      client.activate(r.id);
    } catch (e) {
      toast("bad", t("shell.open.failed"), (e as Error).message);
    }
  }
  async function relocateProject() {
    if (!engagement) return;
    const dir = await window.penteosDesktop?.chooseProjectsRoot?.();
    if (!dir) return;
    try {
      const r = await client.call<{ dir: string }>("project.relocate", { engagementId: engagement.id, dir });
      client.activate(engagement.id); // reopen at the new location
      toast("ok", t("shell.relocate.done"), r.dir);
    } catch (e) {
      toast("bad", t("shell.relocate.failed"), (e as Error).message);
    }
  }
  async function changeProjectsRoot() {
    const dir = await window.penteosDesktop?.chooseProjectsRoot?.();
    if (!dir) return;
    try {
      await client.call("workspace.set_prefs", { projectsRoot: dir });
      toast("ok", t("shell.root.changed"), dir);
    } catch (e) {
      toast("bad", t("shell.root.failed"), (e as Error).message);
    }
  }

  const loadRecent = () =>
    client.call<{ engagements: EngagementSummary[] }>("engagement.list").then((r) => setRecent(r.engagements.slice(0, 8))).catch(() => undefined);
  useEffect(() => {
    if (connected) void loadRecent();
  }, [connected, engagement?.id]);
  // Solo mode: new projects go to a visible ~/Penteos by default, not the buried data dir.
  useEffect(() => {
    if (!connected || teamMode) return;
    void (async () => {
      const prefs = await client.call<{ projectsRoot?: string }>("workspace.prefs", {}).catch(() => null);
      if (!prefs || prefs.projectsRoot) return;
      const info = await window.penteosDesktop?.projectDir?.();
      if (info?.home) await client.call("workspace.set_prefs", { projectsRoot: `${info.home}/Penteos` }).catch(() => undefined);
    })();
  }, [connected, teamMode]);
  // A project whose folder was moved or deleted: say so instead of switching to nothing.
  useEffect(() => {
    const onFail = (e: Event) => {
      const dir = (e as CustomEvent<{ dir?: string }>).detail?.dir ?? "";
      toast("bad", t("shell.open.missingTitle"), t("shell.open.missingBody", { dir }));
    };
    window.addEventListener("penteos:activate-failed", onFail);
    return () => window.removeEventListener("penteos:activate-failed", onFail);
  }, []);

  // Plugins enabled in this project add their entries to the Plugins menu (and the palette).
  const pluginOffers = usePluginCatalog().plugins;
  usePluginNotifications();
  const pluginItems = pluginOffers
    .filter((p) => p.enabled)
    .flatMap((p) => [
      ...p.menus.filter((m) => m.where === "plugins").map((m) => ({ label: `${p.name} · ${ptext(m.title)}`, onClick: () => void openPluginMenu(client, p, m) })),
      ...(p.panels ?? []).filter((x) => x.where === "plugins").map((x) => ({ label: `${p.name} · ${ptext(x.title)}`, onClick: () => workbench.openPluginPanel(p.id, x.id, ptext(x.title)) })),
    ]);

  // Five menus, no duplicates: the activity bar is the way to the sections, the emergency button
  // holds pause and stop-work, and clipboard shortcuts work without an Edit menu.
  const menus: Menu[] = [
    {
      label: t("shell.menu.file"),
      items: [
        { label: t("shell.file.newProject"), shortcut: "Ctrl+N", onClick: () => setWizard("new") },
        { label: t("shell.file.open"), shortcut: "Ctrl+O", disabled: teamMode, onClick: () => void openProject() },
        { header: t("shell.file.recent") },
        ...recent.map((e) => ({ label: e.missing ? t("shell.file.recentMissing", { client: e.clientName, name: e.name }) : `${e.clientName} / ${e.name}`, checked: e.id === engagement?.id, disabled: e.missing, onClick: () => client.activate(e.id) })),
        "sep",
        { label: t("shell.file.import"), onClick: () => void importFile(client) },
        { label: t("shell.file.retest"), onClick: () => void retest(), disabled: !engagement },
        "sep",
        { header: t("shell.file.onDisk") },
        { label: t("shell.file.reveal"), disabled: !engagement || teamMode, onClick: () => void revealProjectFolder(client, engagement!.id) },
        { label: t("shell.file.relocate"), disabled: !engagement || teamMode, onClick: () => void relocateProject() },
        { label: t("shell.file.projectsRoot"), disabled: teamMode, onClick: () => void changeProjectsRoot() },
        { label: t("shell.file.export"), disabled: !engagement || teamMode, onClick: () => void exportProject() },
        { label: t("shell.file.importProject"), disabled: teamMode, onClick: () => void importProject() },
        "sep",
        { label: t("shell.file.closeTab"), shortcut: "Ctrl+W", onClick: () => workbench.closeActive() },
        { label: t("shell.file.quit"), shortcut: "Ctrl+Q", onClick: () => window.close() },
      ],
    },
    {
      label: t("shell.menu.view"),
      items: [
        { label: t("shell.view.palette"), shortcut: "Ctrl+K", onClick: () => props.setPalette(true) },
        "sep",
        { label: t("shell.view.agent"), shortcut: "Ctrl+L", checked: sizes.agentOpen, onClick: () => toggle("agentOpen") },
        { label: t("shell.view.bottomPanel"), shortcut: "Ctrl+J", checked: sizes.bottomOpen, onClick: () => toggle("bottomOpen") },
        ...bottomTabs.map((b) => ({ label: BOTTOM[b].title, ...(b === "terminal" ? { shortcut: "Ctrl+`" } : {}), onClick: () => openBottom(b) })),
        "sep",
        { label: t("shell.view.showAll"), checked: showAll, onClick: () => setShowAll(!showAll) },
        "sep",
        { header: t("shell.view.language") },
        ...LANGS.map((l) => ({ label: l.name, checked: lang() === l.id, onClick: () => void changeLanguage(l.id) })),
      ],
    },
    {
      label: t("shell.menu.project"),
      items: [
        { header: t("shell.project.actions") },
        { label: t("shell.project.browser"), shortcut: "Ctrl+Shift+B", onClick: () => void openProjectBrowser(client, engagement) },
        { label: t("shell.project.newFinding"), onClick: () => workbench.newFinding() },
        { label: t("shell.project.snapshot"), onClick: () => void snapshot() },
        "sep",
        { header: t("shell.project.settings") },
        { label: t("shell.project.mode", { mode: mode.title }), onClick: () => setModePicker(true) },
        { label: t("shell.project.aiLevel", { level: LEVELS.find((l) => l.id === engagement?.autonomy)?.title ?? t("shell.project.aiLevelDefault") }), onClick: () => setLevelPicker(true) },
        { label: t("shell.project.deliverableLanguage", { name: t(`labels.lang.${engagement?.language ?? "en"}`) }), disabled: !engagement, onClick: () => void changeDeliverableLanguage() },
      ],
    },
    {
      label: t("shell.menu.plugins"),
      items: [
        { label: t("plugins.menu.manage"), onClick: () => workbench.openPanel("plugins") },
        "sep",
        ...(pluginItems.length ? pluginItems : [{ header: t("plugins.menu.none") }]),
      ],
    },
    {
      label: t("shell.menu.help"),
      items: [
        { label: t("shell.help.modes"), onClick: () => setHelp("modes") },
        { label: t("shell.help.keys"), onClick: () => setHelp("keys") },
        { label: t("shell.help.welcome"), onClick: () => setWizard("first") },
        "sep",
        // The way out when a plugin breaks things: restart with every plugin off.
        { label: t("shell.help.safeMode"), disabled: !window.penteosDesktop?.restart, onClick: () => void window.penteosDesktop?.restart?.({ safeMode: true }) },
        "sep",
        { label: t("shell.help.about"), onClick: () => setHelp("about") },
      ],
    },
  ];

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const mod = e.ctrlKey || e.metaKey;
      const key = e.key.toLowerCase();
      if (mod && key === "n") {
        e.preventDefault();
        setWizard("new");
      } else if (mod && !e.shiftKey && key === "o") {
        e.preventDefault();
        if (!teamMode) void openProject();
      } else if (mod && key === "w") {
        e.preventDefault();
        workbench.closeActive();
      } else if (mod && e.shiftKey && key === "b") {
        e.preventDefault();
        void openProjectBrowser(client, engagement);
      } else if (mod && key === "q") {
        e.preventDefault();
        window.close();
      }
    };
    window.addEventListener("keydown", onKey, true);
    return () => window.removeEventListener("keydown", onKey, true);
  }, [workbench, client, engagement]);

  return (
    <div className="shell">
      <TopBar onStop={() => setStopModal(true)} onNew={() => setWizard("new")} onOpen={() => void openProject()} openApprovals={() => setSizes((s) => ({ ...s, agentOpen: true }))} sizes={sizes} toggle={toggle} menus={menus} />
      <div className="workarea">
        <ActivityBar active={props.active} sections={sections} showTeam={showTeam} />
        <div className="center">
          {engagement?.stopWork?.active ? (
            <div className="stop-banner">
              <OctagonX size={15} /> {t("shell.stopBanner", { reason: engagement.stopWork.reason })}
            </div>
          ) : null}
          <div className="editor">
            <DockviewReact theme={theme} components={components} defaultTabComponent={Tab} onReady={(e) => props.onReady(e.api)} />
          </div>
          {sizes.bottomOpen ? (
            <>
              <Sash axis="y" onDrag={(d) => setSizes((s) => ({ ...s, bottom: Math.min(Math.max(s.bottom - d, 120), window.innerHeight - 220) }))} />
              <ErrorBoundary area="bottom"><BottomPanel tab={props.bottomTab} tabs={bottomTabs} setTab={props.setBottomTab} height={sizes.bottom} onClose={() => toggle("bottomOpen")} /></ErrorBoundary>
            </>
          ) : null}
        </div>
        {sizes.agentOpen ? (
          <>
            <Sash axis="x" onDrag={(d) => setSizes((s) => ({ ...s, agent: Math.min(Math.max(s.agent - d, 280), 640) }))} />
            <ErrorBoundary area="agent"><AgentSidebar width={sizes.agent} {...(props.ask ? { ask: props.ask } : {})} onAskConsumed={props.onAskConsumed} /></ErrorBoundary>
          </>
        ) : null}
      </div>
      <StatusBar bottomOpen={sizes.bottomOpen} openBottom={openBottom} openAgent={() => setSizes((s) => ({ ...s, agentOpen: true }))} />
      {props.palette ? <Palette onClose={() => props.setPalette(false)} onStop={() => setStopModal(true)} onNew={() => setWizard("new")} /> : null}
      {stopModal ? <StopWorkModal onClose={() => setStopModal(false)} /> : null}
      {wizard ? <ProjectWizard firstRun={wizard === "first"} onClose={() => setWizard(undefined)} /> : null}
      {modePicker ? <ModePicker onClose={() => setModePicker(false)} /> : null}
      {levelPicker ? <AiLevelPicker onClose={() => setLevelPicker(false)} /> : null}
      {help ? <HelpModal kind={help} onClose={() => setHelp(undefined)} /> : null}
      <PluginNotices />
      <PluginRunHost />
      <PluginAlerts />
      <Toasts />
    </div>
  );
}

export function App(props: { client: CoreClient }) {
  const apiRef = useRef<DockviewApi>(undefined);
  const [active, setActive] = useState<string>();
  const [palette, setPalette] = useState(false);
  const [sizes, setSizesState] = useState<Sizes>(loadSizes);
  const [bottomTab, setBottomTab] = useState<BottomTab>("terminal");
  const [ask, setAsk] = useState<string>();
  useEffect(() => {
    const onAsk = (e: Event) => {
      setSizesState((s) => ({ ...s, agentOpen: true }));
      setAsk((e as CustomEvent<string>).detail);
    };
    const onOpen = () => setSizesState((s) => ({ ...s, agentOpen: true }));
    window.addEventListener("penteos:ask-maestro", onAsk);
    window.addEventListener("penteos:open-agent", onOpen);
    return () => {
      window.removeEventListener("penteos:ask-maestro", onAsk);
      window.removeEventListener("penteos:open-agent", onOpen);
    };
  }, []);

  const setSizes = useCallback((fn: (s: Sizes) => Sizes) => {
    setSizesState((s) => {
      const next = fn(s);
      try {
        localStorage.setItem(SIZES_KEY, JSON.stringify(next));
      } catch {
        /* storage unavailable */
      }
      return next;
    });
  }, []);

  const workbench = useMemo(
    () =>
      makeWorkbench(
        () => apiRef.current,
        (t) => {
          setSizes((s) => ({ ...s, bottomOpen: true }));
          setBottomTab(t);
        },
        () => setPalette(true),
      ),
    [setSizes],
  );

  const onReady = useCallback(
    (api: DockviewApi) => {
      apiRef.current = api;
      let restored = false;
      try {
        const saved = localStorage.getItem(LAYOUT_KEY);
        if (saved) {
          api.fromJSON(JSON.parse(saved));
          restored = api.panels.length > 0;
        }
      } catch {
        restored = false;
      }
      if (!restored) {
        api.clear();
        api.addPanel({ id: "home", component: "home", title: EDITOR.home.title, params: { icon: "home" } });
      }
      api.onDidLayoutChange(() => {
        try {
          localStorage.setItem(LAYOUT_KEY, JSON.stringify(api.toJSON()));
        } catch {
          /* storage unavailable */
        }
      });
      api.onDidActivePanelChange((e) => setActive(e.panel?.id));
      setActive(api.activePanel?.id);
      (window as any).__penteos = { api, workbench };
    },
    [workbench],
  );

  // Switching engagement: close panels that belong to the previous one.
  useEffect(
    () =>
      props.client.onEngagementSwitch(() => {
        const api = apiRef.current;
        if (!api) return;
        // Detail tabs belong to the engagement that was open: entities, runs, findings, requests, docs.
        for (const p of [...api.panels]) if (/^(entity|run|finding|request|doc|fuzzer|wsrepeater):/.test(p.id)) p.api.close();
        workbench.openPanel("home");
      }),
    [props.client, workbench],
  );

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const mod = e.ctrlKey || e.metaKey;
      const key = e.key.toLowerCase();
      if (mod && (key === "k" || (e.shiftKey && key === "p"))) {
        e.preventDefault();
        setPalette((v) => !v);
      } else if (mod && key === "j") {
        e.preventDefault();
        setSizes((s) => ({ ...s, bottomOpen: !s.bottomOpen }));
      } else if (mod && key === "l") {
        e.preventDefault();
        setSizes((s) => ({ ...s, agentOpen: !s.agentOpen }));
      } else if (mod && e.key === "`") {
        e.preventDefault();
        workbench.openPanel("terminal");
      }
    };
    window.addEventListener("keydown", onKey, true);
    return () => window.removeEventListener("keydown", onKey, true);
  }, [workbench, setSizes]);

  return (
    <AppProvider client={props.client} workbench={workbench}>
      <Shell onReady={onReady} active={active} palette={palette} setPalette={setPalette} sizes={sizes} setSizes={setSizes} bottomTab={bottomTab} setBottomTab={setBottomTab} ask={ask} onAskConsumed={() => setAsk(undefined)} />
    </AppProvider>
  );
}
