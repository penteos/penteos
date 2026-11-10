import { RISK_ES } from "../labels";
import type { ColumnDef } from "@tanstack/react-table";
import { Check, Download, Loader2, RefreshCw, RotateCcw, SquareTerminal, Trash2, Upload, Wrench, Zap } from "../ui/icons";
import { useState } from "react";
import { useApp, useOperation } from "../state";
import { Badge, toast } from "../ui/bits";
import { DataTable } from "../ui/DataTable";
import { lang as currentLang, t as tr } from "../i18n";
import { HelpHint } from "../ui/HelpHint";
import { VulnSources } from "../ui/VulnSources";

/**
 * Tools, by the job they do: what each capability runs with on this
 * machine, what a missing tool left undone (gaps), kits per kind of test, Penteos's own tool box
 * (space, versions, going back, freeing space), and the full list of tools at the end.
 */

interface Tool {
  name: string;
  description: string;
  risk: string;
  source: "builtin" | "custom";
  installed: boolean;
  binary?: string;
  version?: string;
  mismatch?: string;
  integrated: boolean;
  install?: { method: "go" | "manual"; command: string } | { method: "catalog"; command: string; version: string; size: number };
  /** Installed by Penteos from its verified catalog. */
  managed?: boolean;
  catalog?: { version: string; size: number; license: string; homepage: string };
  /** On the system, but older than the catalog's minimum. */
  outdated?: boolean;
}

interface Capability {
  id: string;
  title: { es: string; en: string };
  risk: string;
  now: { provider: string; quality: "full" | "degraded" | "blocked" };
  providers: string[];
  fallback?: { name: string; quality: string; lacks: { es: string; en: string } };
  installable?: { tool: string; version: string; size: number };
  /** Only the system's package manager has it: installed with the password window (or by hand). */
  system?: { tool: string; command: string; password: boolean };
  /** nmap's packet capture permission (SYN scans, OS detection, UDP). */
  capture?: { state: "root" | "capability" | "none"; password: boolean };
}

interface Gap {
  id: string;
  capability: string;
  severity: "degraded" | "blocked";
  tools: string[];
  targets: string[];
  text: string;
  critical: boolean;
}

interface Box {
  dir: string;
  usage: number;
  quota: number;
  autoInstall: { enabled: boolean; maxMB: number };
  tools: Array<{ name: string; version: string; size: number; license: string; homepage: string; installed?: { version: string; bytes: number; installedAt: string; lastUsedAt?: string; previous?: string }; update?: boolean }>;
}

const mb = (n: number) => (n >= 1e9 ? `${(n / 1e9).toFixed(1)} GB` : `${(n / 1e6).toFixed(n < 1e7 ? 1 : 0)} MB`);
const lang = (): "es" | "en" => (currentLang() === "en" ? "en" : "es");
/** Unused for this long, a tool counts as worth removing to free space. */
const STALE_DAYS = 60;

/** Kinds of test and the catalog tools each one uses ("all": every tool the catalog has). */
const KITS: Array<{ id: string; tools: string[] }> = [
  { id: "web", tools: ["httpx", "katana", "nuclei", "ffuf", "interactsh-client"] },
  { id: "recon", tools: ["subfinder", "dnsx", "httpx"] },
  { id: "all", tools: [] },
];

export function ToolsPanel() {
  const { client, workbench } = useApp();
  const [refresh, setRefresh] = useState(0);
  const [busy, setBusy] = useState<string>();
  const [showAll, setShowAll] = useState(false);
  const toolEvent = (e: { type: string }) => ["run.finished", "tool.installed", "gap.changed"].includes(e.type);
  const tools = useOperation<{ tools: Tool[] }>("tool.list", { refresh: refresh > 0 }, { refreshOn: toolEvent, deps: [refresh] });
  const caps = useOperation<{ capabilities: Capability[] }>("capability.list", {}, { refreshOn: toolEvent, deps: [refresh] });
  const box = useOperation<Box>("tool.toolbox", {}, { refreshOn: toolEvent, deps: [refresh] });
  const gaps = useOperation<{ gaps: Gap[] }>("gap.list", { status: "open" }, { refreshOn: toolEvent });
  // What could keep installs from working here: shown only when something fails.
  const diag = useOperation<{ checks: Array<{ id: string; ok: boolean; level: string; detail?: string }> }>("tool.diagnose", {}, { deps: [refresh] });
  const problems = (diag.data?.checks ?? []).filter((c) => !c.ok && c.id !== "password");
  const list = [...(tools.data?.tools ?? [])].sort((a, b) => Number(b.installed) - Number(a.installed) || Number(b.integrated) - Number(a.integrated) || a.name.localeCompare(b.name));
  const reload = () => setRefresh((n) => n + 1);

  /** Installs from the verified catalog, one after another; each is a run in Executions. */
  async function installAll(names: string[], key: string) {
    setBusy(key);
    try {
      let first: string | undefined;
      for (const name of names) {
        const r = await client.call<{ runId?: string; status?: string; command?: string }>("tool.install", { tool: name });
        // No desktop to ask for the password: the exact command goes to the terminal, not run.
        if (r.status === "manual_install" && r.command) {
          toTerminal(r.command);
          continue;
        }
        first ??= r.runId;
      }
      if (first) workbench.openRun(first);
      toast("info", tr("data.tools.installing", { tools: names.join(", ") }), tr("data.tools.installingBody"));
    } catch (e) {
      toast("bad", tr("data.tools.installFailed"), (e as Error).message);
    } finally {
      setBusy(undefined);
    }
  }

  /** Puts a command in the integrated terminal without running it: the operator decides. */
  function toTerminal(command: string) {
    workbench.openPanel("terminal");
    setTimeout(() => (window as unknown as { __penteosTerm?: (s: string) => void }).__penteosTerm?.(command), 200);
    toast("info", tr("data.tools.manualReady"), tr("data.tools.manualReadyBody"));
  }

  async function install(t: Tool) {
    if (!t.install) return;
    if (t.install.method === "manual") return toTerminal(t.install.command);
    await installAll([t.name], t.name);
  }

  async function grantCapture() {
    setBusy("capture");
    try {
      const r = await client.call<{ status: string; command?: string; note?: string; error?: string }>("tool.grant_capture", {});
      if (r.status === "granted") toast("ok", tr("data.tools.capture.granted"));
      else if (r.status === "manual" && r.command) toTerminal(r.command);
      else if (r.status === "dismissed") toast("info", tr("data.tools.capture.dismissed"));
      else toast("bad", tr("data.tools.capture.failed"), r.note ?? r.error);
      caps.reload();
    } catch (e) {
      toast("bad", tr("data.tools.capture.failed"), (e as Error).message);
    } finally {
      setBusy(undefined);
    }
  }

  async function act(op: "tool.remove" | "tool.rollback", tool: string) {
    setBusy(`${op}:${tool}`);
    try {
      await client.call(op, { tool });
      toast("ok", op === "tool.remove" ? tr("data.tools.removed", { tool }) : tr("data.tools.rolledBack", { tool }));
      reload();
    } catch (e) {
      toast("bad", tr("data.tools.actionFailed"), (e as Error).message);
    } finally {
      setBusy(undefined);
    }
  }

  async function acceptGap(g: Gap) {
    try {
      await client.call("gap.accept", { id: g.id, reason: tr("data.tools.gap.acceptReason") });
      gaps.reload();
    } catch (e) {
      toast("bad", tr("data.tools.actionFailed"), (e as Error).message);
    }
  }

  /** A kit for a network without internet: written here, installed there (each file checked against its catalog). */
  async function kit(kind: "export" | "import") {
    const desktop = window.penteosDesktop;
    const path = kind === "export" ? await desktop?.exportToolsKit?.(`${tr("data.tools.kit.fileName")}.penteos-tools`) : await desktop?.importToolsKit?.();
    if (!path) return;
    try {
      const r = await client.call<{ runId?: string }>(kind === "export" ? "tool.export_kit" : "tool.import_kit", kind === "export" ? { dest: path } : { file: path });
      if (r.runId) workbench.openRun(r.runId);
      toast("info", kind === "export" ? tr("data.tools.kit.exporting") : tr("data.tools.kit.importing"), tr("data.tools.installingBody"));
    } catch (e) {
      toast("bad", tr("data.tools.actionFailed"), (e as Error).message);
    }
  }

  async function setAuto(enabled: boolean) {
    try {
      await client.call("tool.set_auto_install", { enabled });
      box.reload();
    } catch (e) {
      toast("bad", tr("data.tools.actionFailed"), (e as Error).message);
    }
  }

  const b = box.data;
  /** Catalog tools of a set that this machine does not have (neither Penteos's nor the system's). */
  const missingIn = (names: string[]) => (b?.tools ?? []).filter((x) => (names.length ? names.includes(x.name) : true) && !x.installed && !list.find((t) => t.name === x.name)?.installed);
  const capsList = caps.data?.capabilities ?? [];
  const full = capsList.filter((c) => c.now.quality === "full").length;
  const stale = (b?.tools ?? []).filter((x) => x.installed && (!x.installed.lastUsedAt || Date.now() - Date.parse(x.installed.lastUsedAt) > STALE_DAYS * 864e5) && Date.now() - Date.parse(x.installed.installedAt) > STALE_DAYS * 864e5);

  const columns: Array<ColumnDef<Tool, any> & { width?: string }> = [
    {
      id: "state", header: "", width: "34px", accessorFn: (t) => (t.installed ? 2 : t.mismatch ? 1 : 0),
      cell: (c) => <span className={`dot ${c.row.original.installed ? "open" : c.row.original.mismatch ? "filtered" : "closed"}`} />,
    },
    { id: "name", header: () => tr("data.tools.col.tool"), width: "140px", accessorFn: (t) => t.name, cell: (c) => <span className="mono" style={{ color: "var(--fg-0)" }}>{c.getValue()}</span> },
    { id: "desc", header: () => tr("data.tools.col.purpose"), width: "1.6fr", accessorFn: (t) => t.description, cell: (c) => c.getValue() },
    {
      id: "status", header: () => tr("data.tools.col.status"), width: "1.2fr", accessorFn: (t) => t.version ?? "",
      cell: (c) => {
        const t = c.row.original;
        if (t.installed) {
          return (
            <span>
              {tr("data.tools.installed")}
              {t.version ? <span className="mono muted"> · {t.version}</span> : null}
              {t.managed ? <> <Badge tone="accent">{tr("data.tools.managed")}</Badge></> : null}
              {t.outdated && t.catalog ? <span style={{ color: "var(--warn)" }} title={tr("data.tools.outdatedTitle", { version: t.catalog.version })}> · {tr("data.tools.outdated")}</span> : null}
            </span>
          );
        }
        if (t.mismatch) return <span style={{ color: "var(--warn)" }} title={t.mismatch}>{tr("data.tools.mismatch")}</span>;
        if (t.catalog) return <span className="muted" title={tr("data.tools.catalogTitle")}>{tr("data.tools.notInstalled")} · {tr("data.tools.catalogReady", { size: mb(t.catalog.size) })}</span>;
        return <span className="muted">{tr("data.tools.notInstalled")}</span>;
      },
    },
    {
      id: "integrated", header: () => tr("data.tools.col.graph"), width: "110px", accessorFn: (t) => Number(t.integrated),
      cell: (c) =>
        c.row.original.integrated ? (
          <Badge tone="ok">{tr("data.tools.integrated")}</Badge>
        ) : (
          <span className="muted" title={tr("data.tools.runOnlyTitle")}>{tr("data.tools.runOnly")}</span>
        ),
    },
    { id: "risk", header: () => tr("data.tools.col.risk"), width: "100px", accessorFn: (t) => t.risk, cell: (c) => <span>{RISK_ES[c.getValue()] ?? c.getValue()}</span> },
    { id: "source", header: () => tr("data.tools.col.source"), width: "100px", accessorFn: (t) => t.source, cell: (c) => (c.getValue() === "custom" ? <Badge tone="accent">{tr("data.tools.custom")}</Badge> : <span className="muted">{tr("data.tools.builtin")}</span>) },
    {
      id: "action", header: "", width: "120px", accessorFn: (t) => t.name, enableSorting: false,
      cell: (c) => {
        const t = c.row.original;
        // A tool on the system that is too old can be replaced by the catalog's (installed alongside, in Penteos's box).
        const update = t.installed && t.outdated && t.install?.method === "catalog";
        if ((t.installed && !update) || !t.install) return null;
        const own = t.install.method === "catalog" || t.install.method === "go";
        return (
          <button className="btn sm" disabled={busy === t.name} onClick={(e) => { e.stopPropagation(); void install(t); }} title={t.install.command}>
            {own ? <Download size={12} /> : <SquareTerminal size={12} />} {update ? tr("data.tools.update") : tr("data.tools.install")}
          </button>
        );
      },
    },
  ];

  return (
    <div className="panel tools-panel">
      <div className="panel-toolbar">
        <Wrench size={14} />
        <h3>{tr("data.tools.title")}</h3>
        <span className="count">{tr("data.tools.capsCount", { full, total: capsList.length })}</span>
        <HelpHint id="tools" text={tr("data.tools.hint")} />
        <div className="grow" />
        {b ? (
          <label className="tb-auto" title={tr("data.tools.autoTitle")}>
            <input type="checkbox" checked={b.autoInstall.enabled} onChange={(e) => void setAuto(e.target.checked)} />
            {tr("data.tools.auto", { mb: b.autoInstall.maxMB })}
          </label>
        ) : null}
        <button className="btn sm ghost" onClick={reload} title={tr("data.tools.redetect")}><RefreshCw size={12} /></button>
      </div>

      <div className="tb-body">
        {problems.length ? (
          <section className="tb-diag">
            {problems.map((c) => (
              <div key={c.id} className={`tb-diag-row ${c.level}`}>
                <span className="tb-mark" />
                <span>{tr(`data.tools.diag.${c.id}`, { detail: c.detail ?? "" })}</span>
              </div>
            ))}
          </section>
        ) : null}
        {(gaps.data?.gaps ?? []).length ? (
          <section className="tb-gaps">
            <h4>{tr("data.tools.gaps.title")}</h4>
            {gaps.data!.gaps.map((g) => {
              const installable = g.tools.find((t) => missingIn([t]).length);
              return (
                <div key={g.id} className={`tb-gap ${g.severity}`}>
                  <span className="tb-mark" />
                  <div className="tb-gap-text">
                    <div>{g.text}</div>
                    <div className="muted">{g.severity === "blocked" ? tr("data.tools.gap.blocked") : tr("data.tools.gap.degraded")}{g.critical ? ` · ${tr("data.tools.gap.critical")}` : ""}</div>
                  </div>
                  {installable ? (
                    <button className="btn sm primary" disabled={!!busy} onClick={() => void installAll([installable], `gap:${g.id}`)}>
                      {busy === `gap:${g.id}` ? <Loader2 size={12} className="spin" /> : <Download size={12} />} {tr("data.tools.gap.install", { tool: installable })}
                    </button>
                  ) : null}
                  <button className="btn sm" onClick={() => void acceptGap(g)} title={tr("data.tools.gap.acceptTitle")}>{tr("data.tools.gap.accept")}</button>
                </div>
              );
            })}
          </section>
        ) : null}

        <section className="tb-kits">
          <h4>{tr("data.tools.kits.title")}</h4>
          <div className="tb-kit-row">
            {KITS.map((k) => {
              const missing = missingIn(k.tools);
              const size = missing.reduce((n, x) => n + x.size, 0);
              return (
                <button key={k.id} className="tb-kit" disabled={!missing.length || !!busy} onClick={() => void installAll(missing.map((x) => x.name), `kit:${k.id}`)}>
                  <span className="tb-kit-name">{busy === `kit:${k.id}` ? <Loader2 size={12} className="spin" /> : missing.length ? <Download size={12} /> : <Check size={12} />} {tr(`data.tools.kit.${k.id}`)}</span>
                  <span className="tb-kit-meta mono">{missing.length ? `${missing.map((x) => x.name).join(" · ")} - ${mb(size)}` : tr("data.tools.kits.ready")}</span>
                </button>
              );
            })}
          </div>
          <p className="muted tb-note">{tr("data.tools.kits.note")}</p>
        </section>

        <section className="tb-caps">
          <h4>{tr("data.tools.caps.title")}</h4>
          {capsList.map((c) => {
            const q = c.now.quality;
            const who = q === "full" ? (c.now.provider.startsWith("penteos:") ? tr("data.tools.caps.own") : c.now.provider) : q === "degraded" ? tr("data.tools.caps.ownLesser") : tr("data.tools.caps.none");
            return (
              <div key={c.id} className={`tb-cap q-${q}`}>
                <span className="tb-mark" />
                <div className="tb-cap-name">
                  <div>{c.title[lang()]}</div>
                  {q === "degraded" && c.fallback ? <div className="muted tb-lacks">{c.fallback.lacks[lang()]}</div> : null}
                  {q === "blocked" ? <div className="muted tb-lacks">{c.system ? tr("data.tools.caps.systemNote") : tr("data.tools.caps.blockedNote")}</div> : null}
                  {c.capture ? <div className="muted tb-lacks">{c.capture.state === "none" ? tr("data.tools.capture.none") : tr("data.tools.capture.ok")}</div> : null}
                </div>
                <span className="tb-cap-who mono">{who}</span>
                <span className="tb-cap-act">
                  {c.capture?.state === "none" ? (
                    <button className="btn sm" disabled={!!busy} onClick={() => void grantCapture()} title={c.capture.password ? tr("data.tools.capture.title") : tr("data.tools.capture.manualTitle")}>
                      {busy === "capture" ? <Loader2 size={12} className="spin" /> : <Zap size={12} />} {tr("data.tools.capture.grant")}
                    </button>
                  ) : null}
                  {c.system ? (
                    <button className="btn sm" disabled={!!busy} onClick={() => void installAll([c.system!.tool], `sys:${c.id}`)} title={c.system.password ? tr("data.tools.system.title", { command: c.system.command }) : tr("data.tools.system.manualTitle")}>
                      {busy === `sys:${c.id}` ? <Loader2 size={12} className="spin" /> : <SquareTerminal size={12} />} {tr("data.tools.system.install", { tool: c.system.tool })}
                    </button>
                  ) : null}
                  {c.installable ? (
                    <button className="btn sm" disabled={!!busy} onClick={() => void installAll([c.installable!.tool], `cap:${c.id}`)} title={tr("data.tools.catalogTitle")}>
                      {busy === `cap:${c.id}` ? <Loader2 size={12} className="spin" /> : <Download size={12} />} {c.installable.tool} · {mb(c.installable.size)}
                    </button>
                  ) : null}
                </span>
              </div>
            );
          })}
        </section>

        {b ? (
          <section className="tb-box">
            <div className="tb-box-head">
              <h4>{tr("data.tools.box.title")}</h4>
              <span className="muted mono" title={b.dir}>{tr("data.tools.box.usage", { used: mb(b.usage), quota: mb(b.quota) })}</span>
              <div className="tb-bar"><div style={{ width: `${Math.min(100, (b.usage / b.quota) * 100)}%` }} className={b.usage / b.quota > 0.8 ? "warn" : ""} /></div>
              <div className="grow" />
              {window.penteosDesktop?.exportToolsKit ? (
                <>
                  <button className="btn sm ghost" onClick={() => void kit("export")} title={tr("data.tools.kit.exportTitle")}><Download size={12} /> {tr("data.tools.kit.export")}</button>
                  <button className="btn sm ghost" onClick={() => void kit("import")} title={tr("data.tools.kit.importTitle")}><Upload size={12} /> {tr("data.tools.kit.import")}</button>
                </>
              ) : null}
              {stale.length ? (
                <button className="btn sm" disabled={!!busy} onClick={() => void Promise.all(stale.map((x) => act("tool.remove", x.name)))} title={tr("data.tools.box.freeTitle", { days: STALE_DAYS })}>
                  <Trash2 size={12} /> {tr("data.tools.box.free", { size: mb(stale.reduce((n, x) => n + (x.installed?.bytes ?? 0), 0)) })}
                </button>
              ) : null}
            </div>
            {b.tools.some((x) => x.installed) ? (
              <div className="tb-installed">
                {b.tools
                  .filter((x) => x.installed)
                  .map((x) => (
                    <div key={x.name} className="tb-inst">
                      <span className="mono tb-inst-name">{x.name}</span>
                      <span className="mono muted">{x.installed!.version}</span>
                      <span className="muted">{mb(x.installed!.bytes)}</span>
                      <span className="muted">{x.installed!.lastUsedAt ? tr("data.tools.box.used", { date: new Date(x.installed!.lastUsedAt).toLocaleDateString() }) : tr("data.tools.box.neverUsed")}</span>
                      <a className="muted tb-lic" href={x.homepage} target="_blank" rel="noreferrer">{x.license}</a>
                      <div className="grow" />
                      {x.update ? (
                        <button className="btn sm" disabled={!!busy} onClick={() => void installAll([x.name], `upd:${x.name}`)}><Zap size={12} /> {tr("data.tools.box.update", { version: x.version })}</button>
                      ) : null}
                      {x.installed!.previous ? (
                        <button className="btn sm ghost" disabled={!!busy} onClick={() => void act("tool.rollback", x.name)} title={tr("data.tools.box.rollbackTitle", { version: x.installed!.previous })}><RotateCcw size={12} /></button>
                      ) : null}
                      <button className="btn sm ghost" disabled={!!busy} onClick={() => void act("tool.remove", x.name)} title={tr("data.tools.box.remove")}><Trash2 size={12} /></button>
                    </div>
                  ))}
              </div>
            ) : (
              <p className="muted tb-note">{tr("data.tools.box.empty")}</p>
            )}
          </section>
        ) : null}

        <VulnSources />

        <section className="tb-all">
          <button className="btn sm ghost" onClick={() => setShowAll((v) => !v)}>{showAll ? tr("data.tools.all.hide") : tr("data.tools.all.show", { n: list.length })}</button>
          {showAll ? <DataTable data={list} columns={columns} rowKey={(t) => t.name} /> : null}
        </section>
      </div>
    </div>
  );
}
