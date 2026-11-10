import { Command } from "cmdk";
import { Bug, Network, House, OctagonX, Plus, Puzzle, Radar, ShieldCheck } from "../ui/icons";
import { openPluginOperation, ptext, usePluginCatalog } from "../ui/plugins";
import { useState } from "react";
import type { CoreClient } from "../client";
import { importFile } from "../ui/importFile";
import { ProjectWizard } from "../ProjectWizard";
import { openProjectBrowser } from "../panels/Proxy";
import { type BottomTab, type EditorPanelId, useApp } from "../state";
import { toast } from "../ui/bits";
import { t } from "../i18n";

import { BOTTOM, EDITOR, LAYOUT_KEY, SIZES_KEY } from "./registry";
// ---------------------------------------------------------------------------------------------
// Palette and modals
// ---------------------------------------------------------------------------------------------

export function Palette(props: { onClose: () => void; onStop: () => void; onNew: () => void }) {
  const { workbench, client, engagement } = useApp();
  const [search, setSearch] = useState("");
  const pluginOps = usePluginCatalog().plugins.filter((p) => p.enabled).flatMap((p) => p.operations.filter((o) => o.actors.includes("human")).map((o) => ({ p, o })));
  const target = search.trim();
  const looksLikeTarget = /^[\w.-]+\.[a-z]{2,}(:\d+)?$|^\d{1,3}(\.\d{1,3}){3}(\/\d+|:\d+)?$|^https?:\/\//i.test(target);
  const go = (fn: () => void) => {
    props.onClose();
    fn();
  };
  async function scan(preset: string) {
    try {
      const r = await client.call<{ runId?: string }>("tool.run", { tool: "nmap", preset, targets: [target] });
      if (r.runId) workbench.openRun(r.runId);
    } catch (e) {
      toast("bad", t("shell.palette.blocked"), (e as Error).message);
    }
  }
  async function check() {
    const d = await client.call<{ decision: string; reason?: string }>("scope.check", { target, risk: "active" }).catch((e: Error) => ({ decision: "deny", reason: e.message }));
    toast(d.decision === "allow" ? "ok" : "bad", d.decision === "allow" ? t("shell.palette.inScope", { target }) : d.decision === "ask" ? t("shell.palette.needsApproval", { target }) : t("shell.palette.denied", { target }), d.reason);
  }
  return (
    <div className="overlay" onMouseDown={(e) => e.target === e.currentTarget && props.onClose()}>
      <Command label={t("shell.palette.label")} loop>
        <Command.Input autoFocus placeholder={t("shell.palette.placeholder")} value={search} onValueChange={setSearch} onKeyDown={(e) => e.key === "Escape" && props.onClose()} />
        <Command.List>
          <Command.Empty>{t("shell.palette.empty")}</Command.Empty>
          {looksLikeTarget ? (
            <Command.Group heading={t("shell.palette.target", { target })}>
              <Command.Item value={`a scan ${target}`} onSelect={() => go(() => scan("quick"))}><Radar size={14} /> {t("shell.palette.scanQuick")}</Command.Item>
              <Command.Item value={`b scan full ${target}`} onSelect={() => go(() => scan("full"))}><Radar size={14} /> {t("shell.palette.scanFull")}</Command.Item>
              <Command.Item value={`c check ${target}`} onSelect={() => go(check)}><ShieldCheck size={14} /> {t("shell.palette.check")}</Command.Item>
            </Command.Group>
          ) : null}
          <Command.Group heading={t("shell.palette.goTo")}>
            {(Object.keys(EDITOR) as EditorPanelId[]).map((id) => (
              <Command.Item key={id} value={`ir go ${EDITOR[id].title}`} onSelect={() => go(() => workbench.openPanel(id))}>
                {EDITOR[id].icon(14)} {EDITOR[id].title}
              </Command.Item>
            ))}
            {(Object.keys(BOTTOM) as BottomTab[]).map((id) => (
              <Command.Item key={id} value={`ir go ${BOTTOM[id].title}`} onSelect={() => go(() => workbench.openPanel(id))}>
                {BOTTOM[id].icon} {BOTTOM[id].title}
              </Command.Item>
            ))}
          </Command.Group>
          {pluginOps.length ? (
            <Command.Group heading={t("plugins.palette.group")}>
              {pluginOps.map(({ p, o }) => (
                <Command.Item key={o.name} value={`plugin ${p.name} ${ptext(o.title)}`} onSelect={() => go(() => openPluginOperation(p, o))}>
                  <Puzzle size={14} /> {p.name} · {ptext(o.title)}
                </Command.Item>
              ))}
            </Command.Group>
          ) : null}
          <Command.Group heading={t("shell.palette.actions")}>
            <Command.Item value={`nuevo proyecto engagement ${t("shell.palette.newProject")}`} onSelect={() => go(props.onNew)}><Plus size={14} /> {t("shell.palette.newProject")}</Command.Item>
            <Command.Item value={`importar resultados nmap bloodhound ${t("shell.palette.import")}`} onSelect={() => go(() => void importFile(client))}>
              <Radar size={14} /> {t("shell.palette.import")}
            </Command.Item>
            <Command.Item value={`nuevo hallazgo ${t("shell.project.newFinding")}`} onSelect={() => go(() => workbench.newFinding())}><Bug size={14} /> {t("shell.project.newFinding")}</Command.Item>
            <Command.Item value={`abrir navegador del proyecto proxy ${t("shell.project.browser")}`} onSelect={() => go(() => void openProjectBrowser(client, engagement))}><Network size={14} /> {t("shell.project.browser")}</Command.Item>
            <Command.Item value={`stop work detener frenar ${t("shell.palette.stopWork")}`} onSelect={() => go(props.onStop)}><OctagonX size={14} /> {t("shell.palette.stopWork")}</Command.Item>
            <Command.Item value={`restablecer layout paneles ${t("shell.palette.resetLayout")}`} onSelect={() => go(() => { localStorage.removeItem(LAYOUT_KEY); localStorage.removeItem(SIZES_KEY); location.reload(); })}>
              <House size={14} /> {t("shell.palette.resetLayout")}
            </Command.Item>
          </Command.Group>
        </Command.List>
      </Command>
    </div>
  );
}

