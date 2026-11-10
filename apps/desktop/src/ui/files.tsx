import { useEffect, useState } from "react";
import type { CoreClient } from "../client";
import { t } from "../i18n";
import { relTime, toast } from "./bits";
import { BarChart3, Download, ExternalLink, FileCode2, FileText, FolderOpen, Image, Loader2, Trash2 } from "./icons";

/**
 * Files plugins make for the operator: a report, a CSV, a
 * chart. Each one can be downloaded and, in the desktop app with a local core, opened with the
 * system's program or shown in its folder.
 */

interface Work {
  (): Promise<unknown>;
}

export interface OutputFile {
  name: string;
  size: number;
  modifiedAt: string;
  type: string;
}

export function fileSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(0)} KB`;
  return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
}

/** Opens a project's real folder (wherever the operator put it) in the file manager. */
export async function revealProjectFolder(client: CoreClient, id: string): Promise<void> {
  const desktop = window.penteosDesktop;
  if (!desktop) return;
  const { dir } = await client.call<{ dir: string }>("project.dir", { id });
  await desktop.revealFile?.(dir);
}

let localCache: Promise<boolean> | undefined;
/** Whether files can be opened here: the desktop app talking to a core on this machine. */
function useLocalFiles(): boolean {
  const [local, setLocal] = useState(false);
  useEffect(() => {
    const d = window.penteosDesktop;
    if (!d?.openFile || !d.projectDir) return;
    localCache ??= d.projectDir().then((p) => !p.remote).catch(() => false);
    let live = true;
    void localCache.then((v) => live && setLocal(v));
    return () => {
      live = false;
    };
  }, []);
  return local;
}

function iconFor(f: OutputFile) {
  if (f.type.startsWith("image/")) return <Image size={14} />;
  if (/csv|tab-separated|spreadsheet/.test(f.type)) return <BarChart3 size={14} />;
  if (/json|xml|yaml|html/.test(f.type)) return <FileCode2 size={14} />;
  return <FileText size={14} />;
}

const base = (name: string) => name.split("/").pop() ?? name;

async function download(client: CoreClient, plugin: string, f: OutputFile, engagementId?: string): Promise<void> {
  const r = await client.call<{ base64: string; type: string }>("plugin.output_read", { id: plugin, name: f.name, ...(engagementId ? { engagementId } : {}) });
  const bin = atob(r.base64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  const url = URL.createObjectURL(new Blob([bytes], { type: r.type }));
  const a = document.createElement("a");
  a.href = url;
  a.download = base(f.name);
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
}

async function pathOf(client: CoreClient, plugin: string, name: string | undefined, engagementId?: string): Promise<string> {
  const r = await client.call<{ path: string }>("plugin.output_path", { id: plugin, ...(name ? { name } : {}), ...(engagementId ? { engagementId } : {}) });
  return r.path;
}

/** What a panel asks for one of its plugin's files (through window.penteos.files). */
export async function panelFile(client: CoreClient, plugin: string, action: string, name: string, engagementId?: string): Promise<void> {
  const r = await client.call<{ path: string; file: OutputFile }>("plugin.output_path", { id: plugin, name, ...(engagementId ? { engagementId } : {}) });
  const desktop = window.penteosDesktop;
  if (action === "download" || !desktop?.openFile) return download(client, plugin, r.file, engagementId);
  if (action === "open") {
    const done = await desktop.openFile(r.path);
    if (!done.ok) throw new Error(done.error ?? "this kind of file is not opened from Penteos");
    return;
  }
  if (action === "reveal") {
    await desktop.revealFile?.(r.path);
    return;
  }
  throw new Error(`unknown file action ${action}`);
}

/** The files of one plugin: download, open, show in folder and (optionally) delete each one. */
export function OutputFiles(props: { client: CoreClient; plugin: string; files: OutputFile[]; engagementId?: string; onDelete?: (f: OutputFile) => void; highlight?: boolean }) {
  const local = useLocalFiles();
  const [busy, setBusy] = useState<string | null>(null);
  async function act(key: string, work: Work) {
    setBusy(key);
    try {
      await work();
    } catch (e) {
      toast("bad", t("plugins.files.failed"), e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(null);
    }
  }
  const open = async (f: OutputFile) => {
    const r = await window.penteosDesktop!.openFile!(await pathOf(props.client, props.plugin, f.name, props.engagementId));
    if (!r.ok) toast("bad", t("plugins.files.cannotOpen"), r.error ?? t("plugins.files.cannotOpenHint"));
  };
  const reveal = async (f: OutputFile) => {
    await window.penteosDesktop!.revealFile!(await pathOf(props.client, props.plugin, f.name, props.engagementId));
  };
  if (!props.files.length) return null;
  return (
    <ul className={`plugin-files${props.highlight ? " made" : ""}`}>
      {props.files.map((f) => (
        <li key={f.name} className="plugin-file">
          <span className="plugin-file-icon">{iconFor(f)}</span>
          <span className="plugin-file-name" title={f.name}>
            <strong>{base(f.name)}</strong>
            <span className="muted">
              {f.name.includes("/") ? `${f.name.slice(0, f.name.lastIndexOf("/"))} · ` : ""}
              {fileSize(f.size)} · {relTime(f.modifiedAt)}
            </span>
          </span>
          <span className="plugin-file-actions">
            {busy?.endsWith(f.name) ? <Loader2 size={13} className="spin" /> : null}
            {local ? (
              <button className="btn sm" disabled={busy !== null} onClick={() => void act(`open:${f.name}`, () => open(f))}>
                <ExternalLink size={12} /> {t("plugins.files.open")}
              </button>
            ) : null}
            <button className={local ? "btn ghost sm" : "btn sm"} disabled={busy !== null} onClick={() => void act(`dl:${f.name}`, () => download(props.client, props.plugin, f, props.engagementId))}>
              <Download size={12} /> {t("plugins.files.download")}
            </button>
            {local ? (
              <button className="btn ghost sm" title={t("plugins.files.reveal")} aria-label={t("plugins.files.reveal")} disabled={busy !== null} onClick={() => void act(`rv:${f.name}`, () => reveal(f))}>
                <FolderOpen size={13} />
              </button>
            ) : null}
            {props.onDelete ? (
              <button className="btn ghost sm" title={t("plugins.files.delete")} aria-label={t("plugins.files.delete")} disabled={busy !== null} onClick={() => props.onDelete!(f)}>
                <Trash2 size={13} />
              </button>
            ) : null}
          </span>
        </li>
      ))}
    </ul>
  );
}

/** A plugin's files in the open project, for its card: newest first, with delete and its folder. */
export function PluginFilesSection(props: { client: CoreClient; plugin: string; engagementId: string }) {
  const local = useLocalFiles();
  const [state, setState] = useState<{ files: OutputFile[]; total: number; bytes: number } | null>(null);
  const [seq, setSeq] = useState(0);
  useEffect(() => {
    let live = true;
    void props.client
      .call<{ plugins: Array<{ files: OutputFile[]; total: number; bytes: number }> }>("plugin.outputs", { id: props.plugin, engagementId: props.engagementId })
      .then((r) => live && setState(r.plugins[0] ?? { files: [], total: 0, bytes: 0 }))
      .catch(() => live && setState({ files: [], total: 0, bytes: 0 }));
    return () => {
      live = false;
    };
  }, [props.client, props.plugin, props.engagementId, seq]);
  if (!state) return null;
  const hidden = state.total - state.files.length;
  const remove = async (f: OutputFile) => {
    try {
      await props.client.call("plugin.output_delete", { id: props.plugin, name: f.name, engagementId: props.engagementId });
      toast("ok", t("plugins.files.deleted"), f.name);
      setSeq((n) => n + 1);
    } catch (e) {
      toast("bad", t("plugins.files.failed"), e instanceof Error ? e.message : String(e));
    }
  };
  const openFolder = async () => {
    const path = await pathOf(props.client, props.plugin, undefined, props.engagementId);
    const r = await window.penteosDesktop!.revealFile!(path);
    if (!r.ok) toast("bad", t("plugins.files.cannotOpen"), r.error ?? path);
  };
  return (
    <div className="plugin-files-section">
      <div className="plugin-files-head">
        <span>{state.total ? t("plugins.files.summary", { n: state.total, size: fileSize(state.bytes) }) : t("plugins.files.none")}</span>
        {local && state.total ? (
          <button className="btn ghost sm" onClick={() => void openFolder()}>
            <FolderOpen size={12} /> {t("plugins.files.openFolder")}
          </button>
        ) : null}
      </div>
      <OutputFiles client={props.client} plugin={props.plugin} files={state.files} engagementId={props.engagementId} onDelete={(f) => void remove(f)} />
      {hidden > 0 ? <p className="muted small">{t("plugins.files.more", { n: hidden })}</p> : null}
    </div>
  );
}
