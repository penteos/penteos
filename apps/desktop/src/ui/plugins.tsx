/**
 * Plugins in the interface: what running plugins offer, the forms
 * generated from what they declare, and how their results are shown - always with Penteos's own
 * components, so a plugin looks native and survives a redesign. A plugin never ships interface code
 * at this level: it ships data, and this file draws it.
 */
import { type ReactNode, useCallback, useEffect, useRef, useState } from "react";
import { Bot, BarChart3, Database, Download, FileText, Globe, Image, KeyRound, Loader2, Lock, Mail, Play, Puzzle, Radar, RefreshCw, Search, Send, Shield, SquareTerminal, Upload, Wand2, Zap, Bug } from "./icons";
import { Markdown } from "./Markdown";
import { OutputFiles, panelFile, type OutputFile } from "./files";
import { useApp } from "../state";
import type { CoreClient } from "../client";
import { Badge, Modal, toast } from "./bits";
import { lang, t } from "../i18n";

export type PText = string | { es?: string; en?: string };

/** A permission as a sentence the operator can judge. */
export function permissionText(p: string): string {
  if (p.startsWith("net:")) return t("plugins.perm.net", { host: p.slice(4) });
  if (p.startsWith("secrets:")) return t("plugins.perm.secrets", { name: p.slice(8) });
  return t(`plugins.perm.${p}`);
}

const ICONS: Record<string, (size: number) => ReactNode> = {
  play: (s) => <Play size={s} />, search: (s) => <Search size={s} />, "file-text": (s) => <FileText size={s} />, download: (s) => <Download size={s} />,
  send: (s) => <Send size={s} />, shield: (s) => <Shield size={s} />, bug: (s) => <Bug size={s} />, globe: (s) => <Globe size={s} />, zap: (s) => <Zap size={s} />,
  wand: (s) => <Wand2 size={s} />, key: (s) => <KeyRound size={s} />, lock: (s) => <Lock size={s} />, radar: (s) => <Radar size={s} />, database: (s) => <Database size={s} />,
  terminal: (s) => <SquareTerminal size={s} />, image: (s) => <Image size={s} />, chart: (s) => <BarChart3 size={s} />, mail: (s) => <Mail size={s} />,
  refresh: (s) => <RefreshCw size={s} />, upload: (s) => <Upload size={s} />,
};

/** The icon an operation declares (a play by default). */
export function opIcon(icon: string | undefined, size: number): ReactNode {
  return (icon && ICONS[icon]?.(size)) ?? <Play size={size} />;
}

/** A plugin's own words in the operator's language (falling back to the other one). */
export function ptext(v: unknown): string {
  if (v === undefined || v === null) return "";
  if (typeof v === "string") return v;
  if (typeof v === "object") {
    const o = v as { es?: string; en?: string };
    return (lang() === "es" ? (o.es ?? o.en) : (o.en ?? o.es)) ?? "";
  }
  return String(v);
}

export interface FieldSpec {
  name: string;
  type: "string" | "text" | "number" | "integer" | "boolean" | "date" | "url" | "host" | "enum" | "tags" | "json";
  label?: PText;
  help?: PText;
  placeholder?: PText;
  required?: boolean;
  default?: unknown;
  values?: string[];
  min?: number;
  max?: number;
  secret?: boolean;
}

export type PluginView =
  | { type: "table"; items?: string; columns: Array<{ field: string; label: PText }> }
  | { type: "card"; fields: Array<{ field: string; label: PText }> }
  | { type: "message"; text: string }
  | { type: "json" }
  | { type: "markdown"; field?: string }
  | { type: "document"; field?: string };

export interface CatalogOperation {
  name: string;
  op: string;
  title: PText;
  action?: PText;
  icon?: string;
  description: PText;
  input: FieldSpec[];
  view?: PluginView;
  actors: Array<"human" | "agent">;
  sendsTo: string[];
}

export interface PluginMenu {
  id: string;
  title: PText;
  operation: string;
  where: "plugins" | "entity";
  kinds?: string[];
  prefill?: Record<string, string>;
  direct?: boolean;
}

export interface PluginPanelSpec {
  id: string;
  title: PText;
  file: string;
  where: "plugins" | "entity";
  kinds?: string[];
  height: number;
}

export interface CatalogPlugin {
  id: string;
  level?: "declarative" | "code";
  trust?: "free" | "isolated";
  panels?: PluginPanelSpec[];
  /** Formats it adds to the Deliverable panel. */
  exports?: Array<{ id: string; title: PText; operation: string; icon?: string }>;
  name: string;
  version: string;
  author: { type: "human" | "maestro"; name?: string };
  description?: string;
  permissions: string[];
  sendsTo: string[];
  operations: CatalogOperation[];
  menus: PluginMenu[];
  settings: FieldSpec[];
  providers: Array<{ id: string; label: PText }>;
  entityTypes: Array<{ kind: string; label: PText }>;
  enabled: boolean;
}

/** The running plugins and whether each is enabled in the open project; refreshes on its own. */
export function usePluginCatalog(): { plugins: CatalogPlugin[]; reload: () => void } {
  const { client, engagement } = useApp();
  const [plugins, setPlugins] = useState<CatalogPlugin[]>([]);
  const id = engagement?.id;
  const load = useCallback(() => {
    client.call<{ plugins: CatalogPlugin[] }>("plugin.catalog", id ? { engagementId: id } : {}).then(
      (r) => setPlugins(r.plugins),
      // A core that cannot answer: nothing to offer.
      () => setPlugins([]),
    );
  }, [client, id]);
  useEffect(() => {
    load();
    return client.onEvent((e) => {
      if (e.type === "plugins.changed" || e.type === "engagement.updated" || e.type === "engagement.switched") load();
    });
  }, [client, load]);
  return { plugins, reload: load };
}

// ---------------------------------------------------------------------------------------------
// Opening an operation from anywhere (a menu, the palette, an entity, the Plugins section)
// ---------------------------------------------------------------------------------------------

interface RunRequest {
  /** Set when opened: the form keeps its state until closed or opened again. */
  seq?: number;
  plugin: CatalogPlugin;
  operation: CatalogOperation;
  values: Record<string, unknown>;
  direct?: boolean;
}

const OPEN = "penteos:plugin-run";

export function openPluginOperation(plugin: CatalogPlugin, operation: CatalogOperation, values: Record<string, unknown> = {}, direct = false): void {
  window.dispatchEvent(new CustomEvent<RunRequest>(OPEN, { detail: { plugin, operation, values, direct } }));
}

/** Opens a plugin menu: its form, with what it takes from the entity already filled in. */
type Client = CoreClient;

export async function openPluginMenu(client: Client, plugin: CatalogPlugin, menu: PluginMenu, entityId?: string) {
  const operation = plugin.operations.find((o) => o.op === menu.operation);
  if (!operation) return;
  let values: Record<string, unknown> = {};
  if (menu.prefill && Object.keys(menu.prefill).length) {
    const r = await client.call<{ values: Record<string, unknown> }>("plugin.prefill", { plugin: plugin.id, menu: menu.id, ...(entityId ? { entityId } : {}) }).catch(() => ({ values: {} }));
    values = r.values;
  }
  openPluginOperation(plugin, operation, values, menu.direct);
}

let runSeq = 0;
function detailOf(e: Event): RunRequest {
  return { ...((e as CustomEvent).detail as RunRequest), seq: ++runSeq };
}

/** Mounted once: shows the form of whatever operation was opened. */
export function PluginRunHost() {
  const [req, setReq] = useState<RunRequest>();
  useEffect(() => {
    const on = (e: Event) => setReq(detailOf(e));
    window.addEventListener(OPEN, on);
    return () => window.removeEventListener(OPEN, on);
  }, []);
  return req ? <PluginRunModal key={req.seq} {...req} onClose={() => setReq(undefined)} /> : null;
}

function initialValue(f: FieldSpec, given: unknown): string | boolean {
  const v = given ?? f.default;
  if (f.type === "boolean") return Boolean(v);
  if (v === undefined || v === null) return "";
  if (f.type === "tags" && Array.isArray(v)) return v.join(", ");
  if (f.type === "json") return typeof v === "string" ? v : JSON.stringify(v, null, 2);
  if (f.type === "date" && typeof v === "string") return v.slice(0, 16);
  return String(v);
}

/** Turns what the form holds into the values the operation expects; returns an error text if one does not fit. */
export function collectValues(fields: FieldSpec[], form: Record<string, string | boolean>): { values: Record<string, unknown> } | { error: string } {
  const values: Record<string, unknown> = {};
  for (const f of fields) {
    const raw = form[f.name];
    const label = ptext(f.label) || f.name;
    if (f.type === "boolean") {
      values[f.name] = Boolean(raw);
      continue;
    }
    const text = typeof raw === "string" ? raw.trim() : "";
    if (!text) {
      if (f.required && f.default === undefined) return { error: t("plugins.run.required", { field: label }) };
      continue;
    }
    switch (f.type) {
      case "number":
      case "integer":
        values[f.name] = Number(text);
        break;
      case "tags":
        values[f.name] = text.split(",").map((x) => x.trim()).filter(Boolean);
        break;
      case "json":
        try {
          values[f.name] = JSON.parse(text);
        } catch {
          return { error: t("plugins.run.invalidJson", { field: label }) };
        }
        break;
      case "date":
        values[f.name] = new Date(text).toISOString();
        break;
      default:
        values[f.name] = text;
    }
  }
  return { values };
}

export function FieldInput(props: { field: FieldSpec; value: string | boolean; onChange: (v: string | boolean) => void; secretSet?: boolean; autoFocus?: boolean }) {
  const f = props.field;
  const label = ptext(f.label) || f.name;
  const placeholder = props.secretSet ? t("plugins.settings.secretSet") : ptext(f.placeholder);
  const common = { id: `pf-${f.name}`, autoFocus: props.autoFocus } as const;
  let control;
  if (f.type === "boolean") {
    control = (
      <label className="pf-check">
        <input {...common} type="checkbox" checked={Boolean(props.value)} onChange={(e) => props.onChange(e.target.checked)} /> {label}
      </label>
    );
  } else if (f.type === "enum") {
    control = (
      <select {...common} className="input" value={String(props.value)} onChange={(e) => props.onChange(e.target.value)}>
        {!f.required || f.default === undefined ? <option value="">-</option> : null}
        {(f.values ?? []).map((v) => <option key={v} value={v}>{v}</option>)}
      </select>
    );
  } else if (f.type === "text" || f.type === "json") {
    control = <textarea {...common} className={`input ${f.type === "json" ? "mono" : ""}`} rows={f.type === "json" ? 6 : 4} placeholder={placeholder} value={String(props.value)} onChange={(e) => props.onChange(e.target.value)} />;
  } else {
    const type = f.secret ? "password" : f.type === "number" || f.type === "integer" ? "number" : f.type === "date" ? "datetime-local" : f.type === "url" ? "url" : "text";
    control = (
      <input
        {...common}
        className={`input ${f.type === "host" || f.type === "url" ? "mono" : ""}`}
        type={type}
        {...(f.min !== undefined ? { min: f.min } : {})}
        {...(f.max !== undefined && (f.type === "number" || f.type === "integer") ? { max: f.max } : {})}
        {...(f.type === "integer" ? { step: 1 } : {})}
        autoComplete={f.secret ? "new-password" : "off"}
        placeholder={placeholder}
        value={String(props.value)}
        onChange={(e) => props.onChange(e.target.value)}
      />
    );
  }
  return (
    <div className="pf-field">
      {f.type !== "boolean" ? (
        <label className="pf-label" htmlFor={common.id}>
          {label}
          {f.required ? <span className="pf-req">*</span> : null}
        </label>
      ) : null}
      {control}
      {f.help ? <div className="pf-help">{ptext(f.help)}</div> : null}
    </div>
  );
}

function PluginRunModal(props: RunRequest & { onClose: () => void }) {
  const { client, engagement } = useApp();
  const { plugin, operation } = props;
  const [form, setForm] = useState<Record<string, string | boolean>>(() => Object.fromEntries(operation.input.map((f) => [f.name, initialValue(f, props.values[f.name])])));
  const [state, setState] = useState<"idle" | "running" | "done">("idle");
  const [error, setError] = useState<string>();
  const [out, setOut] = useState<{ result: unknown; message?: string; plugin?: string; files?: OutputFile[] }>();

  const run = useCallback(async () => {
    const collected = collectValues(operation.input, form);
    if ("error" in collected) {
      setError(collected.error);
      return;
    }
    setError(undefined);
    setState("running");
    try {
      const r = await client.call<{ result: unknown; message?: string; plugin?: string; files?: OutputFile[] }>("plugin.run", { name: operation.name, input: collected.values, ...(engagement ? { engagementId: engagement.id } : {}) });
      setOut(r);
      setState("done");
    } catch (e) {
      setError((e as Error).message);
      setState("idle");
    }
  }, [client, engagement, form, operation]);

  // A menu that has nothing left to ask runs right away.
  useEffect(() => {
    if (props.direct && !("error" in collectValues(operation.input, form))) void run();
    // Only once, when opened.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const description = ptext(operation.description);
  return (
    <Modal
      title={t("plugins.run.title", { plugin: plugin.name, op: ptext(operation.title) })}
      icon={<Puzzle size={15} />}
      onClose={props.onClose}
      footer={
        <>
          <button className="btn ghost" onClick={props.onClose}>{t("common.close")}</button>
          <button className="btn primary" disabled={state === "running" || !plugin.enabled} onClick={() => void run()}>
            {state === "running" ? <Loader2 size={12} className="spin" /> : opIcon(operation.icon, 12)} {state === "running" ? t("plugins.run.running") : state === "done" ? t("plugins.run.again") : ptext(operation.action) || t("plugins.run.go")}
          </button>
        </>
      }
    >
      <div className="pf">
        {description ? <p className="pf-desc">{description}</p> : null}
        <div className="pf-badges">
          {operation.sendsTo.length ? <Badge tone="warn" title={t("plugins.project.consent", { hosts: operation.sendsTo.join(", ") })}>{t("plugins.sendsTo", { hosts: operation.sendsTo.join(", ") })}</Badge> : null}
          {operation.actors.includes("agent") ? <Badge tone="agent"><Bot size={11} /> {t("plugins.ops.agent")}</Badge> : null}
        </div>
        {!plugin.enabled ? <div className="pf-error">{t("plugins.run.unavailable")}</div> : null}
        {operation.input.map((f, i) => (
          <FieldInput key={f.name} field={f} value={form[f.name] ?? ""} autoFocus={i === 0} onChange={(v) => setForm((cur) => ({ ...cur, [f.name]: v }))} />
        ))}
        {error ? <div className="pf-error">{error}</div> : null}
        {state === "done" && out?.files?.length ? (
          <div className="pf-result">
            <div className="pf-result-h">{t(out.files.length === 1 ? "plugins.files.made.one" : "plugins.files.made.other", { n: out.files.length })}</div>
            <OutputFiles client={client} plugin={out.plugin ?? plugin.id} files={out.files} {...(engagement ? { engagementId: engagement.id } : {})} highlight />
          </div>
        ) : null}
        {state === "done" && out ? (
          <div className="pf-result">
            <div className="pf-result-h">{t("plugins.run.result")}</div>
            <ResultView view={operation.view} result={out.result} message={out.message} />
          </div>
        ) : null}
      </div>
    </Modal>
  );
}

/** Reads `a.b[0].c` from a value (the same paths a plugin writes in its views). */
export function pick(value: unknown, path: string | undefined): unknown {
  if (!path) return value;
  let cur: unknown = value;
  for (const m of path.matchAll(/([^.[\]]+)|\[(\d+)\]/g)) {
    if (cur === null || cur === undefined) return undefined;
    const key = m[1] ?? Number(m[2]);
    cur = (cur as Record<string | number, unknown>)[key as never];
  }
  return cur;
}

function cell(v: unknown): string {
  if (v === undefined || v === null) return "-";
  if (Array.isArray(v)) return v.map(cell).join(", ");
  if (typeof v === "object") return JSON.stringify(v);
  return String(v);
}

/** "openPorts" or "open_ports" → "Open ports": a key read as a label. */
function label(key: string): string {
  const words = key.replace(/[_-]+/g, " ").replace(/([a-z0-9])([A-Z])/g, "$1 $2").trim().toLowerCase();
  return words ? words[0]!.toUpperCase() + words.slice(1) : key;
}

const looksHtml = (s: string) => /^\s*(<!doctype html|<html[\s>])/i.test(s) || (s.length > 200 && /<(div|p|table|h[1-6]|body|section)[\s>]/i.test(s));
const looksMarkdown = (s: string) => /(^|\n)(#{1,6} |[-*] |\d+\. |```)/.test(s) || /\*\*[^*]+\*\*/.test(s);

/** An HTML document as a preview: no scripts, no access to the app. */
function DocumentPreview(props: { html: string }) {
  return <iframe className="pf-doc" title={t("plugins.result.document")} sandbox="" srcDoc={props.html} />;
}

function LongText(props: { text: string }) {
  const [open, setOpen] = useState(false);
  const long = props.text.length > 600;
  return (
    <div className="pf-long">
      <pre className="mono">{long && !open ? `${props.text.slice(0, 600)}…` : props.text}</pre>
      {long ? <button className="link-btn" onClick={() => setOpen(!open)}>{open ? t("plugins.result.less") : t("plugins.result.more")}</button> : null}
    </div>
  );
}

/** Any value, in the form that reads naturally (the default when a plugin declares no view). */
function SmartValue(props: { value: unknown; depth?: number }) {
  const { value } = props;
  const depth = props.depth ?? 0;
  if (value === null || value === undefined || value === "") return <span className="muted">-</span>;
  if (typeof value === "boolean") return <span>{value ? t("plugins.result.yes") : t("plugins.result.no")}</span>;
  if (typeof value === "number") return <span className="mono">{value.toLocaleString()}</span>;
  if (typeof value === "string") {
    if (looksHtml(value)) return <DocumentPreview html={value} />;
    if (value.length > 120 && looksMarkdown(value)) return <div className="pf-md"><Markdown text={value} /></div>;
    if (value.length > 160 || value.includes("\n")) return <LongText text={value} />;
    return /^https:\/\//.test(value) ? <a href={value} target="_blank" rel="noreferrer">{value}</a> : <span>{value}</span>;
  }
  if (Array.isArray(value)) {
    if (value.length === 0) return <span className="muted">-</span>;
    const objects = value.every((x) => x && typeof x === "object" && !Array.isArray(x));
    if (objects && depth < 2) {
      const keys = [...new Set(value.flatMap((x) => Object.keys(x as object)))].slice(0, 8);
      return (
        <div className="pf-table-wrap">
          <table className="tbl boxed">
            <thead><tr>{keys.map((k) => <th key={k}>{label(k)}</th>)}</tr></thead>
            <tbody>
              {value.slice(0, 500).map((row, i) => (
                <tr key={i}>{keys.map((k) => <td key={k}>{cell((row as Record<string, unknown>)[k])}</td>)}</tr>
              ))}
            </tbody>
          </table>
          {value.length > 500 ? <div className="muted">{t("plugins.result.firstRows", { n: 500, total: value.length })}</div> : null}
        </div>
      );
    }
    if (value.every((x) => typeof x !== "object" || x === null) && value.length <= 40) return <span>{value.map(cell).join(", ")}</span>;
    return <LongText text={JSON.stringify(value, null, 2)} />;
  }
  if (typeof value === "object" && depth < 3) {
    return (
      <div className="kv pf-card">
        {Object.entries(value as Record<string, unknown>).flatMap(([k, v]) => [
          <div key={`${k}-k`} className="k">{label(k)}</div>,
          <div key={`${k}-v`} className="v"><SmartValue value={v} depth={depth + 1} /></div>,
        ])}
      </div>
    );
  }
  return <LongText text={JSON.stringify(value, null, 2)} />;
}

export function ResultView(props: { view?: PluginView; result: unknown; message?: string }) {
  const { view, result } = props;
  const [raw, setRaw] = useState(false);
  const empty = result === null || result === undefined || (Array.isArray(result) && result.length === 0);
  let body: ReactNode;
  if (empty && !props.message) body = <div className="muted">{t("plugins.run.noResult")}</div>;
  else if (view?.type === "message") body = <div className="pf-message">{props.message ?? cell(result)}</div>;
  else if (view?.type === "table") {
    const items = pick(result, view.items);
    const rows = Array.isArray(items) ? items : [];
    body = (
      <div className="pf-table-wrap">
        <table className="tbl boxed">
          <thead><tr>{view.columns.map((c) => <th key={c.field}>{ptext(c.label)}</th>)}</tr></thead>
          <tbody>
            {rows.slice(0, 500).map((row, i) => (
              <tr key={i}>{view.columns.map((c) => <td key={c.field}>{cell(pick(row, c.field))}</td>)}</tr>
            ))}
            {rows.length === 0 ? <tr><td colSpan={view.columns.length} className="muted">{t("plugins.run.noResult")}</td></tr> : null}
          </tbody>
        </table>
      </div>
    );
  } else if (view?.type === "card") {
    body = (
      <div className="kv pf-card">
        {view.fields.map((f) => [
          <div key={`${f.field}-k`} className="k">{ptext(f.label)}</div>,
          <div key={`${f.field}-v`} className="v"><SmartValue value={pick(result, f.field)} depth={1} /></div>,
        ])}
      </div>
    );
  } else if (view?.type === "markdown") body = <div className="pf-md"><Markdown text={cell(pick(result, view.field))} /></div>;
  else if (view?.type === "document") body = <DocumentPreview html={cell(pick(result, view.field))} />;
  else if (view?.type === "json") body = <pre className="pf-json mono">{JSON.stringify(result, null, 2)}</pre>;
  else body = <SmartValue value={result} />;
  return (
    <div className="pf-result-body">
      {body}
      {!empty && view?.type !== "json" ? (
        <div className="pf-result-tools">
          <button className="link-btn" onClick={() => setRaw(!raw)}>{raw ? t("plugins.result.hideData") : t("plugins.result.showData")}</button>
          <button className="link-btn" onClick={() => void navigator.clipboard.writeText(typeof result === "string" ? result : JSON.stringify(result, null, 2)).then(() => toast("ok", t("plugins.result.copied")))}>{t("common.copy")}</button>
        </div>
      ) : null}
      {raw ? <pre className="pf-json mono">{JSON.stringify(result, null, 2)}</pre> : null}
    </div>
  );
}

/** A plugin notice arrived: shown as a toast with the plugin's name. */
export function usePluginNotifications(): void {
  const { client } = useApp();
  useEffect(
    () =>
      client.onEvent((e) => {
        if (e.type === "plugin.setting_requested") {
          const ev = e as unknown as { name: string; label: string; reason: string };
          toast("info", t("plugins.needs.toast", { label: ev.label, name: ev.name }), ev.reason);
          return;
        }
        if (e.type !== "plugin.notify") return;
        const ev = e as unknown as { pluginName: string; title: string; body?: string; level: "info" | "warn" };
        toast(ev.level === "warn" ? "bad" : "info", ev.title, ev.body ? `${t("plugins.notify.from", { plugin: ev.pluginName })} · ${ev.body}` : t("plugins.notify.from", { plugin: ev.pluginName }));
      }),
    [client],
  );
}

/** The actions plugins enabled here offer on an entity of this kind (entity menus). */
export function PluginEntityActions(props: { entityId: string; kind: string }) {
  const { client } = useApp();
  const offers = usePluginCatalog().plugins;
  const actions = offers
    .filter((p) => p.enabled)
    .flatMap((p) => p.menus.filter((m) => m.where === "entity" && (m.kinds ?? []).some((k) => k === props.kind || `${p.id}:${k}` === props.kind)).map((m) => ({ p, m })));
  return (
    <>
      {actions.map(({ p, m }) => (
        <button key={`${p.id}-${m.id}`} className="btn sm" title={p.name} onClick={() => void openPluginMenu(client, p, m, props.entityId)}>
          <Puzzle size={12} /> {ptext(m.title)}
        </button>
      ))}
    </>
  );
}

function extValue(v: unknown): string {
  if (Array.isArray(v)) return v.map(extValue).join(", ");
  if (v && typeof v === "object") return JSON.stringify(v);
  return String(v);
}

/** What plugins noted on an entity, by plugin (links open in the browser). */
export function PluginExtData(props: { ext?: Record<string, Record<string, unknown>> }) {
  const offers = usePluginCatalog().plugins;
  if (!props.ext || Object.keys(props.ext).length === 0) return null;
  return (
    <>
      <div className="section-title"><Puzzle size={12} /> {t("plugins.entity.ext")}</div>
      <div className="kv">
        {Object.entries(props.ext).flatMap(([pluginId, data]) =>
          Object.entries(data).map(([k, v]) => [
            <div key={`${pluginId}-${k}-k`} className="k" title={pluginId}>{offers.find((p) => p.id === pluginId)?.name ?? pluginId} · {k}</div>,
            <div key={`${pluginId}-${k}-v`} className="v mono">
              {typeof v === "string" && /^https:\/\//.test(v) ? <a href={v} target="_blank" rel="noreferrer">{v}</a> : extValue(v)}
            </div>,
          ]),
        )}
      </div>
    </>
  );
}

// ---------------------------------------------------------------------------------------------
// Panels of code plugins: an isolated frame served by the core, and its bridge
// ---------------------------------------------------------------------------------------------

/** Calls a panel may make per minute (a runaway panel cannot flood the core). */
const PANEL_CALLS_PER_MINUTE = 60;

/**
 * One plugin panel. The frame has its own origin and `sandbox="allow-scripts"`: it can touch
 * nothing of the app, and the core's policy forbids it any network. Its only way out is a message
 * to this window, answered only for the plugin's own operations that people may call.
 */
export function PluginPanelFrame(props: { plugin: CatalogPlugin; panel: PluginPanelSpec; entityId?: string }) {
  const { client, engagement } = useApp();
  const frame = useRef<HTMLIFrameElement>(null);
  const [src, setSrc] = useState<string>();
  const [error, setError] = useState<string>();
  const calls = useRef<number[]>([]);
  const { plugin, panel, entityId } = props;

  useEffect(() => {
    setSrc(undefined);
    client
      .call<{ path: string }>("plugin.panel_open", { id: plugin.id, panel: panel.id, ...(entityId ? { entityId } : {}), ...(engagement ? { engagementId: engagement.id } : {}) })
      .then((r) => setSrc(`${client.httpBase}${r.path}`), (e: Error) => setError(e.message));
  }, [client, plugin.id, panel.id, entityId, engagement?.id]);

  useEffect(() => {
    const onMessage = async (e: MessageEvent) => {
      if (!frame.current || e.source !== frame.current.contentWindow) return;
      const m = e.data as { penteos?: string; id?: number; op?: string; input?: unknown; action?: string; name?: string };
      if ((m?.penteos !== "call" && m?.penteos !== "file") || typeof m.id !== "number") return;
      const reply = (msg: Record<string, unknown>) => frame.current?.contentWindow?.postMessage({ penteos: "result", id: m.id, ...msg }, "*");
      const now = Date.now();
      calls.current = calls.current.filter((at) => at > now - 60_000);
      if (calls.current.length >= PANEL_CALLS_PER_MINUTE) return reply({ ok: false, error: "too many calls from this panel" });
      calls.current.push(now);
      const input = (m.input && typeof m.input === "object" ? m.input : {}) as Record<string, unknown>;
      const where = engagement ? { engagementId: engagement.id } : {};
      if (m.penteos === "file") {
        // Only its own files, in the open project.
        try {
          await panelFile(client, plugin.id, String(m.action), String(m.name ?? ""), engagement?.id);
          return reply({ ok: true, value: null });
        } catch (err) {
          return reply({ ok: false, error: (err as Error).message });
        }
      }
      try {
        // Its own operations by their short name; a free plugin's panel may also call any operation of
        // Penteos by its full name - except those that manage plugins (it cannot give itself more).
        const op = plugin.operations.find((o) => o.op === m.op && o.actors.includes("human"));
        if (op) {
          const r = await client.call<{ result: unknown }>("plugin.run", { name: op.name, input, ...where });
          return reply({ ok: true, value: r.result });
        }
        const name = String(m.op ?? "");
        if (plugin.trust !== "free" || !name.includes(".") || /^plugin\.(approve|enable|disable|set_trust|set_project|install|install_file|uninstall|rescan|set_settings|purge_project)$/.test(name)) {
          return reply({ ok: false, error: `no operation ${name} for this panel` });
        }
        reply({ ok: true, value: await client.call(name, { ...where, ...input }) });
      } catch (err) {
        reply({ ok: false, error: (err as Error).message });
      }
    };
    window.addEventListener("message", onMessage);
    return () => window.removeEventListener("message", onMessage);
  }, [client, engagement, plugin]);

  if (error) return <div className="pf-error">{error}</div>;
  if (!src) return <div className="muted">{t("plugins.code.loading")}</div>;
  return <iframe ref={frame} className="plugin-frame" title={ptext(panel.title)} src={src} sandbox="allow-scripts" referrerPolicy="no-referrer" style={{ height: panel.height }} />;
}

/** A plugin panel in a tab of its own (opened from the Plugins menu). */
export function PluginPanelTab(props: { params: { pluginId: string; panelId: string } }) {
  const offers = usePluginCatalog().plugins;
  const plugin = offers.find((p) => p.id === props.params.pluginId);
  const panel = plugin?.panels?.find((p) => p.id === props.params.panelId);
  if (!plugin || !panel) return <div className="panel"><div className="panel-scroll"><div className="muted" style={{ padding: 16 }}>{t("plugins.run.unavailable")}</div></div></div>;
  return (
    <div className="panel">
      <div className="panel-toolbar"><Puzzle size={14} /><h3>{plugin.name} · {ptext(panel.title)}</h3></div>
      <div className="panel-scroll plugin-panel-body">
        <PluginPanelFrame plugin={plugin} panel={{ ...panel, height: Math.max(panel.height, 480) }} />
      </div>
    </div>
  );
}

/** The panels plugins enabled here show inside an entity's detail. */
export function PluginEntityPanels(props: { entityId: string; kind: string }) {
  const offers = usePluginCatalog().plugins;
  const panels = offers
    .filter((p) => p.enabled)
    .flatMap((p) => (p.panels ?? []).filter((x) => x.where === "entity" && (x.kinds ?? []).some((k) => k === props.kind || `${p.id}:${k}` === props.kind)).map((x) => ({ p, x })));
  if (!panels.length) return null;
  return (
    <>
      {panels.map(({ p, x }) => (
        <div key={`${p.id}-${x.id}`}>
          <div className="section-title"><Puzzle size={12} /> {p.name} · {ptext(x.title)}</div>
          <div className="plugin-panel-inline"><PluginPanelFrame plugin={p} panel={x} entityId={props.entityId} /></div>
        </div>
      ))}
    </>
  );
}

// ---------------------------------------------------------------------------------------------
// Alerts of free plugins: Penteos tells what it saw; the operator stops the plugin or goes on.
// ---------------------------------------------------------------------------------------------

interface PluginAlert {
  key: number;
  pluginId: string;
  pluginName: string;
  kind: "destination" | "client_data";
  text: string;
}

export function PluginAlerts() {
  const { client } = useApp();
  const [alerts, setAlerts] = useState<PluginAlert[]>([]);
  useEffect(() => {
    let n = 0;
    return client.onEvent((e) => {
      if (e.type !== "plugin.alert") return;
      const a = e as unknown as Omit<PluginAlert, "key">;
      setAlerts((cur) => [...cur.slice(-4), { ...a, key: ++n }]);
    });
  }, [client]);
  const dismiss = (key: number) => setAlerts((cur) => cur.filter((a) => a.key !== key));
  const stop = (a: PluginAlert) =>
    client.call("plugin.disable", { id: a.pluginId }).then(
      () => {
        toast("ok", t("plugins.alert.stopped", { name: a.pluginName }));
        setAlerts((cur) => cur.filter((x) => x.pluginId !== a.pluginId));
      },
      (err: Error) => toast("bad", t("plugins.failed"), err.message),
    );
  if (!alerts.length) return null;
  return (
    <div className="plugin-alerts">
      {alerts.map((a) => (
        <div key={a.key} className="plugin-alert">
          <div className="plugin-alert-h"><Puzzle size={13} /> <b>{a.pluginName}</b> · {t(`plugins.alert.${a.kind}`)}</div>
          <div className="mono plugin-alert-t">{a.text}</div>
          <div className="plugin-alert-a">
            <button className="btn sm danger" onClick={() => void stop(a)}>{t("plugins.alert.stop")}</button>
            <button className="btn sm ghost" onClick={() => dismiss(a.key)}>{t("plugins.alert.goOn")}</button>
          </div>
        </div>
      ))}
    </div>
  );
}

interface ActivityItem {
  at: string;
  kind: "egress" | "direct" | "process" | "alert";
  severity: "info" | "warn";
  text: string;
  where?: "target" | "declared" | "elsewhere";
}

type ActivityReply = { activity: ActivityItem[] };

/** What Penteos saw a plugin do (destinations, programs, alerts), newest first. */
export function PluginActivityList(props: { pluginId: string }) {
  const { client } = useApp();
  const [items, setItems] = useState<ActivityItem[]>();
  useEffect(() => {
    function load() {
      return client.call<ActivityReply>("plugin.activity", { id: props.pluginId }).then((r) => setItems(r.activity.slice().reverse()), () => setItems([]));
    }
    load();
    return client.onEvent((e) => {
      if (e.type === "plugin.alert") load();
    });
  }, [client, props.pluginId]);
  if (!items) return null;
  if (!items.length) return <div className="muted plugin-activity-empty">{t("plugins.activity.empty")}</div>;
  return (
    <div className="plugin-activity">
      {items.slice(0, 60).map((a, i) => (
        <div key={i} className={`pa-row ${a.severity}`}>
          <span className="mono muted">{new Date(a.at).toLocaleTimeString()}</span>
          <span className="pa-kind">{t(`plugins.activity.${a.kind}`)}{a.where ? ` · ${t(`plugins.activity.where.${a.where}`)}` : ""}</span>
          <span className="mono pa-text">{a.text}</span>
        </div>
      ))}
    </div>
  );
}

/**
 * The code of a plugin the Maestro wrote, in its approval card: what changed against the
 * installed version, and each file. The operator approves it only after reviewing it.
 */
export function ProposalCode(props: { pluginId: string; code: { runtime: "node" | "python"; files: Array<{ path: string; lines: number }>; diff?: string } }) {
  const { client } = useApp();
  const [files, setFiles] = useState<Array<{ path: string; text: string }>>();
  const [open, setOpen] = useState<string>(props.code.diff ? "@diff" : "");
  const [error, setError] = useState<string>();
  useEffect(() => {
    let live = true;
    client.call<{ code?: Array<{ path: string; text: string }> }>("plugin.draft_get", { id: props.pluginId }).then(
      (r) => {
        if (!live) return;
        setFiles(r.code ?? []);
        setOpen((cur) => cur || r.code?.find((f) => /^main\.(m?js|py)$/.test(f.path))?.path || r.code?.[0]?.path || "");
      },
      (e: Error) => live && setError(e.message),
    );
    return () => {
      live = false;
    };
  }, [client, props.pluginId]);
  const shown = files?.find((f) => f.path === open);
  return (
    <div className="code-review proposal-code">
      <div className="code-review-files">
        {props.code.diff ? <button className={`code-file ${open === "@diff" ? "on" : ""}`} onClick={() => setOpen("@diff")}>{t("plugins.proposal.changes")}</button> : null}
        {props.code.files.map((f) => (
          <button key={f.path} className={`code-file ${f.path === open ? "on" : ""}`} onClick={() => setOpen(f.path)}>{f.path} <span className="muted">{f.lines}</span></button>
        ))}
      </div>
      {error ? <div className="pf-error">{error}</div> : null}
      {open === "@diff" && props.code.diff ? (
        <pre className="code-view mono diff">
          {props.code.diff.split("\n").map((l, i) => (
            <span key={i} className={l.startsWith("+") && !l.startsWith("+++") ? "add" : l.startsWith("-") && !l.startsWith("---") ? "del" : l.startsWith("@@") ? "hunk" : ""}>{l}{"\n"}</span>
          ))}
        </pre>
      ) : shown ? (
        <pre className="code-view mono">{shown.text}</pre>
      ) : !files && !error ? (
        <div className="muted">{t("plugins.code.loading")}</div>
      ) : null}
    </div>
  );
}

/**
 * Formats plugins enabled in the project add to the deliverable: each one runs its plugin's
 * operation and offers the files it made, right there.
 */
export function PluginExports() {
  const { client, engagement } = useApp();
  const { plugins } = usePluginCatalog();
  const [busy, setBusy] = useState<string>();
  const [made, setMade] = useState<{ plugin: string; files: OutputFile[] }>();
  const offers = plugins.filter((p) => p.enabled).flatMap((p) => (p.exports ?? []).map((x) => ({ plugin: p, x })));
  if (!offers.length) return null;
  const run = async (plugin: CatalogPlugin, x: { id: string; operation: string }) => {
    const op = plugin.operations.find((o) => o.op === x.operation);
    if (!op) return;
    // A format that asks for something (an author, a template) goes through its form.
    if (op.input.length) return openPluginOperation(plugin, op);
    setBusy(`${plugin.id}:${x.id}`);
    try {
      const r = await client.call<{ plugin?: string; files?: OutputFile[] }>("plugin.run", { name: op.name, input: {}, ...(engagement ? { engagementId: engagement.id } : {}) });
      if (r.files?.length) setMade({ plugin: r.plugin ?? plugin.id, files: r.files });
      else toast("info", t("plugins.exports.noFiles"), plugin.name);
    } catch (e) {
      toast("bad", t("plugins.exports.failed"), (e as Error).message);
    } finally {
      setBusy(undefined);
    }
  };
  return (
    <div className="plugin-exports">
      <div className="plugin-exports-row">
        <span className="muted">{t("plugins.exports.title")}</span>
        {offers.map(({ plugin, x }) => (
          <button key={`${plugin.id}:${x.id}`} className="btn sm" disabled={busy !== undefined} title={plugin.name} onClick={() => void run(plugin, x)}>
            {busy === `${plugin.id}:${x.id}` ? <Loader2 size={12} className="spin" /> : opIcon(x.icon ?? "download", 12)} {ptext(x.title)}
          </button>
        ))}
      </div>
      {made ? <OutputFiles client={client} plugin={made.plugin} files={made.files} {...(engagement ? { engagementId: engagement.id } : {})} highlight /> : null}
    </div>
  );
}

/**
 * The Extensions section of the activity bar: what the plugins enabled in this project bring
 * to work with - their panels, right here, and their actions one click away.
 */
export function PluginHubPanel() {
  const { workbench } = useApp();
  const { plugins } = usePluginCatalog();
  const offers = plugins.filter((p) => p.enabled && ((p.panels ?? []).some((x) => x.where === "plugins") || p.operations.some((o) => o.actors.includes("human"))));
  const [open, setOpen] = useState<string>();
  const panels = offers.flatMap((p) => (p.panels ?? []).filter((x) => x.where === "plugins").map((panel) => ({ plugin: p, panel, key: `${p.id}:${panel.id}` })));
  const current = panels.find((x) => x.key === open) ?? panels[0];
  if (!offers.length) {
    return (
      <div className="panel">
        <div className="panel-scroll"><div className="muted" style={{ padding: 16 }}>{t("plugins.hub.empty")}</div></div>
      </div>
    );
  }
  return (
    <div className="panel">
      <div className="panel-toolbar"><Puzzle size={14} /><h3>{t("plugins.hub.title")}</h3></div>
      <div className="panel-scroll plugin-hub">
        <div className="plugin-hub-actions">
          {offers.map((p) => {
            const ops = p.operations.filter((o) => o.actors.includes("human"));
            if (!ops.length) return null;
            return (
              <div key={p.id} className="plugin-hub-plugin">
                <span className="plugin-hub-name">{p.name}</span>
                {ops.map((o) => (
                  <button key={o.name} className="btn sm" onClick={() => openPluginOperation(p, o)} title={ptext(o.description)}>
                    {opIcon(o.icon, 12)} {ptext(o.action) || ptext(o.title)}
                  </button>
                ))}
              </div>
            );
          })}
        </div>
        {current ? (
          <div className="plugin-hub-panels">
            <div className="plugin-hub-tabs">
              {panels.map((x) => (
                <button key={x.key} className={`code-file ${x.key === current.key ? "on" : ""}`} onClick={() => setOpen(x.key)}>{x.plugin.name} · {ptext(x.panel.title)}</button>
              ))}
              <span className="grow" />
              <button className="btn ghost sm" onClick={() => workbench.openPluginPanel(current.plugin.id, current.panel.id, ptext(current.panel.title))}>{t("plugins.hub.ownTab")}</button>
            </div>
            <PluginPanelFrame key={current.key} plugin={current.plugin} panel={{ ...current.panel, height: Math.max(current.panel.height, 520) }} />
          </div>
        ) : null}
      </div>
    </div>
  );
}

/** Whether the project has anything for the Extensions section (its place shows only then). */
export function useHasPluginHub(): boolean {
  const { plugins } = usePluginCatalog();
  return plugins.some((p) => p.enabled && ((p.panels ?? []).some((x) => x.where === "plugins") || p.operations.some((o) => o.actors.includes("human"))));
}
