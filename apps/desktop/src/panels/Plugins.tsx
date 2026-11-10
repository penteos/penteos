/**
 * The Plugins section: what is installed and in what state, what each
 * plugin may do, where it sends data, the switches (approve, enable, per project, uninstall), its
 * settings, its log and what it keeps. Every action goes through the core's plugin operations.
 */
import { useEffect, useMemo, useState } from "react";
import { Activity, Bot, Check, Cpu, Database, Globe, KeyRound, Lock, Upload, Zap, Play, Puzzle, RefreshCw, ScrollText, Settings2, ShieldAlert, Trash2 } from "../ui/icons";
import { can, useApp, useOperation } from "../state";
import { Badge, Empty, Modal, toast } from "../ui/bits";
import { HelpHint } from "../ui/HelpHint";
import { collectValues, FieldInput, opIcon, permissionText, PluginActivityList, type CatalogPlugin, type FieldSpec, openPluginOperation, type PText, ptext, usePluginCatalog } from "../ui/plugins";
import { t } from "../i18n";
import { PluginFilesSection } from "../ui/files";

interface PluginInfo {
  id: string;
  name: string;
  folder: string;
  status: "active" | "disabled" | "pending" | "invalid" | "incompatible" | "modified" | "slow" | "safe_mode";
  version?: string;
  level?: "declarative" | "code";
  description?: PText;
  author?: { type: "human" | "maestro"; name?: string };
  permissions: string[];
  reason?: { code: string; detail?: string; auto: boolean };
  health: { errors: number; timeouts: number; crashes: number };
  /** Code plugins: how its process runs. */
  isolation?: "free" | "kernel" | "process";
  trust?: "free" | "isolated";
}

interface BundledEntry {
  id: string;
  name: string;
  version: string;
  description?: PText;
  permissions: string[];
  sendsTo: string[];
  offers: { operations: number; menus: number; providers: number; entityTypes: number; events: number };
  installed?: { version?: string; status: string };
  update: boolean;
}

interface DraftView {
  level?: "declarative" | "code";
  id: string;
  name: string;
  version: string;
  valid: boolean;
  issues: string[];
  warnings: string[];
  tested: boolean;
  meta: { updatedAt: string; lastTest?: { ok: boolean; at: string; operation: string; error?: string; live?: boolean }; proposed?: { at: string }; needs?: Array<{ setting: string; reason: string }> };
  installed?: { version?: string; status: string };
}

interface StorageStats {
  bytes: number;
  quotaBytes: number;
  tables: Array<{ name: string; rows: number }>;
}

const TONE: Record<PluginInfo["status"], string | undefined> = {
  active: "ok",
  slow: "warn",
  disabled: undefined,
  pending: "info",
  invalid: "bad",
  incompatible: "bad",
  modified: "warn",
  safe_mode: "warn",
};

function size(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(0)} KB`;
  return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
}

export function PluginsPanel() {
  const { client, engagement, me } = useApp();
  const lead = can(me, "lead");
  const list = useOperation<{ safeMode: boolean; dir: string; plugins: PluginInfo[] }>("plugin.list", {}, { refreshOn: (e) => e.type === "plugins.changed" });
  const catalog = usePluginCatalog();
  const byId = useMemo(() => new Map(catalog.plugins.map((p) => [p.id, p])), [catalog.plugins]);
  const [approving, setApproving] = useState<PluginInfo>();
  const [uninstalling, setUninstalling] = useState<PluginInfo>();
  const [settingsOf, setSettingsOf] = useState<PluginInfo>();
  const [busy, setBusy] = useState(false);
  const bundled = useOperation<{ plugins: BundledEntry[] }>("plugin.bundled", {}, { refreshOn: (e) => e.type === "plugins.changed" });
  const [installing, setInstalling] = useState<BundledEntry>();
  const offerable = (bundled.data?.plugins ?? []).filter((b) => !b.installed || b.update);
  const drafts = useOperation<{ drafts: DraftView[] }>("plugin.drafts", {}, { refreshOn: (e) => e.type === "plugins.changed" || e.type === "approval.changed" || e.type === "plugin.setting_requested" || e.type === "plugin.setting_given" });
  // A .penteos-plugin file: checked and unpacked by the core; it then waits for approval.
  const installFromFile = () => {
    const input = document.createElement("input");
    input.type = "file";
    input.accept = ".penteos-plugin,.zip";
    input.onchange = async () => {
      const file = input.files?.[0];
      if (!file) return;
      const bytes = new Uint8Array(await file.arrayBuffer());
      let binary = "";
      for (let i = 0; i < bytes.length; i += 0x8000) binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
      setBusy(true);
      try {
        const r = await client.call<{ name: string; version: string }>("plugin.install_file", { filename: file.name, contentBase64: btoa(binary) });
        toast("ok", t("plugins.file.installed", { name: r.name, version: r.version }), t("plugins.file.next"));
        list.reload();
      } catch (e) {
        toast("bad", t("plugins.file.failed"), (e as Error).message);
      } finally {
        setBusy(false);
      }
    };
    input.click();
  };
  const askMaestro = () => {
    window.dispatchEvent(new Event("penteos:open-agent"));
    setTimeout(() => window.dispatchEvent(new CustomEvent("penteos:agent-prefill", { detail: t("plugins.ask.prefill") })), 150);
  };

  const act = async (op: string, input: Record<string, unknown>, ok: string) => {
    setBusy(true);
    try {
      await client.call(op, input);
      toast("ok", ok);
      list.reload();
      catalog.reload();
    } catch (e) {
      toast("bad", t("plugins.failed"), (e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  const plugins = list.data?.plugins ?? [];
  return (
    <div className="panel">
      <div className="panel-toolbar">
        <Puzzle size={14} />
        <h3>{t("plugins.title")}</h3>
        <span className="count">{plugins.length}</span>
        <HelpHint id="plugins" text={t("plugins.hint")} />
        <span className="grow" />
        <button className="btn sm" onClick={askMaestro}><Bot size={12} /> {t("plugins.ask.button")}</button>
        {lead ? <button className="btn sm ghost" disabled={busy} onClick={installFromFile}><Upload size={12} /> {t("plugins.file.install")}</button> : null}
        {lead ? (
          <button className="btn sm ghost" disabled={busy} onClick={() => void act("plugin.rescan", {}, t("plugins.reload"))}>
            <RefreshCw size={12} /> {t("plugins.reload")}
          </button>
        ) : null}
      </div>
      <div className="panel-scroll">
        {list.data?.safeMode ? (
          <div className="plugin-safe"><ShieldAlert size={13} /> {t("plugins.safeMode")}</div>
        ) : null}
        {lead && offerable.length ? (
          <div className="plugin-catalog">
            <div className="sec-head"><Puzzle size={13} /> <span>{t("plugins.catalog.title")}</span> <span className="muted">{t("plugins.catalog.hint")}</span></div>
            <div className="plugin-catalog-grid">
              {offerable.map((b) => (
                <div key={b.id} className="plugin-offer">
                  <div className="plugin-offer-h">
                    <b>{b.name}</b>
                    <span className="mono muted">{t("plugins.version", { version: b.version })}</span>
                  </div>
                  {b.description ? <p>{ptext(b.description)}</p> : null}
                  <div className="plugin-offer-f">
                    {b.sendsTo.length ? <Badge tone="warn" title={t("plugins.sendsTo", { hosts: b.sendsTo.join(", ") })}><Globe size={11} /> {b.sendsTo.join(", ")}</Badge> : <Badge>{t("plugins.local")}</Badge>}
                    <span className="grow" />
                    <button className="btn sm primary" disabled={busy} onClick={() => setInstalling(b)}>
                      {b.update ? t("plugins.catalog.update", { from: b.installed?.version ?? "", to: b.version }) : t("plugins.catalog.install")}
                    </button>
                  </div>
                </div>
              ))}
            </div>
          </div>
        ) : null}
        {(drafts.data?.drafts ?? []).length ? (
          <div className="plugin-catalog">
            <div className="sec-head"><Bot size={13} /> <span>{t("plugins.drafts.title")}</span> <span className="muted">{t("plugins.drafts.hint")}</span></div>
            <div className="plugin-drafts">
              {(drafts.data?.drafts ?? []).map((d) => (
                <div key={d.id} className="plugin-draft">
                  <div className="plugin-draft-h">
                    <b>{d.name}</b>
                    <span className="mono muted">{d.id} · {t("plugins.version", { version: d.version })}</span>
                    <span className="grow" />
                    {d.level === "code" ? <Badge>{t("plugins.code.badge")}</Badge> : null}
                    {!d.valid ? <Badge tone="bad">{t("plugins.drafts.invalid", { n: d.issues.length })}</Badge> : d.tested ? <Badge tone="ok">{t("plugins.drafts.tested")}</Badge> : d.meta.lastTest && !d.meta.lastTest.ok ? <Badge tone="warn">{t("plugins.drafts.testFailed")}</Badge> : <Badge>{t("plugins.drafts.untested")}</Badge>}
                    {d.meta.proposed ? <Badge tone="info">{t("plugins.drafts.proposed")}</Badge> : null}
                    {d.installed ? <Badge>{t("plugins.drafts.installed", { version: d.installed.version ?? "?" })}</Badge> : null}
                    {lead ? <button className="btn sm ghost" title={t("common.delete")} onClick={() => void act("plugin.draft_delete", { id: d.id }, t("plugins.drafts.deleted")).then(() => drafts.reload())}><Trash2 size={12} /></button> : null}
                  </div>
                  {!d.valid ? <div className="plugin-draft-issues mono">{d.issues.slice(0, 4).join("\n")}</div> : null}
                  {d.valid && d.meta.lastTest && !d.meta.lastTest.ok && d.meta.lastTest.error ? <div className="plugin-draft-issues mono">{d.meta.lastTest.error}</div> : null}
                  {d.meta.needs?.length ? <DraftNeeds id={d.id} needs={d.meta.needs} onDone={() => drafts.reload()} /> : null}
                </div>
              ))}
            </div>
          </div>
        ) : null}
        {plugins.length === 0 && list.data ? (
          <Empty icon={<Puzzle size={22} />} title={t("plugins.empty.title")}>
            {t("plugins.empty.body", { dir: list.data.dir })}
          </Empty>
        ) : null}
        <div className="plugin-list">
          {plugins.map((p) => (
            <PluginCard
              key={p.id}
              info={p}
              offer={byId.get(p.id)}
              lead={lead}
              busy={busy}
              hasProject={Boolean(engagement)}
              localOnly={engagement?.dataPolicy === "local_only" || engagement?.dataPolicy === "no_ai"}
              onApprove={() => setApproving(p)}
              onEnable={() => void act("plugin.enable", { id: p.id }, t("plugins.enabled"))}
              onDisable={() => void act("plugin.disable", { id: p.id }, t("plugins.disabled"))}
              onUninstall={() => setUninstalling(p)}
              onSettings={() => setSettingsOf(p)}
              onTrust={(trust) => void act("plugin.set_trust", { id: p.id, trust }, t(`plugins.trust.changed.${trust}`))}
              onProject={(enabled) => void act("plugin.set_project", { id: p.id, engagementId: engagement!.id, enabled }, enabled ? t("plugins.project.enabledToast") : t("plugins.project.disabledToast"))}
            />
          ))}
        </div>
      </div>
      {approving ? <ApproveModal info={approving} busy={busy} onClose={() => setApproving(undefined)} onApprove={(reviewedCode, trust) => void act("plugin.approve", { id: approving.id, ...(reviewedCode ? { reviewedCode: true, trust } : {}) }, t("plugins.approved")).then(() => setApproving(undefined))} /> : null}
      {installing ? (
        <Modal
          title={t("plugins.approve.title", { name: installing.name })}
          icon={<Puzzle size={15} />}
          onClose={() => setInstalling(undefined)}
          footer={
            <>
              <button className="btn ghost" onClick={() => setInstalling(undefined)}>{t("common.cancel")}</button>
              <button className="btn primary" disabled={busy} onClick={() => void act("plugin.install", { id: installing.id, approve: true }, t("plugins.catalog.installed", { name: installing.name })).then(() => { setInstalling(undefined); bundled.reload(); })}>
                <Check size={12} /> {installing.update ? t("plugins.catalog.updateConfirm") : t("plugins.catalog.installConfirm")}
              </button>
            </>
          }
        >
          {installing.description ? <p>{ptext(installing.description)}</p> : null}
          <p>{t("plugins.approve.body")}</p>
          <ul className="plugin-perms">
            {installing.permissions.map((perm) => <li key={perm} className={perm.startsWith("net:") || perm === "target" || perm === "proxy" ? "warn" : ""}>{permissionText(perm)}</li>)}
          </ul>
          <p className="muted">{t("plugins.catalog.next")}</p>
        </Modal>
      ) : null}
      {uninstalling ? <UninstallModal info={uninstalling} onClose={() => setUninstalling(undefined)} onDone={() => { list.reload(); catalog.reload(); }} /> : null}
      {settingsOf ? <SettingsModal info={settingsOf} onClose={() => setSettingsOf(undefined)} /> : null}
    </div>
  );
}

function PluginCard(props: {
  info: PluginInfo;
  offer?: CatalogPlugin;
  lead: boolean;
  busy: boolean;
  hasProject: boolean;
  localOnly: boolean;
  onApprove: () => void;
  onEnable: () => void;
  onDisable: () => void;
  onUninstall: () => void;
  onSettings: () => void;
  onProject: (enabled: boolean) => void;
  onTrust: (trust: "free" | "isolated") => void;
}) {
  const { client, engagement } = useApp();
  const { info, offer } = props;
  const [log, setLog] = useState<string[]>();
  const [showActivity, setShowActivity] = useState(false);
  const [storage, setStorage] = useState<{ project?: StorageStats; global?: StorageStats; footprint?: { entities: Record<string, number>; annotations: number } }>();
  const running = info.status === "active" || info.status === "slow";
  const failures = info.health.errors + info.health.timeouts + info.health.crashes;
  const sendsTo = offer?.sendsTo ?? [];

  useEffect(() => {
    if (!running || !engagement) return;
    client.call<typeof storage>("plugin.storage", { id: info.id, engagementId: engagement.id }).then(setStorage, () => undefined);
  }, [client, engagement, info.id, running, offer?.enabled]);

  const toggleLog = () => {
    if (log) return setLog(undefined);
    client.call<{ lines: string[] }>("plugin.log", { id: info.id, lines: 80 }).then((r) => setLog(r.lines), (e: Error) => toast("bad", t("plugins.failed"), e.message));
  };

  const entities = Object.values(storage?.footprint?.entities ?? {}).reduce((a, b) => a + b, 0);
  return (
    <section className={`plugin-card ${running ? "" : "off"}`}>
      <div className="plugin-head">
        <Puzzle size={15} />
        <div className="plugin-name">
          <b>{info.name}</b>
          <span className="mono muted">{info.id}{info.version ? ` · ${t("plugins.version", { version: info.version })}` : ""}</span>
        </div>
        <Badge tone={TONE[info.status]}>{t(`plugins.status.${info.status}`)}</Badge>
        {info.author?.type === "maestro" ? <Badge tone="agent"><Bot size={11} /> {t("plugins.author.maestro")}</Badge> : null}
        {info.level === "code" ? <Badge tone="accent" title={t("plugins.code.hint")}><Cpu size={11} /> {t("plugins.code.badge")}</Badge> : null}
        {info.level === "code" && info.trust ? (
          <Badge tone={info.trust === "free" ? "warn" : undefined} title={t(`plugins.trust.${info.trust}.hint`)}>{info.trust === "free" ? <Zap size={11} /> : <Lock size={11} />} {t(`plugins.trust.${info.trust}`)}</Badge>
        ) : null}
        {info.isolation && info.isolation !== "free" ? <Badge title={t(`plugins.code.isolation.${info.isolation}.hint`)}>{t(`plugins.code.isolation.${info.isolation}`)}</Badge> : null}
        {sendsTo.length ? <Badge tone="warn" title={t("plugins.sendsTo", { hosts: sendsTo.join(", ") })}><Globe size={11} /> {t("plugins.sendsTo.short")}</Badge> : null}
      </div>
      {info.description ? <p className="plugin-desc">{ptext(info.description)}</p> : null}
      {info.reason && info.status !== "active" ? (
        <div className={`plugin-reason ${info.reason.auto ? "auto" : ""}`}>
          {t(`shell.plugins.reason.${info.reason.code}`)}
          {info.reason.detail ? <span className="mono muted"> {info.reason.detail}</span> : null}
        </div>
      ) : null}
      {failures > 0 ? <div className="plugin-health muted">{t("plugins.health", info.health)}</div> : null}
      {info.permissions.length ? (
        <ul className="plugin-perms">
          {info.permissions.map((perm) => <li key={perm} className={perm.startsWith("net:") || perm === "target" || perm === "proxy" ? "warn" : ""}>{permissionText(perm)}</li>)}
        </ul>
      ) : null}

      {running && offer ? (
        <div className="plugin-project">
          <div className="sec-head"><span>{t("plugins.project.title")}</span></div>
          {!props.hasProject ? (
            <div className="muted">{t("plugins.project.noProject")}</div>
          ) : (
            <>
              <div className="plugin-project-row">
                <Badge tone={offer.enabled ? "ok" : undefined}>{offer.enabled ? t("plugins.project.on") : t("plugins.project.off")}</Badge>
                {props.lead ? (
                  <button className={`btn sm ${offer.enabled ? "ghost" : "primary"}`} disabled={props.busy || (!offer.enabled && sendsTo.length > 0 && props.localOnly)} onClick={() => props.onProject(!offer.enabled)}>
                    {offer.enabled ? t("plugins.project.disable") : t("plugins.project.enable")}
                  </button>
                ) : null}
              </div>
              {sendsTo.length ? <div className="muted plugin-consent">{props.localOnly ? t("plugins.project.blockedPolicy") : t("plugins.project.consent", { hosts: sendsTo.join(", ") })}</div> : <div className="muted plugin-consent">{t("plugins.local")}</div>}
            </>
          )}
          {offer.operations.some((o) => o.actors.includes("human")) ? (
            <>
              <div className="sec-head"><span>{t("plugins.ops.title")}</span></div>
              <div className="plugin-ops">
                {offer.operations.filter((o) => o.actors.includes("human")).map((o) => (
                  <div key={o.name} className="plugin-op">
                    <div>
                      <div>{ptext(o.title)} {o.actors.includes("agent") ? <span className="muted" title={t("plugins.ops.agent")}><Bot size={11} /></span> : null}</div>
                      <div className="muted">{ptext(o.description)}</div>
                    </div>
                    <button className="btn sm" disabled={!offer.enabled} onClick={() => openPluginOperation(offer, o)}>
                      {opIcon(o.icon, 11)} {ptext(o.action) || t("plugins.action.run")}
                    </button>
                  </div>
                ))}
              </div>
            </>
          ) : null}
          {offer.entityTypes.length ? (
            <div className="muted">{t("plugins.types.title")}: {offer.entityTypes.map((x) => ptext(x.label)).join(", ")}</div>
          ) : null}
          {offer.providers.length ? (
            <div className="muted">{t("plugins.providers.title")}: {offer.providers.map((x) => ptext(x.label)).join(", ")}</div>
          ) : null}
          {storage && (storage.project || storage.global || entities || storage.footprint?.annotations) ? (
            <div className="plugin-storage muted">
              <Database size={11} /> {t("plugins.storage.title")}:{" "}
              {[storage.project, storage.global].filter(Boolean).map((s, i) => (
                <span key={i}>{t("plugins.storage.size", { size: size(s!.bytes), quota: size(s!.quotaBytes) })} · {s!.tables.map((x) => t("plugins.storage.rows", { table: x.name, n: x.rows })).join(" · ")} </span>
              ))}
              {entities || storage.footprint?.annotations ? <span>{t("plugins.storage.footprint", { entities, annotations: storage.footprint?.annotations ?? 0 })}</span> : null}
            </div>
          ) : null}
          {engagement && (info.permissions.includes("files:write") || info.trust === "free") ? (
            <>
              <div className="sec-head"><span>{t("plugins.files.title")}</span></div>
              <PluginFilesSection client={client} plugin={info.id} engagementId={engagement.id} />
            </>
          ) : null}
        </div>
      ) : null}

      <div className="plugin-actions">
        {props.lead && (info.status === "pending" || info.status === "modified") ? (
          <button className="btn sm primary" disabled={props.busy} onClick={props.onApprove}><Check size={12} /> {t("plugins.action.approve")}</button>
        ) : null}
        {props.lead && info.status === "disabled" ? <button className="btn sm" disabled={props.busy} onClick={props.onEnable}>{t("plugins.action.enable")}</button> : null}
        {props.lead && running ? <button className="btn sm ghost" disabled={props.busy} onClick={props.onDisable}>{t("plugins.action.disable")}</button> : null}
        {props.lead && offer?.settings.length ? <button className="btn sm ghost" onClick={props.onSettings}><Settings2 size={12} /> {t("plugins.action.settings")}</button> : null}
        {props.lead && info.level === "code" && running ? (
          <button className="btn sm ghost" disabled={props.busy} onClick={() => props.onTrust(info.trust === "free" ? "isolated" : "free")}>
            {info.trust === "free" ? <><Lock size={12} /> {t("plugins.trust.isolate")}</> : <><Zap size={12} /> {t("plugins.trust.free")}</>}
          </button>
        ) : null}
        <button className="btn sm ghost" onClick={toggleLog}><ScrollText size={12} /> {log ? t("plugins.action.hideLog") : t("plugins.action.log")}</button>
        {info.level === "code" ? <button className="btn sm ghost" onClick={() => setShowActivity(!showActivity)}><Activity size={12} /> {t("plugins.activity.title")}</button> : null}
        <span className="grow" />
        {props.lead ? <button className="btn sm ghost danger" disabled={props.busy} onClick={props.onUninstall}><Trash2 size={12} /> {t("plugins.action.uninstall")}</button> : null}
      </div>
      {log ? <pre className="plugin-log mono">{log.join("\n") || "-"}</pre> : null}
      {showActivity ? <PluginActivityList pluginId={info.id} /> : null}
    </section>
  );
}

function UninstallModal(props: { info: PluginInfo; onClose: () => void; onDone: () => void }) {
  const { client } = useApp();
  const [purge, setPurge] = useState(false);
  const [busy, setBusy] = useState(false);
  const go = async () => {
    setBusy(true);
    try {
      await client.call("plugin.uninstall", { id: props.info.id, purgeGlobal: purge });
      toast("ok", t("plugins.uninstalled"), props.info.name);
      props.onDone();
      props.onClose();
    } catch (e) {
      toast("bad", t("plugins.failed"), (e as Error).message);
      setBusy(false);
    }
  };
  return (
    <Modal
      title={t("plugins.uninstall.title", { name: props.info.name })}
      icon={<Trash2 size={15} />}
      onClose={props.onClose}
      footer={
        <>
          <button className="btn ghost" onClick={props.onClose}>{t("common.cancel")}</button>
          <button className="btn danger" disabled={busy} onClick={() => void go()}>{t("plugins.uninstall.confirm")}</button>
        </>
      }
    >
      <p>{t("plugins.uninstall.body")}</p>
      <label className="pf-check">
        <input type="checkbox" checked={purge} onChange={(e) => setPurge(e.target.checked)} /> {t("plugins.uninstall.purgeGlobal")}
      </label>
    </Modal>
  );
}

function SettingsModal(props: { info: PluginInfo; onClose: () => void }) {
  const { client } = useApp();
  const [fields, setFields] = useState<FieldSpec[]>([]);
  const [secretsSet, setSecretsSet] = useState<string[]>([]);
  const [form, setForm] = useState<Record<string, string | boolean>>({});
  const [cleared, setCleared] = useState<Set<string>>(new Set());
  const [error, setError] = useState<string>();
  useEffect(() => {
    client.call<{ fields: FieldSpec[]; values: Record<string, unknown>; secretsSet: string[] }>("plugin.settings", { id: props.info.id }).then(
      (r) => {
        setFields(r.fields);
        setSecretsSet(r.secretsSet);
        setForm(Object.fromEntries(r.fields.map((f) => [f.name, f.secret ? "" : f.type === "boolean" ? Boolean(r.values[f.name] ?? f.default) : String(r.values[f.name] ?? f.default ?? "")])));
      },
      (e: Error) => setError(e.message),
    );
  }, [client, props.info.id]);

  const save = async () => {
    // Secrets: only what was typed (or cleared) is sent; an untouched one keeps its value.
    const plain = fields.filter((f) => !f.secret);
    const collected = collectValues(plain.map((f) => ({ ...f, required: false })), form);
    if ("error" in collected) return setError(collected.error);
    const values: Record<string, unknown> = {};
    for (const f of plain) values[f.name] = collected.values[f.name] ?? null;
    for (const f of fields.filter((x) => x.secret)) {
      if (cleared.has(f.name)) values[f.name] = "";
      else if (typeof form[f.name] === "string" && (form[f.name] as string).length > 0) values[f.name] = form[f.name];
    }
    try {
      await client.call("plugin.set_settings", { id: props.info.id, values });
      toast("ok", t("plugins.settings.saved"), props.info.name);
      props.onClose();
    } catch (e) {
      setError((e as Error).message);
    }
  };

  return (
    <Modal
      title={t("plugins.settings.title", { name: props.info.name })}
      icon={<Settings2 size={15} />}
      onClose={props.onClose}
      footer={
        <>
          <button className="btn ghost" onClick={props.onClose}>{t("common.cancel")}</button>
          <button className="btn primary" disabled={fields.length === 0} onClick={() => void save()}>{t("common.save")}</button>
        </>
      }
    >
      <div className="pf">
        {fields.length === 0 && !error ? <div className="muted">{t("plugins.settings.none")}</div> : null}
        {fields.map((f, i) => (
          <div key={f.name} className="pf-row">
            <FieldInput field={f} value={form[f.name] ?? ""} autoFocus={i === 0} secretSet={f.secret && secretsSet.includes(f.name) && !cleared.has(f.name)} onChange={(v) => setForm((cur) => ({ ...cur, [f.name]: v }))} />
            {f.secret && secretsSet.includes(f.name) && !cleared.has(f.name) ? (
              <button className="btn sm ghost" onClick={() => setCleared((c) => new Set([...c, f.name]))}>{t("plugins.settings.clear")}</button>
            ) : null}
          </div>
        ))}
        {error ? <div className="pf-error">{error}</div> : null}
      </div>
    </Modal>
  );
}

/** Approving a plugin: its permissions; for code, its files too - approved only after a review. */
function ApproveModal(props: { info: PluginInfo; busy: boolean; onClose: () => void; onApprove: (reviewedCode: boolean, trust: "free" | "isolated") => void }) {
  const { client } = useApp();
  const code = props.info.level === "code";
  const [files, setFiles] = useState<Array<{ path: string; bytes: number; text?: string }>>();
  const [open, setOpen] = useState<string>();
  const [reviewed, setReviewed] = useState(false);
  const [trust, setTrust] = useState<"free" | "isolated">("free");
  useEffect(() => {
    if (!code) return;
    client.call<{ files: Array<{ path: string; bytes: number; text?: string }> }>("plugin.files", { id: props.info.id }).then(
      (r) => {
        setFiles(r.files);
        setOpen(r.files.find((f) => /\.(m?js)$/.test(f.path))?.path);
      },
      (e: Error) => toast("bad", t("plugins.failed"), e.message),
    );
  }, [client, code, props.info.id]);
  const shown = files?.find((f) => f.path === open);
  return (
    <Modal
      title={t("plugins.approve.title", { name: props.info.name })}
      icon={<Puzzle size={15} />}
      onClose={props.onClose}
      footer={
        <>
          <button className="btn ghost" onClick={props.onClose}>{t("common.cancel")}</button>
          <button className="btn primary" disabled={props.busy || (code && !reviewed)} onClick={() => props.onApprove(code, trust)}>
            <Check size={12} /> {t("plugins.approve.confirm")}
          </button>
        </>
      }
    >
      <p>{t("plugins.approve.body")}</p>
      <ul className="plugin-perms">
        {props.info.permissions.map((perm) => <li key={perm} className={perm.startsWith("net:") || perm === "target" || perm === "proxy" ? "warn" : ""}>{permissionText(perm)}</li>)}
      </ul>
      {code ? (
        <div className="code-review">
          <div className="code-review-warn"><Cpu size={13} /> {t("plugins.code.approveWarn")}</div>
          {files ? (
            <>
              <div className="code-review-files">
                {files.map((f) => (
                  <button key={f.path} className={`code-file ${f.path === open ? "on" : ""}`} onClick={() => setOpen(f.path)}>
                    <span className="mono">{f.path}</span> <span className="muted">{Math.max(1, Math.round(f.bytes / 1024))} KB</span>
                  </button>
                ))}
              </div>
              {shown ? <pre className="code-view mono">{shown.text ?? t("plugins.code.binary")}</pre> : null}
            </>
          ) : (
            <div className="muted">{t("plugins.code.loading")}</div>
          )}
          <div className="trust-pick">
            {(["free", "isolated"] as const).map((x) => (
              <label key={x} className={`trust-opt ${trust === x ? "on" : ""}`}>
                <input type="radio" name="trust" checked={trust === x} onChange={() => setTrust(x)} />
                <span><b>{t(`plugins.trust.${x}`)}</b><span className="muted">{t(`plugins.trust.${x}.hint`)}</span></span>
              </label>
            ))}
          </div>
          <label className="pf-check">
            <input type="checkbox" checked={reviewed} onChange={(e) => setReviewed(e.target.checked)} /> {t("plugins.code.reviewed")}
          </label>
        </div>
      ) : null}
    </Modal>
  );
}

/**
 * What the Maestro asked the operator for to finish a plugin (a key, an account): a protected field
 * per request. Secrets are encrypted by the core and never reach the Maestro.
 */
function DraftNeeds(props: { id: string; needs: Array<{ setting: string; reason: string }>; onDone: () => void }) {
  const { client, engagement } = useApp();
  const [fields, setFields] = useState<FieldSpec[]>([]);
  const [values, setValues] = useState<Record<string, string>>({});
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    client.call<{ fields: FieldSpec[] }>("plugin.draft_settings", { id: props.id }).then((r) => setFields(r.fields), () => undefined);
  }, [client, props.id]);
  const save = async () => {
    setBusy(true);
    try {
      const given = Object.fromEntries(Object.entries(values).filter(([, v]) => v.trim()));
      await client.call("plugin.draft_set_settings", { id: props.id, values: given, ...(engagement ? { engagementId: engagement.id } : {}) });
      toast("ok", t("plugins.needs.saved"));
      setValues({});
      props.onDone();
    } catch (e) {
      toast("bad", t("plugins.failed"), (e as Error).message);
    } finally {
      setBusy(false);
    }
  };
  return (
    <div className="draft-needs">
      <div className="draft-needs-h"><KeyRound size={13} /> {t("plugins.needs.title")}</div>
      {props.needs.map((n) => {
        const f = fields.find((x) => x.name === n.setting);
        return (
          <label key={n.setting} className="draft-need">
            <span className="draft-need-label">{f ? ptext(f.label) || n.setting : n.setting}</span>
            <span className="muted">{n.reason}</span>
            <input type={f?.secret ? "password" : "text"} autoComplete="off" value={values[n.setting] ?? ""} placeholder={f?.secret ? t("plugins.needs.secretPh") : ""} onChange={(e) => setValues((v) => ({ ...v, [n.setting]: e.target.value }))} />
          </label>
        );
      })}
      <div className="draft-needs-f">
        <span className="muted">{t("plugins.needs.private")}</span>
        <button className="btn sm primary" disabled={busy || !Object.values(values).some((v) => v.trim())} onClick={() => void save()}>{t("plugins.needs.give")}</button>
      </div>
    </div>
  );
}
