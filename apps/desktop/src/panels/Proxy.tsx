import { Ban, Copy, Download, ExternalLink, FileCheck2, Globe, Network, Pencil, PlugZap, Search, Send, Settings2, ShieldAlert, Zap } from "../ui/icons";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { CoreClient } from "../client";
import { type EngagementInfo, type Entity, useApp, useOperation } from "../state";
import { Modal, toast } from "../ui/bits";
import { InterceptTab, RulesTab, useInterceptState } from "./ProxyIntercept";
import { WsMessages } from "./WebSocket";
import { t, tn } from "../i18n";
import { browseOf } from "../browse";
import { BrowseRequest } from "../ui/BrowseRequest";
import { asksOperator } from "../tasks";

/**
 * The proxy: everything the project browser (or Burp, Caido, curl -x…) sends, live, with the
 * scope applied. Pick an exchange to read it, send it to the request editor, keep it as
 * evidence or annotate it.
 */

export interface ProxyEntry {
  seq: number;
  id: string;
  at: string;
  source: string;
  method: string;
  url: string;
  host: string;
  path: string;
  status?: number;
  mime?: string;
  reqSize: number;
  resSize: number;
  durationMs?: number;
  heldMs?: number;
  inScope: boolean;
  blocked: boolean;
  reason?: string;
  rawId?: string;
  error?: string;
  static: boolean;
  edited: boolean;
  note?: string;
  highlight?: string;
  httpVersion?: string;
}

interface ProxyStatus {
  running: boolean;
  host: string;
  port: number;
  /** The port asked for, when it was taken and the proxy moved to another. */
  requestedPort?: number;
  token: string;
  caFingerprint: string;
  upstream?: string;
  username: string;
  settings: { outOfScope: "block" | "passthrough"; recordStatic: boolean };
}

/** Where the browser starts: the first thing the scope includes. */
export function firstTarget(engagement?: EngagementInfo): string {
  const rule = engagement?.scope.find((r) => r.effect === "include");
  const t = rule?.target as { type?: string; value?: string } | undefined;
  if (!t?.value) return "";
  if (t.type === "url") return t.value;
  if (t.type === "ip") {
    const port = (rule as { ports?: string } | undefined)?.ports?.split(/[,-]/)[0];
    return port ? `http://${t.value}:${port}/` : `http://${t.value}/`;
  }
  if (t.type === "wildcard") return `https://${t.value.replace(/^\*\./, "")}/`;
  return `https://${t.value}/`;
}

/** Texts of the browser window (toolbar and the Maestro's note), in the operator's language. */
export function browserLabels() {
  return {
    window: t("web.browser.window"),
    bar: {
      back: t("web.browser.back"),
      forward: t("web.browser.forward"),
      reload: t("web.browser.reload"),
      devtools: t("web.browser.devtools"),
      placeholder: t("web.browser.placeholder"),
      proxy: t("web.browser.proxy"),
      proxyHint: t("web.browser.proxyHint"),
      maestro: t("common.maestro"),
    },
    note: {
      maestro: t("common.maestro"),
      kicker: t("web.browser.note.kicker"),
      counter: t("web.browser.note.counter"),
      counterShort: t("web.browser.note.counterShort"),
      live: t("web.browser.note.live"),
      done: t("web.browser.note.done"),
      hide: t("web.browser.note.hide"),
      show: t("web.browser.note.show"),
      hint: t("web.browser.note.hint"),
    },
    block: {
      outTitle: t("web.browser.block.outTitle"),
      outWhy: t("web.browser.block.outWhy"),
      add: t("web.browser.block.add"),
      letThrough: t("web.browser.block.letThrough"),
      stopTitle: t("web.browser.block.stopTitle"),
      stopWhy: t("web.browser.block.stopWhy"),
      stopWhyReason: t("web.browser.block.stopWhyReason"),
      resume: t("web.browser.block.resume"),
      windowTitle: t("web.browser.block.windowTitle"),
      windowWhy: t("web.browser.block.windowWhy"),
      otherTitle: t("web.browser.block.otherTitle"),
      otherWhy: t("web.browser.block.otherWhy"),
      openScope: t("web.browser.block.openScope"),
      working: t("web.browser.block.working"),
      dismiss: t("web.browser.block.dismiss"),
    },
  };
}

export async function openProjectBrowser(client: CoreClient, engagement: EngagementInfo | undefined, url?: string, note?: { taskId: string; title: string; url: string; steps: string[]; exchanges?: number; hosts?: string[] }) {
  if (!engagement) return;
  if (!window.penteosDesktop?.openBrowser) {
    toast("info", t("web.proxy.desktopOnly"), t("web.proxy.desktopOnlyBody"));
    return;
  }
  try {
    const s = await client.call<ProxyStatus>("proxy.status", {});
    await window.penteosDesktop.openBrowser({ engagementId: engagement.id, port: s.port, token: s.token, caFingerprint: s.caFingerprint, title: engagement.name, url: url ?? firstTarget(engagement), labels: browserLabels(), ...(note ? { note } : {}) });
  } catch (e) {
    toast("bad", t("web.proxy.browserFailed"), (e as Error).message);
  }
}

const HIGHLIGHT: Record<string, string> = { red: "#e5717d", orange: "#e0956b", yellow: "#d6b26e", green: "#6cc69a", blue: "#8fa8d8", violet: "#9d8cff" };
const size = (n: number) => (n < 1024 ? `${n} B` : n < 1048576 ? `${(n / 1024).toFixed(1)} KB` : `${(n / 1048576).toFixed(1)} MB`);
/**
 * A failed exchange in words: what happened and the likely cause. "error" alone told the operator
 * nothing; a connection the server never accepted usually means its firewall banned this IP.
 */
export function explainProxyError(error: string): { short: string; long: string } {
  if (/no TCP connection|ETIMEDOUT|did not answer the handshake/i.test(error)) return { short: t("web.proxy.err.noConnection"), long: t("web.proxy.err.noConnection.long") };
  if (/ECONNREFUSED/i.test(error)) return { short: t("web.proxy.err.refused"), long: t("web.proxy.err.refused.long") };
  if (/ENOTFOUND|EAI_AGAIN|getaddrinfo/i.test(error)) return { short: t("web.proxy.err.dns"), long: t("web.proxy.err.dns.long") };
  if (/certificate|TLS|SSL|handshake/i.test(error)) return { short: t("web.proxy.err.tls"), long: t("web.proxy.err.tls.long") };
  if (/ECONNRESET|socket hang up|closed the connection/i.test(error)) return { short: t("web.proxy.err.reset"), long: t("web.proxy.err.reset.long") };
  if (/did not answer within|timeout/i.test(error)) return { short: t("web.proxy.err.slow"), long: t("web.proxy.err.slow.long") };
  return { short: t("web.error"), long: error };
}

const GUIDE_KEY = "penteos.proxyGuide";

/** How the proxy works, in three steps, while there is little traffic (or until hidden). */
function ProxyGuide(props: { onOpen: () => void; canOpen: boolean; onHide: () => void }) {
  return (
    <div className="px-guide">
      {[1, 2, 3].map((n) => (
        <div key={n} className="pg-step">
          <span className="pg-n mono">{String(n).padStart(2, "0")}</span>
          <div>
            <div className="pg-t">{t(`web.proxy.guide.${n}.title`)}</div>
            <div className="pg-d">{t(`web.proxy.guide.${n}.body`)}</div>
          </div>
        </div>
      ))}
      <div className="pg-actions">
        <button className="btn sm primary" disabled={!props.canOpen} onClick={props.onOpen}>{t("web.proxy.openBrowser")}</button>
        <button className="link-btn" onClick={props.onHide}>{t("web.proxy.guide.hide")}</button>
      </div>
    </div>
  );
}

const statusTone = (e: ProxyEntry) => (e.blocked ? "bad" : e.error ? "bad" : !e.status ? "" : e.status >= 500 ? "bad" : e.status >= 400 ? "warn" : e.status >= 300 ? "accent" : "ok");

function prettyBody(text: string): string {
  const cut = text.indexOf("\r\n\r\n");
  if (cut < 0) return text;
  const head = text.slice(0, cut);
  const body = text.slice(cut + 4);
  if (/content-type:\s*[^\r\n]*json/i.test(head)) {
    try {
      return `${head}\r\n\r\n${JSON.stringify(JSON.parse(body), null, 2)}`;
    } catch {
      return text;
    }
  }
  return text;
}

function Detail(props: { entry: ProxyEntry; onChanged: (e: ProxyEntry) => void }) {
  const { client, workbench } = useApp();
  const [data, setData] = useState<{ request: string; response: string }>();
  const isWs = props.entry.status === 101 || props.entry.reason === "WebSocket";
  const [tab, setTab] = useState<"request" | "response" | "messages">(isWs ? "messages" : "response");
  const [note, setNote] = useState(props.entry.note ?? "");
  useEffect(() => {
    setData(undefined);
    setNote(props.entry.note ?? "");
    setTab(props.entry.status === 101 ? "messages" : "response");
    client.call<{ request: string; response: string }>("proxy.entry", { id: props.entry.id }).then(setData, (e: Error) => toast("bad", t("common.error"), e.message));
  }, [props.entry.id, client]);
  const e = props.entry;
  const url = new URL(e.url);

  async function annotate(patch: { note?: string; highlight?: string }) {
    const r = await client.call<ProxyEntry>("proxy.annotate", { id: e.id, ...patch }).catch((err: Error) => {
      toast("bad", t("common.error"), err.message);
      return undefined;
    });
    if (r) props.onChanged(r);
  }
  async function evidence() {
    if (!e.rawId) return;
    const caption = window.prompt(t("web.evidence.prompt"), `${e.method} ${url.pathname} → ${e.status ?? t("web.noResponse")}`);
    if (!caption) return;
    await client.call("evidence.from_raw", { rawId: e.rawId, caption }).then(() => toast("ok", t("web.evidence.saved"), t("web.evidence.savedBody")), (err: Error) => toast("bad", t("common.error"), err.message));
  }

  return (
    <div className="px-detail">
      <div className="px-dhead">
        <div className="seg sm">
          <button className={tab === "request" ? "on" : ""} onClick={() => setTab("request")}>{t("web.request")}</button>
          <button className={tab === "response" ? "on" : ""} onClick={() => setTab("response")}>{t("web.response")}</button>
          {isWs ? <button className={tab === "messages" ? "on" : ""} onClick={() => setTab("messages")}>{t("web.proxy.wsMessages")}</button> : null}
        </div>
        <span className="mono muted px-durl" title={e.url}>{e.url}</span>
        <div className="grow" />
        {e.blocked ? <span className="tag bad"><Ban size={10} /> {e.reason}</span> : null}
        {e.error ? <span className="tag bad" title={e.error}>{explainProxyError(e.error).long}</span> : null}
        <div className="px-colors">
          {Object.entries(HIGHLIGHT).map(([k, c]) => (
            <button key={k} title={t("web.proxy.highlight", { color: t(`web.proxy.color.${k}`) })} className={e.highlight === k ? "on" : ""} style={{ background: c }} onClick={() => annotate({ highlight: e.highlight === k ? "none" : k })} />
          ))}
        </div>
        {isWs ? (
          <button
            className="btn sm"
            disabled={!data}
            onClick={() => {
              const keep = (data?.request ?? "").split(/\r?\n/).filter((l) => /^(origin|cookie|authorization|sec-websocket-protocol|user-agent):/i.test(l));
              workbench.openWsRepeater({ url: e.url.replace(/^http/, "ws"), headers: keep.join("\n") });
            }}
          >
            <PlugZap size={12} /> {t("web.toWsRepeater")}
          </button>
        ) : (
          <button className="btn sm" disabled={!data} onClick={() => data && workbench.openRequest({ origin: url.origin, raw: data.request.replace(/\r\n/g, "\n") })}>
            <Send size={12} /> {t("web.toEditor")}
          </button>
        )}
        {isWs ? null : (
          <button className="btn sm" disabled={!data} onClick={() => data && workbench.openFuzzer({ origin: url.origin, template: data.request.replace(/\r\n/g, "\n") })}>
            <Zap size={12} /> {t("web.toFuzzer")}
          </button>
        )}
        <button className="btn sm" disabled={!e.rawId} onClick={evidence}><FileCheck2 size={12} /> {t("web.evidence")}</button>
      </div>
      <div className="px-note">
        <Pencil size={11} />
        <input placeholder={t("web.proxy.notePlaceholder")} value={note} onChange={(ev) => setNote(ev.target.value)} onBlur={() => note !== (e.note ?? "") && annotate({ note })} />
      </div>
      {tab === "messages" ? <WsMessages entryId={e.id} /> : <pre className="px-raw mono">{data ? prettyBody(tab === "request" ? data.request : data.response) || t("web.emptyBody") : t("common.loading")}</pre>}
    </div>
  );
}

function SettingsModal(props: { status: ProxyStatus; onClose: () => void; onSaved: () => void }) {
  const { client } = useApp();
  const [outOfScope, setOutOfScope] = useState(props.status.settings.outOfScope);
  const [recordStatic, setRecordStatic] = useState(props.status.settings.recordStatic);
  const [upstream, setUpstream] = useState(props.status.upstream ?? "");
  async function save() {
    try {
      await client.call("proxy.configure", { outOfScope, recordStatic, upstream: upstream.trim() });
      props.onSaved();
      props.onClose();
      toast("ok", t("web.proxy.configured"));
    } catch (e) {
      toast("bad", t("common.notSaved"), (e as Error).message);
    }
  }
  return (
    <Modal title={t("web.proxy.settings")} icon={<Settings2 size={16} />} onClose={props.onClose} footer={<><button className="btn ghost" onClick={props.onClose}>{t("common.cancel")}</button><button className="btn primary" onClick={save}>{t("common.save")}</button></>}>
      <label>{t("web.proxy.outOfScope")}
        <div className="seg" style={{ alignSelf: "flex-start" }}>
          <button className={outOfScope === "block" ? "on" : ""} onClick={() => setOutOfScope("block")}>{t("web.proxy.block")}</button>
          <button className={outOfScope === "passthrough" ? "on" : ""} onClick={() => setOutOfScope("passthrough")}>{t("web.proxy.passthrough")}</button>
        </div>
        <span className="muted" style={{ fontSize: 12 }}>
          {outOfScope === "block"
            ? t("web.proxy.blockHelp")
            : t("web.proxy.passthroughHelp")}
        </span>
      </label>
      <label className="check" style={{ flexDirection: "row" }}>
        <input type="checkbox" checked={recordStatic} onChange={(e) => setRecordStatic(e.target.checked)} />
        {t("web.proxy.recordStatic")}
      </label>
      <label>{t("web.proxy.upstream")}
        <input className="input mono" placeholder={t("web.proxy.upstreamPlaceholder")} value={upstream} onChange={(e) => setUpstream(e.target.value)} />
        <span className="muted" style={{ fontSize: 12 }}>{t("web.proxy.upstreamHelp")}</span>
      </label>
    </Modal>
  );
}

function ConnectModal(props: { status: ProxyStatus; onClose: () => void }) {
  const { client } = useApp();
  const s = props.status;
  const copy = (text: string, what: string) => navigator.clipboard.writeText(text).then(() => toast("ok", t("web.proxy.copied", { what })));
  async function downloadCa() {
    const ca = await client.call<{ pem: string }>("proxy.ca", {});
    const url = URL.createObjectURL(new Blob([ca.pem], { type: "application/x-pem-file" }));
    const a = document.createElement("a");
    a.href = url;
    a.download = "penteos-ca.pem";
    a.click();
    setTimeout(() => URL.revokeObjectURL(url), 2000);
  }
  const row = (k: string, v: string) => (
    <div className="kv-row"><span className="muted">{k}</span><code className="mono">{v}</code><button className="icon-btn" onClick={() => copy(v, k)}><Copy size={12} /></button></div>
  );
  return (
    <Modal title={t("web.proxy.connectTitle")} icon={<Network size={16} />} onClose={props.onClose} footer={<button className="btn primary" onClick={props.onClose}>{t("common.close")}</button>}>
      <span>{t("web.proxy.connectIntro")}</span>
      {row(t("web.proxy.host"), s.host)}
      {row(t("web.proxy.port"), String(s.port))}
      {row(t("web.proxy.user"), `${s.username}+burp`)}
      {row(t("web.proxy.password"), s.token)}
      <span className="muted" style={{ fontSize: 12 }}>{t("web.proxy.userHelp")}</span>
      {row("curl", `curl -x http://${s.username}+curl:${s.token}@${s.host}:${s.port} --cacert penteos-ca.pem https://…`)}
      <button className="btn" style={{ alignSelf: "flex-start" }} onClick={downloadCa}><Download size={13} /> {t("web.proxy.downloadCa")}</button>
      <span className="muted" style={{ fontSize: 12 }}>{t("web.proxy.caHelp")}</span>
    </Modal>
  );
}

export function ProxyPanel() {
  const { client, engagement, teamMode } = useApp();
  const [status, setStatus] = useState<ProxyStatus>();
  const [statusError, setStatusError] = useState<string>();
  const [entries, setEntries] = useState<ProxyEntry[]>([]);
  const [selected, setSelected] = useState<string>();
  const [text, setText] = useState("");
  const [method, setMethod] = useState("");
  const [statusFilter, setStatusFilter] = useState("");
  const [inScopeOnly, setInScopeOnly] = useState(false);
  const [showBlocked, setShowBlocked] = useState(false);
  const [showStatic, setShowStatic] = useState(false);
  const [modal, setModal] = useState<"settings" | "connect">();
  const [url, setUrl] = useState("");
  const [tab, setTab] = useState<"history" | "intercept" | "rules">(() => (sessionStorage.getItem("penteos.proxyTab") as "history") || "history");
  const intercept = useInterceptState();
  const [guide, setGuide] = useState(() => {
    try {
      return localStorage.getItem(GUIDE_KEY) !== "hidden";
    } catch {
      return true;
    }
  });
  const hideGuide = () => {
    setGuide(false);
    try {
      localStorage.setItem(GUIDE_KEY, "hidden");
    } catch {
      /* storage unavailable */
    }
  };
  // What the Maestro asked the operator to browse: shown here too, where the browsing happens.
  const tasks = useOperation<Entity[]>("entity.query", { kind: "task", limit: 2000 }, { refreshOn: (e) => e.kind === "task" });
  const browseRequests = (tasks.data ?? []).filter((x) => browseOf(x) && asksOperator(x));
  const waiting = intercept.data?.pending.length ?? 0;
  const intercepting = Boolean(intercept.data?.settings.requests || intercept.data?.settings.responses);
  useEffect(() => {
    const go = (e: Event) => setTab((e as CustomEvent<"intercept">).detail); // i18n-ignore: type arguments, not text
    window.addEventListener("penteos:proxy-tab", go);
    return () => window.removeEventListener("penteos:proxy-tab", go);
  }, []);
  useEffect(() => {
    try {
      sessionStorage.setItem("penteos.proxyTab", tab);
    } catch {
      /* storage unavailable */
    }
  }, [tab]);
  const lastSeq = useRef(0);

  const loadStatus = useCallback(() => {
    client.call<ProxyStatus>("proxy.status", {}).then(
      (s) => {
        setStatus(s);
        setStatusError(undefined);
      },
      (e: Error) => setStatusError(e.message),
    );
  }, [client]);

  const filters = useMemo(
    () => ({
      ...(text.trim() ? { text: text.trim() } : {}),
      ...(method ? { methods: [method] } : {}),
      ...(statusFilter ? { status: statusFilter } : {}),
      inScopeOnly,
      includeBlocked: showBlocked,
      includeStatic: showStatic,
    }),
    [text, method, statusFilter, inScopeOnly, showBlocked, showStatic],
  );

  // Full reload when the filters or the project change; live appends otherwise.
  useEffect(() => {
    let alive = true;
    client.call<ProxyEntry[]>("proxy.history", { limit: 1000, ...filters }).then((list) => {
      if (!alive) return;
      setEntries(list);
      lastSeq.current = list[0]?.seq ?? 0;
    }, () => {});
    let timer: ReturnType<typeof setTimeout> | undefined;
    const off = client.onEvent((e) => {
      if (e.type === "engagement.switched") {
        lastSeq.current = 0;
        setEntries([]);
        setSelected(undefined);
        loadStatus();
      }
      if (e.type !== "proxy.entry" && e.type !== "engagement.switched") return;
      clearTimeout(timer);
      timer = setTimeout(() => {
        client.call<ProxyEntry[]>("proxy.history", { limit: 500, afterSeq: lastSeq.current, ...filters }).then((fresh) => {
          if (!alive || !fresh.length) return;
          lastSeq.current = fresh[0]!.seq;
          setEntries((cur) => [...fresh, ...cur].slice(0, 3000));
        }, () => {});
      }, 150);
    });
    return () => {
      alive = false;
      clearTimeout(timer);
      off();
    };
  }, [client, filters, engagement?.id, loadStatus]);

  useEffect(() => loadStatus(), [loadStatus, engagement?.id]);
  useEffect(() => setUrl(firstTarget(engagement)), [engagement?.id]);

  const sel = entries.find((e) => e.id === selected);

  return (
    <div className="panel">
      <div className="panel-toolbar">
        <Network size={14} />
        <h3>{t("web.proxy.title")}</h3>
        {status ? (
          <span className="px-status" title={t("web.proxy.statusTitle")}>
            <span className="led ok" /> 127.0.0.1:{status.port}
            {status.requestedPort ? <span className="tag warn" title={t("web.proxy.portMoved.hint", { from: status.requestedPort, to: status.port })}>{t("web.proxy.portMoved", { from: status.requestedPort })}</span> : null}
            {status.settings.outOfScope === "block" ? <span className="tag" title={t("web.proxy.oosBlocked.hint")}>{t("web.proxy.oosBlocked")}</span> : <span className="tag warn" title={t("web.proxy.oosPassthrough.hint")}>{t("web.proxy.oosPassthrough")}</span>}
            {status.upstream ? <span className="tag accent">→ {status.upstream.replace(/\/\/[^@]*@/, "//")}</span> : null}
          </span>
        ) : (
          <span className="px-status"><span className="led bad" /> {statusError ?? "…"}</span>
        )}
        <div className="grow" />
        <div className="px-open">
          <Globe size={12} />
          <input className="mono" value={url} placeholder={t("web.originPlaceholder")} onChange={(e) => setUrl(e.target.value)} onKeyDown={(e) => e.key === "Enter" && openProjectBrowser(client, engagement, url)} />
          <button className="btn sm primary" disabled={!status} onClick={() => openProjectBrowser(client, engagement, url)}><ExternalLink size={12} /> {t("web.proxy.openBrowser")}</button>
        </div>
        <button className="btn sm ghost" disabled={!status} onClick={() => setModal("connect")} title={t("web.proxy.otherToolsTitle")}><Network size={12} /> {t("web.proxy.otherTools")}</button>
        <button className="icon-btn" disabled={!status} onClick={() => setModal("settings")} title={t("web.proxy.settings")}><Settings2 size={14} /></button>
      </div>
      <div className="px-tabs">
        <button className={tab === "history" ? "on" : ""} onClick={() => setTab("history")}>{t("web.proxy.tab.history")}</button>
        <button className={tab === "intercept" ? "on" : ""} onClick={() => setTab("intercept")}>
          {t("web.proxy.tab.intercept")} {intercepting ? <span className="tag accent">{t("web.active")}</span> : null} {waiting ? <span className="count-pill">{waiting}</span> : null}
        </button>
        <button className={tab === "rules" ? "on" : ""} onClick={() => setTab("rules")}>
          {t("web.proxy.tab.rules")} {intercept.data?.rules.filter((r) => r.enabled).length ? <span className="count-pill muted">{intercept.data.rules.filter((r) => r.enabled).length}</span> : null}{/* i18n-ignore: code, not text */}
        </button>
      </div>
      {tab === "intercept" ? <InterceptTab /> : null}
      {tab === "rules" ? <div className="panel-scroll"><RulesTab /></div> : null}
      {tab === "history" ? (<>
      {browseRequests.length ? (
        <div className="px-requests">
          {browseRequests.map((r) => <div key={r.id} className="approval-card px-request"><div className="head"><span className="head-t">{t("web.proxy.request.title")}</span></div><BrowseRequest task={r} /></div>)}
        </div>
      ) : null}
      {guide && entries.length < 20 && !browseRequests.length ? <ProxyGuide canOpen={Boolean(status)} onOpen={() => openProjectBrowser(client, engagement, url)} onHide={hideGuide} /> : null}
      <div className="px-filters">
        <div className="search-box">
          <Search size={12} />
          <input placeholder={t("web.proxy.filterPlaceholder")} value={text} onChange={(e) => setText(e.target.value)} />
        </div>
        <select className="input sm" value={method} onChange={(e) => setMethod(e.target.value)}>
          <option value="">{t("web.proxy.allMethods")}</option>
          {["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"].map((m) => <option key={m} value={m}>{m}</option>)}
        </select>
        <select className="input sm" value={statusFilter} onChange={(e) => setStatusFilter(e.target.value)}>
          <option value="">{t("web.proxy.allStatuses")}</option>
          {["2xx", "3xx", "4xx", "5xx"].map((s) => <option key={s} value={s}>{s}</option>)}
          <option value="error">{t("web.proxy.withError")}</option>
        </select>
        <label className="check"><input type="checkbox" checked={inScopeOnly} onChange={(e) => setInScopeOnly(e.target.checked)} /> {t("web.inScopeOnly")}</label>
        <label className="check"><input type="checkbox" checked={showStatic} onChange={(e) => setShowStatic(e.target.checked)} /> {t("web.proxy.static")}</label>
        <label className="check"><input type="checkbox" checked={showBlocked} onChange={(e) => setShowBlocked(e.target.checked)} /> <ShieldAlert size={11} /> {t("web.proxy.blocked")}</label>
        <div className="grow" />
        <span className="muted">{tn("web.proxy.exchanges", entries.length)}</span>
      </div>
      <div className="px-split">
        <div className="px-table">
          <table className="tbl dense">
            <thead>
              <tr><th style={{ width: 56 }}>#</th><th style={{ width: 70 }}>{t("web.proxy.col.time")}</th><th style={{ width: 64 }}>{t("web.method")}</th><th style={{ width: 180 }}>{t("web.proxy.col.host")}</th><th>{t("web.proxy.col.path")}</th><th style={{ width: 60 }}>{t("web.status")}</th><th style={{ width: 76 }}>{t("web.size")}</th><th style={{ width: 54 }}>{t("web.ms")}</th><th style={{ width: 90 }}>{t("web.proxy.col.source")}</th></tr>
            </thead>
            <tbody>
              {entries.map((e) => (
                <tr key={e.id} className={`px-row ${selected === e.id ? "on" : ""} ${e.blocked ? "blocked" : ""}`} onClick={() => setSelected(e.id)} style={e.highlight ? { boxShadow: `inset 3px 0 0 ${HIGHLIGHT[e.highlight]}` } : undefined}>
                  <td className="mono muted">{e.seq}</td>
                  <td className="mono muted nowrap">{new Date(e.at).toLocaleTimeString()}</td>
                  <td className="mono nowrap">{e.method}{e.httpVersion === "2" ? <span className="tag muted" title="HTTP/2" style={{ marginLeft: 4 }}>h2</span> : null}{e.edited ? <span className="tag accent" title={t("web.proxy.editedTitle")} style={{ marginLeft: 4 }}>✎</span> : null}</td>
                  <td className="mono nowrap px-host" title={e.host}>{e.host}</td>
                  <td className="mono cmd" title={e.path}>{e.path}{e.note ? <span className="muted"> · {e.note}</span> : null}</td>
                  <td>{e.blocked ? <span className="tag bad">{t("web.proxy.blockedShort")}</span> : e.error ? <span className="tag bad" title={`${explainProxyError(e.error).long}\n${e.error}`}>{explainProxyError(e.error).short}</span> : e.status ? <span className={`tag ${statusTone(e)}`}>{e.status}</span> : "-"}</td>
                  <td className="mono muted nowrap">{size(e.resSize)}</td>
                  <td className="mono muted nowrap">{e.durationMs ?? ""}{e.heldMs ? <span className="tag warn" title={t("web.proxy.heldTitle", { s: (e.heldMs / 1000).toFixed(1) })} style={{ marginLeft: 4 }}>⏸</span> : null}</td>
                  <td className="muted nowrap">{e.source}</td>
                </tr>
              ))}
              {entries.length === 0 ? (
                <tr>
                  <td colSpan={9} className="px-empty">
                    {status ? (
                      t("web.proxy.empty")
                    ) : (
                      client.remote || teamMode ? (
                        <>
                          {t("web.proxy.remote1")}
                          <br />
                          {t("web.proxy.remote2")}
                        </>
                      ) : (
                        t("web.proxy.unavailable", { error: statusError })
                      )
                    )}
                  </td>
                </tr>
              ) : null}
            </tbody>
          </table>
        </div>
        {sel ? <Detail entry={sel} onChanged={(n) => setEntries((cur) => cur.map((x) => (x.id === n.id ? n : x)))} /> : null}
      </div>
      </>) : null}
      {modal === "settings" && status ? <SettingsModal status={status} onClose={() => setModal(undefined)} onSaved={loadStatus} /> : null}
      {modal === "connect" && status ? <ConnectModal status={status} onClose={() => setModal(undefined)} /> : null}
    </div>
  );
}
