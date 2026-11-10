import { ArrowRight, Ban, FastForward, Pause, Play, Plus, Trash2 } from "../ui/icons";
import { useEffect, useMemo, useState } from "react";
import { useApp, useOperation } from "../state";
import { toast } from "../ui/bits";
import { t, tn } from "../i18n";

/** Interception (stage 2): a queue of waiting messages, edited in place, and the replace rules. */

export interface PendingMessage {
  id: string;
  kind: "request" | "response" | "ws_out" | "ws_in";
  createdAt: string;
  method: string;
  url: string;
  status?: number;
  raw: string;
  binaryBody: boolean;
}
interface InterceptSettings {
  requests: boolean;
  responses: boolean;
  wsMessages: boolean;
  inScopeOnly: boolean;
  skipStatic: boolean;
  hostContains: string;
  methods: string[];
}
export interface ReplaceRule {
  id?: string;
  enabled: boolean;
  target: "request_header" | "request_body" | "request_url" | "response_header" | "response_body";
  match: string;
  regex: boolean;
  replace: string;
  comment?: string;
}
export interface InterceptState {
  settings: InterceptSettings;
  pending: PendingMessage[];
  rules: ReplaceRule[];
}

export function useInterceptState() {
  return useOperation<InterceptState>("intercept.state", {}, { refreshOn: (e) => e.type === "intercept.changed" });
}

export function InterceptTab() {
  const { client } = useApp();
  const state = useInterceptState();
  const s = state.data?.settings;
  const pending = state.data?.pending ?? [];
  const [current, setCurrent] = useState<string>();
  const [drafts, setDrafts] = useState<Record<string, string>>({});
  const msg = pending.find((p) => p.id === current) ?? pending[0];
  const text = msg ? (drafts[msg.id] ?? msg.raw) : "";
  const [host, setHost] = useState("");
  useEffect(() => setHost(s?.hostContains ?? ""), [s?.hostContains]);

  const configure = (patch: Partial<InterceptSettings>) => client.call("intercept.configure", patch).catch((e: Error) => toast("bad", t("common.error"), e.message));
  async function decide(action: "forward" | "drop") {
    if (!msg) return;
    try {
      await client.call("intercept.decide", { id: msg.id, action, ...(action === "forward" && drafts[msg.id] !== undefined ? { raw: drafts[msg.id] } : {}) });
      setDrafts(({ [msg.id]: _, ...rest }) => rest);
      setCurrent(undefined);
    } catch (e) {
      toast("bad", action === "drop" ? t("web.ic.dropFailed") : t("web.ic.forwardFailed"), (e as Error).message);
    }
  }

  const on = Boolean(s?.requests || s?.responses || s?.wsMessages);
  return (
    <div className="ic-wrap">
      <div className="ic-bar">
        <button className={`btn sm ${s?.requests ? "primary" : ""}`} onClick={() => configure({ requests: !s?.requests })}>
          {s?.requests ? <Pause size={12} /> : <Play size={12} />} {t("web.ic.requests")}
        </button>
        <button className={`btn sm ${s?.responses ? "primary" : ""}`} onClick={() => configure({ responses: !s?.responses })}>
          {s?.responses ? <Pause size={12} /> : <Play size={12} />} {t("web.ic.responses")}
        </button>
        <button className={`btn sm ${s?.wsMessages ? "primary" : ""}`} onClick={() => configure({ wsMessages: !s?.wsMessages })}>
          {s?.wsMessages ? <Pause size={12} /> : <Play size={12} />} {t("web.ic.ws")}
        </button>
        <label className="check"><input type="checkbox" checked={s?.inScopeOnly ?? true} onChange={(e) => configure({ inScopeOnly: e.target.checked })} /> {t("web.inScopeOnly")}</label>
        <label className="check"><input type="checkbox" checked={s?.skipStatic ?? true} onChange={(e) => configure({ skipStatic: e.target.checked })} /> {t("web.ic.skipStatic")}</label>
        <input className="input sm mono" style={{ width: 170 }} placeholder={t("web.ic.hostPlaceholder")} value={host} onChange={(e) => setHost(e.target.value)} onBlur={() => host !== (s?.hostContains ?? "") && configure({ hostContains: host.trim() })} />
        <div className="grow" />
        {pending.length > 1 ? (
          <button className="btn sm ghost" onClick={() => client.call("intercept.release_all", {}).catch((e: Error) => toast("bad", t("common.error"), e.message))}>
            <FastForward size={12} /> {t("web.ic.forwardAll", { n: pending.length })}
          </button>
        ) : null}
      </div>
      <div className="ic-split">
        <div className="ic-queue">
          {pending.map((p) => (
            <div key={p.id} className={`ic-item ${msg?.id === p.id ? "on" : ""}`} onClick={() => setCurrent(p.id)}>
              <span className={`tag ${p.kind === "request" ? "accent" : p.kind === "response" ? "ok" : "warn"}`}>{p.kind === "request" ? p.method : p.kind === "response" ? p.status : p.method}</span>
              <span className="mono ic-url" title={p.url}>{p.url.replace(/^https?:\/\//, "")}</span>
              {drafts[p.id] !== undefined ? <span className="tag warn">{t("web.edited")}</span> : null}
            </div>
          ))}
          {pending.length === 0 ? (
            <div className="ic-empty">{on ? t("web.ic.waiting") : t("web.ic.off")}</div>
          ) : null}
        </div>
        <div className="ic-editor">
          {msg ? (
            <>
              <div className="ic-head">
                <span className="muted">{t(`web.ic.kind.${msg.kind}`)} · <span className="mono">{msg.url}</span></span>
                {msg.binaryBody ? <span className="tag warn">{t("web.ic.binary")}</span> : null}
                <div className="grow" />
                <button className="btn sm danger" onClick={() => decide("drop")}><Ban size={12} /> {t("web.ic.drop")}</button>
                <button className="btn sm primary" onClick={() => decide("forward")}><ArrowRight size={12} /> {t("web.ic.forward")}</button>
              </div>
              <textarea
                className="ic-text mono"
                spellCheck={false}
                value={text}
                onChange={(e) => setDrafts((d) => ({ ...d, [msg.id]: e.target.value }))}
                onKeyDown={(e) => {
                  if ((e.ctrlKey || e.metaKey) && e.key === "Enter") {
                    e.preventDefault();
                    void decide("forward");
                  }
                }}
              />
            </>
          ) : (
            <div className="graph-empty">{t("web.ic.nothing")}</div>
          )}
        </div>
      </div>
    </div>
  );
}

const TARGETS: Array<ReplaceRule["target"]> = ["request_header", "request_body", "request_url", "response_header", "response_body"];

/** `key` names the catalog entries: web.rules.preset.<key> (button) and .<key>.comment (the rule's note). */
const PRESETS: Array<{ key: string; rule: Omit<ReplaceRule, "comment"> }> = [
  { key: "ua", rule: { enabled: true, target: "request_header", match: "^User-Agent:.*$", regex: true, replace: "User-Agent: Penteos" } },
  { key: "header", rule: { enabled: true, target: "request_header", match: "", regex: false, replace: "X-Pentest: penteos" } },
  { key: "csp", rule: { enabled: true, target: "response_header", match: "^Content-Security-Policy(-Report-Only)?:.*$", regex: true, replace: "" } },
  { key: "xfo", rule: { enabled: true, target: "response_header", match: "^X-Frame-Options:.*$", regex: true, replace: "" } },
  { key: "hidden", rule: { enabled: true, target: "response_body", match: 'type="hidden"', regex: false, replace: 'type="text"' } },
];

export function RulesTab() {
  const { client } = useApp();
  const state = useInterceptState();
  const [rules, setRules] = useState<ReplaceRule[]>([]);
  const [dirty, setDirty] = useState(false);
  useEffect(() => {
    if (!dirty) setRules(state.data?.rules ?? []);
  }, [state.data?.rules, dirty]);
  const update = (i: number, patch: Partial<ReplaceRule>) => {
    setRules((r) => r.map((x, j) => (j === i ? { ...x, ...patch } : x)));
    setDirty(true);
  };
  const add = (rule: ReplaceRule) => {
    setRules((r) => [...r, rule]);
    setDirty(true);
  };
  async function save() {
    try {
      const saved = await client.call<ReplaceRule[]>("proxy.set_rules", { rules });
      setRules(saved);
      setDirty(false);
      toast("ok", t("web.rules.saved"), t("web.rules.savedBody"));
    } catch (e) {
      toast("bad", t("common.notSaved"), (e as Error).message);
    }
  }
  const active = useMemo(() => rules.filter((r) => r.enabled).length, [rules]);
  return (
    <div className="op" style={{ maxWidth: "none" }}>
      <div className="sec-head">
        <span>{t("web.rules.title")}</span>
        <span className="muted">{tn("web.rules.active", active)}</span>
        <div style={{ flex: 1 }} />
        <button className="btn sm primary" disabled={!dirty} onClick={save}>{t("common.save")}</button>
      </div>
      <table className="tbl boxed dense rules">
        <thead>
          <tr><th style={{ width: 30 }} /><th style={{ width: 190 }}>{t("web.rules.col.where")}</th><th>{t("web.rules.col.match")}</th><th style={{ width: 60 }}>{t("web.rules.col.regex")}</th><th>{t("web.rules.col.replace")}</th><th style={{ width: 200 }}>{t("web.rules.col.note")}</th><th style={{ width: 34 }} /></tr>
        </thead>
        <tbody>
          {rules.map((r, i) => (
            <tr key={r.id ?? `n${i}`}>
              <td><input type="checkbox" checked={r.enabled} onChange={(e) => update(i, { enabled: e.target.checked })} /></td>
              <td>
                <select className="input sm" value={r.target} onChange={(e) => update(i, { target: e.target.value as ReplaceRule["target"] })}>
                  {TARGETS.map((k) => <option key={k} value={k}>{t(`web.rules.target.${k}`)}</option>)}
                </select>
              </td>
              <td><input className="input sm mono" style={{ width: "100%" }} value={r.match} placeholder={r.target.endsWith("header") ? t("web.rules.matchEmpty") : ""} onChange={(e) => update(i, { match: e.target.value })} /></td>
              <td style={{ textAlign: "center" }}><input type="checkbox" checked={r.regex} onChange={(e) => update(i, { regex: e.target.checked })} /></td>
              <td><input className="input sm mono" style={{ width: "100%" }} value={r.replace} placeholder={r.target.endsWith("header") ? t("web.rules.replaceEmpty") : ""} onChange={(e) => update(i, { replace: e.target.value })} /></td>
              <td><input className="input sm" style={{ width: "100%" }} value={r.comment ?? ""} onChange={(e) => update(i, { comment: e.target.value })} /></td>
              <td><button className="icon-btn" title={t("common.delete")} onClick={() => (setRules((x) => x.filter((_, j) => j !== i)), setDirty(true))}><Trash2 size={12} /></button></td>
            </tr>
          ))}
          {rules.length === 0 ? <tr><td colSpan={7} className="muted" style={{ padding: 14 }}>{t("web.rules.empty")}</td></tr> : null}
        </tbody>
      </table>
      <div className="add-row" style={{ flexWrap: "wrap" }}>
        <button className="btn sm" onClick={() => add({ enabled: true, target: "request_header", match: "", regex: false, replace: "" })}><Plus size={12} /> {t("web.rules.blank")}</button>
        {PRESETS.map((p) => <button key={p.key} className="btn sm ghost" onClick={() => add({ ...p.rule, comment: t(`web.rules.preset.${p.key}.comment`) })}>{t(`web.rules.preset.${p.key}`)}</button>)}
      </div>
    </div>
  );
}
