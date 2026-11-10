/** Model providers: the picker in the composer and the settings of each one. */
import { Check, ChevronDown, Settings2, ShieldCheck } from "./icons";
import { useCallback, useEffect, useRef, useState } from "react";
import type { AgentEvent, SalaCard } from "../client";
import { useApp } from "../state";
import { Modal, toast } from "../ui/bits";
import { t } from "../i18n";

export interface Provider {
  id: string;
  label: string;
  kind: "plan" | "cli" | "api" | "local";
  description: string;
  fields: Array<"apiKey" | "model" | "baseUrl">;
  settings: { model?: string; baseUrl?: string; hasApiKey: boolean };
  available: boolean;
  reason?: string;
  models?: string[];
}

export function useOutside(ref: React.RefObject<HTMLElement | null>, close: () => void) {
  useEffect(() => {
    const onDown = (e: MouseEvent) => ref.current && !ref.current.contains(e.target as Node) && close();
    window.addEventListener("mousedown", onDown);
    return () => window.removeEventListener("mousedown", onDown);
  }, [ref, close]);
}

export function ProviderPicker(props: { providers: Provider[]; value?: string; onChange: (id: string) => void; onConfigure: (p: Provider) => void; onVerifier: () => void }) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);
  useOutside(ref, useCallback(() => setOpen(false), []));
  const current = props.providers.find((p) => p.id === props.value);
  return (
    <div className="provider-picker" ref={ref}>
      <button className="pp-btn" onClick={() => setOpen((v) => !v)} title={t("agent.provider.title")}>
        <span className={`led ${current?.available ? "ok" : "bad"}`} />
        {current ? current.label : t("agent.provider.none")}
        {current?.settings.model ? <span className="muted">· {current.settings.model}</span> : null}
        <ChevronDown size={12} />
      </button>
      {open ? (
        <div className="pp-menu">
          {(["plan", "api", "local", "cli"] as const).map((kind) => (
            <div key={kind}>
              <div className="pp-group">{t(`agent.provider.group.${kind}`)}</div>
              {props.providers.filter((p) => p.kind === kind).map((p) => (
                <div key={p.id} className={`pp-opt ${p.available ? "" : "off"}`}>
                  <div
                    className="pp-main"
                    onClick={() => {
                      if (!p.available) return props.onConfigure(p);
                      props.onChange(p.id);
                      setOpen(false);
                    }}
                  >
                    <span className={`led ${p.available ? "ok" : ""}`} />
                    <div>
                      <div className="n">
                        {p.label} {p.id === props.value ? <Check size={12} color="var(--accent)" /> : null}
                      </div>
                      <div className="d">{p.available ? p.description : p.reason}</div>
                    </div>
                  </div>
                  <button className="icon-btn" title={t("agent.provider.configure")} onClick={() => { setOpen(false); props.onConfigure(p); }}>
                    <Settings2 size={13} />
                  </button>
                </div>
              ))}
            </div>
          ))}
          <div className="pp-group">{t("agent.provider.group.parallel")}</div>
          <div className="pp-opt">
            <div className="pp-main" onClick={() => { setOpen(false); props.onVerifier(); }}>
              <ShieldCheck size={13} color="var(--accent)" />
              <div>
                <div className="n">{t("agent.provider.verifier.name")}</div>
                <div className="d">{t("agent.provider.verifier.desc")}</div>
              </div>
            </div>
            <button className="icon-btn" title={t("agent.provider.configure")} onClick={() => { setOpen(false); props.onVerifier(); }}>
              <Settings2 size={13} />
            </button>
          </div>
        </div>
      ) : null}
    </div>
  );
}

export function ProviderSettings(props: { provider: Provider; onClose: () => void; onSaved: (providers: Provider[]) => void }) {
  const { client } = useApp();
  const p = props.provider;
  const [apiKey, setApiKey] = useState("");
  const [model, setModel] = useState(p.settings.model ?? "");
  const [baseUrl, setBaseUrl] = useState(p.settings.baseUrl ?? "");
  async function save() {
    const settings: Record<string, string> = {};
    if (p.fields.includes("apiKey") && apiKey) settings.apiKey = apiKey;
    if (p.fields.includes("model")) settings.model = model;
    if (p.fields.includes("baseUrl")) settings.baseUrl = baseUrl;
    const r = await client.request<{ providers: Provider[] }>("agent.configure", { provider: p.id, settings });
    props.onSaved(r.providers);
    const now = r.providers.find((x) => x.id === p.id);
    toast(now?.available ? "ok" : "info", now?.available ? t("agent.provider.ready", { name: p.label }) : t("agent.provider.saved", { name: p.label }), now?.available ? undefined : now?.reason);
    props.onClose();
  }
  return (
    <Modal
      title={t("agent.provider.settings.title", { name: p.label })}
      icon={<Settings2 size={16} />}
      onClose={props.onClose}
      footer={
        <>
          <button className="btn ghost" onClick={props.onClose}>{t("common.cancel")}</button>
          <button className="btn primary" onClick={save}>{t("common.save")}</button>
        </>
      }
    >
      <span>{p.description}.</span>
      {p.kind === "cli" ? (
        <span>
          {t("agent.provider.settings.cliBefore")}<b style={{ color: "var(--fg-0)" }}>{t("agent.provider.settings.cliBold")}</b>{t("agent.provider.settings.cliAfter")}
          {" "}{t("agent.provider.settings.cliRoles")}
        </span>
      ) : null}
      {p.kind === "plan" ? (
        <ChatGptConnect
          onChanged={async () => {
            const r = await client.request<{ providers: Provider[] }>("agent.providers", { refresh: true });
            props.onSaved(r.providers);
          }}
        />
      ) : !p.available && p.reason ? (
        <span style={{ color: "var(--warn)" }}>{p.reason}</span>
      ) : null}
      {p.fields.includes("baseUrl") ? (
        <label>{t("agent.provider.settings.baseUrl")}
          <input className="input mono" value={baseUrl} onChange={(e) => setBaseUrl(e.target.value)} placeholder="http://127.0.0.1:11434/v1" />{/* i18n-ignore: example URL */}
        </label>
      ) : null}
      {p.fields.includes("apiKey") ? (
        <label>{t("agent.provider.settings.apiKey")} {p.settings.hasApiKey ? <span className="muted">{t("agent.provider.settings.apiKeySet")}</span> : null}
          <input className="input mono" type="password" value={apiKey} onChange={(e) => setApiKey(e.target.value)} placeholder={p.kind === "local" ? t("agent.provider.settings.optional") : "sk-…"} />
        </label>
      ) : null}
      {p.fields.includes("model") && (p.kind !== "plan" || p.available) ? (
        <label>{t("agent.provider.settings.model")} {p.kind === "cli" ? <span className="muted">{t("agent.provider.settings.modelDefault")}</span> : null}
          {p.models?.length ? (
            <select className="input" value={model} onChange={(e) => setModel(e.target.value)}>
              {p.models.map((m) => <option key={m} value={m}>{m}</option>)}
            </select>
          ) : (
            <input className="input mono" value={model} onChange={(e) => setModel(e.target.value)} />
          )}
        </label>
      ) : null}
      {p.kind !== "local" ? <span className="muted" style={{ fontSize: 12 }}>{t("agent.provider.settings.cloud")}</span> : null}
    </Modal>
  );
}


interface ChatGptStatus {
  signedIn: boolean;
  plan: boolean;
  email?: string;
  welcome: boolean;
}

const MANAGE_USAGE = "https://chatgpt.com/settings/usage";

/**
 * Sign in with ChatGPT: the official button, then "Using ChatGPT plan" with the account, a link to
 * manage usage in ChatGPT and a way out. The first time, a one-off note says the plan is in use.
 */
export function ChatGptConnect(props: { onChanged: () => unknown }) {
  const { client } = useApp();
  const [status, setStatus] = useState<ChatGptStatus>();
  const [busy, setBusy] = useState(false);
  const load = useCallback(async () => {
    const current: ChatGptStatus = await client.request("chatgpt.status");
    setStatus(current);
  }, [client]);
  // The parent's callback changes every render: read through a ref so the listener is set once.
  const changedRef = useRef(props.onChanged);
  changedRef.current = props.onChanged;
  const changed = () => changedRef.current();
  useEffect(() => {
    void load();
    const done = (e: Event) => {
      const d = (e as CustomEvent<{ ok: boolean; error?: string }>).detail;
      setBusy(false);
      toast(d.ok ? "ok" : "bad", d.ok ? t("agent.chatgpt.connected") : t("agent.chatgpt.failed"), d.ok ? undefined : d.error);
      void load();
      void changed();
    };
    window.addEventListener("penteos:chatgpt-done", done);
    return () => window.removeEventListener("penteos:chatgpt-done", done);
  }, [load]);

  async function signIn() {
    setBusy(true);
    const r = await client.request<{ url?: string; error?: string }>("chatgpt.signin");
    if (r.url) window.open(r.url, "_blank");
    else {
      setBusy(false);
      toast("bad", t("agent.chatgpt.failed"), r.error);
    }
  }
  async function signOut() {
    const r = await client.request<{ revoked: boolean }>("chatgpt.signout");
    toast(r.revoked ? "ok" : "info", r.revoked ? t("agent.chatgpt.signedOut") : t("agent.chatgpt.signedOutLocal"));
    await load();
    await changed();
  }

  if (!status) return null;
  if (status.signedIn && status.plan) {
    return (
      <div className="chatgpt-plan">
        {status.welcome ? (
          <div className="chatgpt-welcome">
            <b>{t("agent.chatgpt.welcome.title")}</b>
            <span>{t("agent.chatgpt.welcome.body")}</span>
            <button
              className="btn sm"
              onClick={() => {
                client.notify("chatgpt.welcomed");
                void load();
              }}
            >
              {t("agent.chatgpt.welcome.ok")}
            </button>
          </div>
        ) : null}
        <div className="chatgpt-row">
          <span className="led ok" />
          <span>
            {t("agent.chatgpt.using")}
            {status.email ? <span className="muted"> · {status.email}</span> : null}
          </span>
          <a href={MANAGE_USAGE} target="_blank" rel="noreferrer">
            {t("agent.chatgpt.manage")}
          </a>
          <button className="btn sm ghost" onClick={() => void signOut()}>
            {t("agent.chatgpt.signOut")}
          </button>
        </div>
      </div>
    );
  }
  return (
    <div className="chatgpt-plan">
      <span className="muted">{t("agent.chatgpt.lead")}</span>
      <button className="btn chatgpt-btn" data-oai-siwc-button="" disabled={busy} onClick={() => void signIn()}>
        {busy ? t("agent.chatgpt.waiting") : t("agent.chatgpt.continue")}
      </button>
    </div>
  );
}
