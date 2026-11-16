/**
 * Connect an AI: the one place to give the Maestro a model, foolproof. It opens by itself when no
 * provider works (after the project assistant, or at start), and from anywhere that needs it (the
 * Maestro panel, Help). It offers only what works on this machine; a failed attempt keeps it open
 * with the reason and the way forward; a success says which AI the Maestro now uses and closes.
 */
import { useCallback, useEffect, useState } from "react";
import { t } from "../i18n";
import { can, useApp } from "../state";
import { Modal } from "./bits";
import { Bot, Check, RefreshCw } from "./icons";
import type { Provider } from "./Providers";

/** Ask any part of the interface to open it, optionally saying why (a provider that stopped working). */
export function openConnectAI(reason?: string) {
  window.dispatchEvent(new CustomEvent("penteos:connect-ai", { detail: reason ?? "" }));
}

const DISMISSED = "penteos.connectAI.later";

type Status = { kind: "idle" } | { kind: "busy"; id: string } | { kind: "error"; id: string; text: string } | { kind: "done"; label: string };

export function ConnectAI() {
  const { client, connected, me } = useApp();
  // Choosing the AI is the lead's (solo: always): a team member without the role is not asked.
  const allowed = can(me, "lead");
  const [open, setOpen] = useState(false);
  const [why, setWhy] = useState("");
  const [providers, setProviders] = useState<Provider[]>([]);
  const [keys, setKeys] = useState<Record<string, string>>({});
  const [status, setStatus] = useState<Status>({ kind: "idle" });

  const load = useCallback(async () => {
    const r = await client.request<{ selected?: string; providers: Provider[] }>("agent.providers", { refresh: true });
    setProviders(r.providers);
    return r.providers;
  }, [client]);

  // At start and after the project assistant: nothing that works means the window opens, unless
  // the operator chose "later" in this session.
  useEffect(() => {
    if (!connected || !allowed) return;
    let later = false;
    try {
      later = sessionStorage.getItem(DISMISSED) === "1";
    } catch {
      /* no storage: ask */
    }
    if (later) return;
    void load().then((ps) => {
      if (!ps.some((p) => p.available)) setOpen(true);
    }).catch(() => undefined);
  }, [connected, load]);

  useEffect(() => {
    const onOpen = (e: Event) => {
      setWhy((e as CustomEvent<string>).detail ?? "");
      setStatus({ kind: "idle" });
      setOpen(true);
      void load().catch(() => undefined);
    };
    // After the project assistant: open if it left the Maestro without a working AI.
    const onCheck = () =>
      void load()
        .then((ps) => {
          if (!ps.some((p) => p.available)) {
            setWhy("");
            setStatus({ kind: "idle" });
            setOpen(true);
          }
        })
        .catch(() => undefined);
    window.addEventListener("penteos:connect-ai", onOpen);
    window.addEventListener("penteos:check-ai", onCheck);
    return () => {
      window.removeEventListener("penteos:connect-ai", onOpen);
      window.removeEventListener("penteos:check-ai", onCheck);
    };
  }, [load]);

  // The outcome of Sign in with ChatGPT arrives from the browser round trip.
  useEffect(() => {
    const done = (e: Event) => {
      const d = (e as CustomEvent<{ ok: boolean; error?: string }>).detail;
      if (d.ok) void use("chatgpt", "ChatGPT");
      else setStatus({ kind: "error", id: "chatgpt", text: d.error || t("agent.connect.chatgptFailed") });
    };
    window.addEventListener("penteos:chatgpt-done", done);
    return () => window.removeEventListener("penteos:chatgpt-done", done);
  });

  /** Makes it the Maestro's provider and says so; the window closes after a moment. */
  async function use(id: string, label: string) {
    client.notify("agent.select", { provider: id });
    window.dispatchEvent(new CustomEvent("penteos:provider-selected", { detail: id }));
    await load().catch(() => undefined);
    setStatus({ kind: "done", label });
    try {
      sessionStorage.removeItem(DISMISSED);
    } catch {
      /* fine */
    }
    setTimeout(() => setOpen(false), 1600);
  }

  async function chatgpt() {
    setStatus({ kind: "busy", id: "chatgpt" });
    const r = await client.request<{ url?: string; error?: string }>("chatgpt.signin");
    if (r.url) window.open(r.url, "_blank");
    else setStatus({ kind: "error", id: "chatgpt", text: r.error || t("agent.connect.chatgptFailed") });
  }

  async function withKey(p: Provider) {
    const key = (keys[p.id] ?? "").trim();
    if (p.fields.includes("apiKey") && !key && p.kind === "api") {
      setStatus({ kind: "error", id: p.id, text: t("agent.connect.keyMissing") });
      return;
    }
    setStatus({ kind: "busy", id: p.id });
    const r = await client.request<{ providers: Provider[] }>("agent.configure", { provider: p.id, settings: key ? { apiKey: key } : {} });
    setProviders(r.providers);
    const now = r.providers.find((x) => x.id === p.id);
    if (now?.available) await use(p.id, p.label);
    else setStatus({ kind: "error", id: p.id, text: now?.reason || t("agent.connect.notWorking") });
  }

  function later() {
    try {
      sessionStorage.setItem(DISMISSED, "1");
    } catch {
      /* fine */
    }
    setOpen(false);
  }

  if (!open || !allowed) return null;
  const plan = providers.find((p) => p.kind === "plan");
  const apis = providers.filter((p) => p.kind === "api" && !p.id.startsWith("plugin:"));
  const local = providers.find((p) => p.kind === "local");
  // CLIs only where installed: offering one the machine does not have only confuses.
  const clis = providers.filter((p) => p.kind === "cli" && p.available);
  const busy = status.kind === "busy";
  const errorFor = (id: string) => (status.kind === "error" && status.id === id ? <span className="connect-error">{status.text}</span> : null);

  return (
    <Modal title={t("agent.connect.title")} icon={<Bot size={16} />} onClose={later} footer={<button className="btn ghost" onClick={later}>{t("agent.connect.later")}</button>}>
      {status.kind === "done" ? (
        <div className="connect-done">
          <Check size={18} /> <b>{t("agent.connect.done", { name: status.label })}</b>
        </div>
      ) : (
        <div className="connect">
          <p className="muted">{why || t("agent.connect.lead")}</p>
          {plan ? (
            <section className="connect-option primary">
              <div>
                <b>{t("agent.connect.chatgptTitle")}</b>
                <span className="muted">{t("agent.connect.chatgptHint")}</span>
              </div>
              <button className="btn primary chatgpt-btn" data-oai-siwc-button="" disabled={busy} onClick={() => void chatgpt()}>
                {status.kind === "busy" && status.id === "chatgpt" ? <><RefreshCw size={13} className="spin" /> {t("agent.connect.waitingBrowser")}</> : t("agent.chatgpt.continue")}
              </button>
              {status.kind === "busy" && status.id === "chatgpt" ? <span className="muted connect-note">{t("agent.connect.browserNote")}</span> : null}
              {errorFor("chatgpt") ? (
                <>
                  {errorFor("chatgpt")}
                  <span className="muted connect-note">{t("agent.connect.tryAgainOrOther")}</span>
                </>
              ) : null}
            </section>
          ) : null}
          <div className="connect-sep">{t("agent.connect.or")}</div>
          {apis.map((p) => (
            <section key={p.id} className="connect-option">
              <div>
                <b>{p.label}</b>
                <span className="muted">{p.available ? t("agent.connect.ready") : p.description}</span>
              </div>
              {p.available ? (
                <button className="btn" disabled={busy} onClick={() => void use(p.id, p.label)}>{t("agent.connect.use")}</button>
              ) : (
                <div className="connect-key">
                  <input className="input mono" type="password" placeholder={t("agent.connect.keyPlaceholder")} value={keys[p.id] ?? ""} onChange={(e) => setKeys((k) => ({ ...k, [p.id]: e.target.value }))} onKeyDown={(e) => e.key === "Enter" && void withKey(p)} />
                  <button className="btn" disabled={busy} onClick={() => void withKey(p)}>
                    {status.kind === "busy" && status.id === p.id ? <RefreshCw size={13} className="spin" /> : null} {t("agent.connect.connect")}
                  </button>
                </div>
              )}
              {errorFor(p.id)}
            </section>
          ))}
          {local ? (
            <section className="connect-option">
              <div>
                <b>{t("agent.connect.localTitle")}</b>
                <span className="muted">{local.available ? t("agent.connect.ready") : t("agent.connect.localHint")}</span>
              </div>
              <button className="btn" disabled={busy} onClick={() => void (local.available ? use(local.id, local.label) : withKey(local))}>
                {status.kind === "busy" && status.id === local.id ? <RefreshCw size={13} className="spin" /> : null} {local.available ? t("agent.connect.use") : t("agent.connect.detect")}
              </button>
              {errorFor(local.id)}
            </section>
          ) : null}
          {clis.map((p) => (
            <section key={p.id} className="connect-option">
              <div>
                <b>{p.label}</b>
                <span className="muted">{t("agent.connect.cliHint")}</span>
              </div>
              <button className="btn" disabled={busy} onClick={() => void use(p.id, p.label)}>{t("agent.connect.use")}</button>
            </section>
          ))}
          <span className="muted connect-note">{t("agent.connect.masked")}</span>
        </div>
      )}
    </Modal>
  );
}
