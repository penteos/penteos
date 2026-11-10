import { ArrowDownLeft, ArrowUpRight, Plug, PlugZap, Send } from "../ui/icons";
import { useEffect, useRef, useState } from "react";
import { useApp } from "../state";
import { toast } from "../ui/bits";
import { t } from "../i18n";

/** WebSocket messages (of a proxy entry) and the WebSocket repeater. */

export interface WsMessage {
  seq: number;
  at: string;
  direction: "out" | "in";
  opcode: number;
  data: string;
  binary: boolean;
  size: number;
  edited: boolean;
}

function pretty(m: WsMessage): string {
  if (m.binary) return `${t("web.ws.binary", { n: m.size })}\n${m.data}`;
  const text = m.data.trim();
  if (text.startsWith("{") || text.startsWith("[")) {
    try {
      return JSON.stringify(JSON.parse(text), null, 2);
    } catch {
      return m.data;
    }
  }
  return m.data;
}

/** Live list of the messages of one WebSocket connection. */
export function WsMessages(props: { entryId: string; compact?: boolean }) {
  const { client } = useApp();
  const [msgs, setMsgs] = useState<WsMessage[]>([]);
  const [open, setOpen] = useState<number>();
  const last = useRef(0);
  useEffect(() => {
    let alive = true;
    last.current = 0;
    setMsgs([]);
    const load = () =>
      client.call<WsMessage[]>("ws.messages", { entryId: props.entryId, afterSeq: last.current, limit: 2000 }).then((fresh) => {
        if (!alive || !fresh.length) return;
        last.current = fresh.at(-1)!.seq;
        setMsgs((cur) => [...cur, ...fresh].slice(-5000));
      }, () => {});
    void load();
    let timer: ReturnType<typeof setTimeout> | undefined;
    const off = client.onEvent((e) => {
      if (e.type !== "ws.message" || e.entryId !== props.entryId) return;
      clearTimeout(timer);
      timer = setTimeout(load, 100);
    });
    return () => {
      alive = false;
      clearTimeout(timer);
      off();
    };
  }, [client, props.entryId]);
  return (
    <div className="ws-list">
      {msgs.map((m) => (
        <div key={m.seq} className={`ws-msg ${m.direction} ${m.opcode === 8 ? "close" : ""}`} onClick={() => setOpen(open === m.seq ? undefined : m.seq)}>
          <span className="dir">{m.direction === "out" ? <ArrowUpRight size={12} /> : <ArrowDownLeft size={12} />}</span>
          <span className="t mono">{new Date(m.at).toLocaleTimeString()}</span>
          <span className="body mono">{open === m.seq ? <pre>{pretty(m)}</pre> : m.binary ? t("web.ws.binary", { n: m.size }) : m.data}</span>
          {m.edited ? <span className="tag accent">{t("web.edited")}</span> : null}
          <span className="sz muted">{m.size} B</span>
        </div>
      ))}
      {msgs.length === 0 ? <div className="ic-empty">{t("web.ws.noMessages")}</div> : null}
    </div>
  );
}

/** Open a WebSocket from Penteos and talk to it by hand. */
export function WsRepeaterPanel(props: { params: { url?: string; headers?: string } }) {
  const { client } = useApp();
  const [url, setUrl] = useState(props.params.url ?? "wss://");
  const [headers, setHeaders] = useState(props.params.headers ?? "");
  const [session, setSession] = useState<{ sessionId: string; entryId: string }>();
  const [entryId, setEntryId] = useState<string>();
  const [text, setText] = useState("");
  const [binary, setBinary] = useState(false);
  const [busy, setBusy] = useState(false);

  // Notice when the server closes it.
  useEffect(() => {
    if (!session) return;
    const off = client.onEvent((e) => {
      if (e.type !== "ws.message" || e.entryId !== session.entryId) return;
      client.call<Array<{ sessionId: string }>>("ws.sessions", {}).then((list) => {
        if (!list.some((s) => s.sessionId === session.sessionId)) setSession(undefined);
      }, () => {});
    });
    return off;
  }, [client, session]);

  async function connect() {
    setBusy(true);
    try {
      const r = await client.call<{ status: string; sessionId?: string; entryId?: string; error?: string }>("ws.open", { url, headers });
      if (r.status === "open" && r.sessionId && r.entryId) {
        setSession({ sessionId: r.sessionId, entryId: r.entryId });
        setEntryId(r.entryId);
      } else if (r.status === "pending_approval") toast("info", t("web.pendingApproval"));
      else {
        toast("bad", t("web.ws.connectFailed"), r.error);
        if (r.entryId) setEntryId(r.entryId);
      }
    } catch (e) {
      toast("bad", t("web.ws.connectFailed"), (e as Error).message);
    } finally {
      setBusy(false);
    }
  }
  async function send() {
    if (!session || !text) return;
    try {
      await client.call("ws.send", { sessionId: session.sessionId, ...(binary ? { base64: text.trim() } : { text }) });
      setText("");
    } catch (e) {
      toast("bad", t("web.sendFailed"), (e as Error).message);
    }
  }
  return (
    <div className="panel">
      <div className="panel-toolbar">
        <PlugZap size={14} />
        <input className="input sm mono" style={{ flex: 1, minWidth: 260 }} value={url} disabled={Boolean(session)} onChange={(e) => setUrl(e.target.value)} placeholder={t("web.ws.urlPlaceholder")} />
        {session ? (
          <button className="btn sm danger" onClick={() => client.call("ws.close", { sessionId: session.sessionId }).then(() => setSession(undefined))}><Plug size={12} /> {t("web.ws.disconnect")}</button>
        ) : (
          <button className="btn sm primary" disabled={busy || !/^wss?:\/\/./.test(url)} onClick={connect}><PlugZap size={12} /> {busy ? t("web.ws.connecting") : t("web.ws.connect")}</button>
        )}
        {session ? <span className="tag ok">{t("web.ws.connected")}</span> : null}
      </div>
      <div className="wsr-split">
        <div className="wsr-side">
          <div className="fz-label">{t("web.ws.handshakeHeaders")}</div>
          <textarea className="input mono" rows={8} disabled={Boolean(session)} value={headers} onChange={(e) => setHeaders(e.target.value)} placeholder={t("web.ws.headersPlaceholder")} />
          <span className="muted" style={{ fontSize: 11.5 }}>{t("web.ws.headersHelp")}</span>
        </div>
        <div className="wsr-main">
          {entryId ? <WsMessages entryId={entryId} /> : <div className="ic-empty">{t("web.ws.connectToSee")}</div>}
          <div className="wsr-compose">
            <textarea
              className="input mono"
              rows={3}
              disabled={!session}
              value={text}
              onChange={(e) => setText(e.target.value)}
              placeholder={binary ? t("web.ws.binaryPlaceholder") : t("web.ws.textPlaceholder")}
              onKeyDown={(e) => {
                if ((e.ctrlKey || e.metaKey) && e.key === "Enter") {
                  e.preventDefault();
                  void send();
                }
              }}
            />
            <div className="wsr-actions">
              <label className="check"><input type="checkbox" checked={binary} onChange={(e) => setBinary(e.target.checked)} /> {t("web.ws.binaryLabel")}</label>
              <button className="btn sm primary" disabled={!session || !text} onClick={send}><Send size={12} /> {t("common.send")}</button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
