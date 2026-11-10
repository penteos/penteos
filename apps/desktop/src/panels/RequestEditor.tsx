import { FileCheck2, Send, Zap } from "../ui/icons";
import { useState } from "react";
import { useApp } from "../state";
import { toast } from "../ui/bits";
import { t } from "../i18n";
import { risk as riskLabel } from "../labels";
import { HelpHint } from "../ui/HelpHint";

/** A Repeater: write a raw request, send it inside the scope, read the response, keep it as evidence. */

interface Sent {
  at: string;
  status?: number;
  statusText?: string;
  timeMs?: number;
  size?: number;
  headers?: string;
  body?: string;
  rawId?: string;
  runId?: string;
  error?: string;
}

const RISKS = ["passive", "active", "intrusive", "exploitation"];
const capitalized = (s: string) => s.charAt(0).toUpperCase() + s.slice(1);

function pretty(body: string, headers: string): string {
  if (/content-type:\s*[^\n]*json/i.test(headers)) {
    try {
      return JSON.stringify(JSON.parse(body), null, 2);
    } catch {
      return body;
    }
  }
  return body;
}

export function RequestEditorPanel(props: { params: { origin?: string; raw?: string } }) {
  const { client, workbench } = useApp();
  const [origin, setOrigin] = useState(props.params.origin ?? "http://");
  const [raw, setRaw] = useState(props.params.raw ?? "GET / HTTP/1.1\n\n");
  const [risk, setRisk] = useState("active");
  const [busy, setBusy] = useState(false);
  const [history, setHistory] = useState<Sent[]>([]);
  const [shown, setShown] = useState(0);
  const [view, setView] = useState<"body" | "headers">("body");
  const cur = history[shown];

  async function send() {
    setBusy(true);
    try {
      const r = await client.call<{ status: string; runId: string; rawId?: string; error?: string; response?: { status: number; statusText: string; timeMs: number; size: number; headers: string; body: string } }>("http.send", { origin, raw, risk });
      const s: Sent = { at: new Date().toISOString(), runId: r.runId, ...(r.rawId ? { rawId: r.rawId } : {}), ...(r.error ? { error: r.error } : {}), ...(r.response ?? {}) };
      setHistory((h) => [s, ...h].slice(0, 50));
      setShown(0);
    } catch (e) {
      toast("bad", t("web.sendFailed"), (e as Error).message);
    } finally {
      setBusy(false);
    }
  }
  async function evidence() {
    if (!cur?.rawId) return;
    const caption = window.prompt(t("web.evidence.prompt"), `${raw.split("\n")[0]} → ${cur.status}`);
    if (!caption) return;
    await client.call("evidence.from_raw", { rawId: cur.rawId, caption }).then(() => toast("ok", t("web.evidence.saved"), t("web.evidence.savedBody")), (e: Error) => toast("bad", t("common.error"), e.message));
  }

  return (
    <div className="panel">
      <div className="panel-toolbar">
        <Send size={14} />
        <input className="input sm mono" style={{ width: 280 }} value={origin} onChange={(e) => setOrigin(e.target.value)} placeholder={t("web.originPlaceholder")} />
        <select className="input sm" value={risk} onChange={(e) => setRisk(e.target.value)} title={t("web.req.riskTitle")}>
          {RISKS.map((k) => <option key={k} value={k}>{capitalized(riskLabel(k))}</option>)}
        </select>
        <button className="btn sm primary" disabled={busy} onClick={send}><Send size={12} /> {busy ? t("web.sending") : t("common.send")}</button>
        <HelpHint id="request" text={t("web.req.hint")} />
        <div style={{ flex: 1 }} />
        <button className="btn sm ghost" onClick={() => workbench.openFuzzer({ origin, template: raw })}><Zap size={12} /> {t("web.toFuzzer")}</button>
      </div>
      <div className="rep-split">
        <textarea
          className="rep-req mono"
          spellCheck={false}
          value={raw}
          onChange={(e) => setRaw(e.target.value)}
          onKeyDown={(e) => {
            if ((e.ctrlKey || e.metaKey) && e.key === "Enter") {
              e.preventDefault();
              void send();
            }
          }}
        />
        <div className="rep-res">
          {cur ? (
            <>
              <div className="rep-status">
                {cur.error ? <span className="tag bad">{t("web.error")}</span> : <span className={`tag ${cur.status! >= 500 ? "bad" : cur.status! >= 400 ? "warn" : "ok"}`}>{cur.status} {cur.statusText}</span>}
                {cur.timeMs !== undefined ? <span className="muted">{cur.timeMs} ms · {cur.size} bytes</span> : null}
                <div className="seg sm">
                  <button className={view === "body" ? "on" : ""} onClick={() => setView("body")}>{t("web.body")}</button>
                  <button className={view === "headers" ? "on" : ""} onClick={() => setView("headers")}>{t("web.headers")}</button>
                </div>
                <div className="grow" />
                {history.length > 1 ? (
                  <select className="input sm" value={shown} onChange={(e) => setShown(Number(e.target.value))}>
                    {history.map((h, i) => <option key={h.at} value={i}>#{history.length - i} · {h.status ?? t("web.error")} · {new Date(h.at).toLocaleTimeString()}</option>)}
                  </select>
                ) : null}
                {cur.rawId ? <button className="btn sm" onClick={evidence}><FileCheck2 size={12} /> {t("web.evidence.saveAs")}</button> : null}
              </div>
              <pre className="rep-body mono">{cur.error ?? (view === "body" ? pretty(cur.body ?? "", cur.headers ?? "") : cur.headers)}</pre>
            </>
          ) : (
            <div className="graph-empty">{t("web.req.empty")}</div>
          )}
        </div>
      </div>
    </div>
  );
}
