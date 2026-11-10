import { Eraser, Play, Square, Wand2, Zap } from "../ui/icons";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useApp } from "../state";
import { toast } from "../ui/bits";
import { t, tn } from "../i18n";
import { risk as riskLabel, anomaly } from "../labels";

/**
 * The fuzzer (Intruder-style): mark positions with §, choose payloads and an attack type, and
 * read what came back different from the original request.
 */

type Attack = "sniper" | "battering_ram" | "pitchfork" | "cluster_bomb";
type SourceType = "list" | "numbers" | "file" | "builtin";
interface SetConfig {
  type: SourceType;
  list: string;
  from: number;
  to: number;
  step: number;
  pad: number;
  path: string;
  builtin: string;
  prefix: string;
  suffix: string;
  encode: "none" | "url" | "url_all" | "base64" | "hex" | "html";
}
interface Row {
  index: number;
  payloads: string[];
  position?: number;
  status?: number;
  length: number;
  words: number;
  lines: number;
  timeMs: number;
  error?: string;
  matches: string[];
  extracted?: string;
  anomalies: string[];
  rawId?: string;
}
interface Results {
  status: string;
  done: number;
  total: number | null;
  anomalies: number;
  matching: number;
  rows: Row[];
}

/** Attack names are the usual Intruder terms and stay as they are; the description is web.fz.attack.<id>. */
const ATTACKS: Array<[Attack, string]> = [
  ["sniper", "Sniper"],
  ["battering_ram", "Battering ram"],
  ["pitchfork", "Pitchfork"],
  ["cluster_bomb", "Cluster bomb"],
];
const attackHelp = (a: Attack) => t(`web.fz.attack.${a}`);
/** Built-in list name (sent to the core) → catalog key of its label. */
const BUILTINS: Array<[string, string]> = [
  ["usuarios", "web.fz.builtin.users"],
  ["contraseñas_debiles", "web.fz.builtin.weakPasswords"],
  ["rutas", "web.fz.builtin.paths"],
  ["metodos", "web.fz.builtin.methods"],
  ["booleanos", "web.fz.builtin.booleans"],
];
const capitalized = (s: string) => s.charAt(0).toUpperCase() + s.slice(1);
const emptySet = (): SetConfig => ({ type: "list", list: "", from: 1, to: 100, step: 1, pad: 0, path: "/usr/share/seclists/", builtin: "usuarios", prefix: "", suffix: "", encode: "none" });

function countPositions(t: string): number {
  return Math.floor((t.split("§").length - 1) / 2);
}

function toSource(c: SetConfig) {
  if (c.type === "list") return { type: "list", items: c.list.split("\n").map((l) => l.replace(/\r$/, "")).filter((l) => l.length > 0) };
  if (c.type === "numbers") return { type: "numbers", from: c.from, to: c.to, step: c.step || 1, ...(c.pad ? { pad: c.pad } : {}) };
  if (c.type === "file") return { type: "file", path: c.path.trim() };
  return { type: "builtin", name: c.builtin };
}

function estimate(c: SetConfig): number | undefined {
  if (c.type === "list") return c.list.split("\n").filter((l) => l.trim()).length;
  if (c.type === "numbers") return Math.floor(Math.abs(c.to - c.from) / Math.max(1, Math.abs(c.step || 1))) + 1;
  if (c.type === "builtin") return ({ usuarios: 15, contraseñas_debiles: 15, rutas: 25, metodos: 8, booleanos: 10 } as Record<string, number>)[c.builtin];
  return undefined;
}

/** Marks every query and form value as a position. */
function autoMark(t: string): string {
  const clean = t.replace(/§/g, "");
  const [head, ...rest] = clean.split(/\n\n/);
  const markValues = (s: string) => s.replace(/([?&]|^)([^=&?\s]+)=([^&\s#]*)/g, (_m, sep: string, k: string, v: string) => `${sep}${k}=§${v}§`);
  const lines = head!.split("\n");
  lines[0] = lines[0]!.replace(/^(\S+\s+)(\S+)/, (_m, a: string, path: string) => {
    const q = path.indexOf("?");
    return q < 0 ? a + path : `${a}${path.slice(0, q + 1)}${markValues(path.slice(q + 1))}`;
  });
  const body = rest.join("\n\n");
  const ct = /content-type:\s*application\/x-www-form-urlencoded/i.test(head!);
  return `${lines.join("\n")}${rest.length ? `\n\n${ct && body ? markValues(body) : body}` : ""}`;
}

function SetEditor(props: { index: number; c: SetConfig; onChange: (c: SetConfig) => void; label: string }) {
  const { c } = props;
  const set = (patch: Partial<SetConfig>) => props.onChange({ ...c, ...patch });
  const n = estimate(c);
  return (
    <div className="fz-set">
      <div className="fz-set-head">
        <b>{props.label}</b>
        <select className="input sm" value={c.type} onChange={(e) => set({ type: e.target.value as SourceType })}>
          <option value="list">{t("web.fz.source.list")}</option>
          <option value="numbers">{t("web.fz.source.numbers")}</option>
          <option value="file">{t("web.fz.source.file")}</option>
          <option value="builtin">{t("web.fz.source.builtin")}</option>
        </select>
        <span className="muted">{n !== undefined ? tn("web.fz.payloads", n) : ""}</span>
      </div>
      {c.type === "list" ? <textarea className="input mono" rows={5} placeholder={t("web.fz.listPlaceholder")} value={c.list} onChange={(e) => set({ list: e.target.value })} /> : null}
      {c.type === "numbers" ? (
        <div className="fz-row">
          <label>{t("web.fz.from")}<input className="input sm" type="number" value={c.from} onChange={(e) => set({ from: Number(e.target.value) })} /></label>
          <label>{t("web.fz.to")}<input className="input sm" type="number" value={c.to} onChange={(e) => set({ to: Number(e.target.value) })} /></label>
          <label>{t("web.fz.step")}<input className="input sm" type="number" value={c.step} onChange={(e) => set({ step: Number(e.target.value) })} /></label>
          <label>{t("web.fz.pad")}<input className="input sm" type="number" min={0} max={20} value={c.pad} onChange={(e) => set({ pad: Number(e.target.value) })} /></label>
        </div>
      ) : null}
      {c.type === "file" ? (
        <input className="input sm mono" placeholder="/usr/share/seclists/Discovery/Web-Content/common.txt" value={c.path} onChange={(e) => set({ path: e.target.value })} /* i18n-ignore: example path */ />
      ) : null}
      {c.type === "builtin" ? (
        <select className="input sm" value={c.builtin} onChange={(e) => set({ builtin: e.target.value })}>
          {BUILTINS.map(([k, v]) => <option key={k} value={k}>{t(v)}</option>)}
        </select>
      ) : null}
      <div className="fz-row">
        <label>{t("web.fz.prefix")}<input className="input sm mono" value={c.prefix} onChange={(e) => set({ prefix: e.target.value })} /></label>
        <label>{t("web.fz.suffix")}<input className="input sm mono" value={c.suffix} onChange={(e) => set({ suffix: e.target.value })} /></label>
        <label>{t("web.fz.encode")}
          <select className="input sm" value={c.encode} onChange={(e) => set({ encode: e.target.value as SetConfig["encode"] })}>
            <option value="none">{t("web.fz.encode.none")}</option>
            <option value="url">URL</option>
            <option value="url_all">{t("web.fz.encode.urlAll")}</option>
            <option value="base64">Base64</option>{/* i18n-ignore: encoding name */}
            <option value="hex">Hex</option>{/* i18n-ignore: encoding name */}
            <option value="html">HTML</option>
          </select>
        </label>
      </div>
    </div>
  );
}

export function FuzzerPanel(props: { params: { origin?: string; template?: string; runId?: string } }) {
  const { client } = useApp();
  const [origin, setOrigin] = useState(props.params.origin ?? "http://");
  // Positions the operator already marked are kept; otherwise every parameter value is marked.
  const [template, setTemplate] = useState(() => (!props.params.template ? "GET /?id=§1§ HTTP/1.1\n\n" : props.params.template.includes("§") ? props.params.template : autoMark(props.params.template)));
  const [attack, setAttack] = useState<Attack>("sniper");
  const [sets, setSets] = useState<SetConfig[]>([emptySet()]);
  const [grep, setGrep] = useState("");
  const [extract, setExtract] = useState("");
  const [concurrency, setConcurrency] = useState(5);
  const [delay, setDelay] = useState(0);
  const [maxRequests, setMaxRequests] = useState(10000);
  const [risk, setRisk] = useState("intrusive");
  const [runId, setRunId] = useState<string | undefined>(props.params.runId);
  const [results, setResults] = useState<Results>();
  const [onlyAnomalies, setOnlyAnomalies] = useState(false);
  const [sort, setSort] = useState<"index" | "status" | "length" | "time">("index");
  const [selected, setSelected] = useState<number>();
  const [raw, setRaw] = useState<string>();
  const area = useRef<HTMLTextAreaElement>(null);

  const positions = countPositions(template);
  const needed = attack === "sniper" || attack === "battering_ram" ? 1 : Math.max(1, positions);
  useEffect(() => {
    setSets((s) => (s.length >= needed ? s : [...s, ...Array.from({ length: needed - s.length }, emptySet)]));
  }, [needed]);

  const total = useMemo(() => {
    const ns = sets.slice(0, needed).map(estimate);
    if (ns.some((n) => n === undefined)) return undefined;
    const v = ns as number[];
    if (attack === "sniper") return positions * v[0]!;
    if (attack === "battering_ram") return v[0]!;
    if (attack === "pitchfork") return Math.min(...v);
    return v.reduce((a, b) => a * b, 1);
  }, [sets, needed, attack, positions]);

  const load = useCallback(() => {
    if (!runId) return;
    client.call<Results>("fuzz.results", { runId, onlyAnomalies, sort, limit: 2000 }).then(setResults, () => {});
  }, [client, runId, onlyAnomalies, sort]);

  useEffect(() => {
    load();
    let timer: ReturnType<typeof setTimeout> | undefined;
    const off = client.onEvent((e) => {
      if ((e.type === "fuzz.progress" && e.runId === runId) || (e.type === "run.finished" && e.id === runId)) {
        clearTimeout(timer);
        timer = setTimeout(load, 200);
      }
    });
    return () => {
      clearTimeout(timer);
      off();
    };
  }, [client, runId, load]);

  const sel = results?.rows.find((r) => r.index === selected);
  useEffect(() => {
    setRaw(undefined);
    if (!sel?.rawId) return;
    client.call<{ content: string }>("raw.get", { rawId: sel.rawId, length: 200_000 }).then((r) => setRaw(r.content), () => setRaw(t("web.fz.unavailable")));
  }, [sel?.rawId, client]);

  function wrapSelection() {
    const el = area.current;
    if (!el) return;
    const a = el.selectionStart;
    const b = el.selectionEnd;
    const next = `${template.slice(0, a)}§${template.slice(a, b)}§${template.slice(b)}`;
    setTemplate(next);
    setTimeout(() => el.setSelectionRange(a + 1, b + 1), 0);
  }

  async function start() {
    try {
      const r = await client.call<{ status: string; runId?: string; approvalId?: string }>("fuzz.start", {
        origin,
        template,
        attack,
        sets: sets.slice(0, needed).map(toSource),
        processing: sets.slice(0, needed).map((c) => ({ ...(c.prefix ? { prefix: c.prefix } : {}), ...(c.suffix ? { suffix: c.suffix } : {}), encode: c.encode })),
        grep: grep.split("\n").map((g) => g.trim()).filter(Boolean),
        ...(extract.trim() ? { extract: extract.trim() } : {}),
        concurrency,
        delayMs: delay,
        maxRequests,
        risk,
      });
      if (r.runId) {
        setRunId(r.runId);
        setResults(undefined);
        setSelected(undefined);
      } else toast("info", t("web.pendingApproval"), t("web.fz.pendingBody"));
    } catch (e) {
      toast("bad", t("web.fz.startFailed"), (e as Error).message);
    }
  }
  const running = results?.status === "running";
  const pct = results?.total ? Math.round((results.done / results.total) * 100) : 0;

  return (
    <div className="panel">
      <div className="panel-toolbar">
        <Zap size={14} />
        <input className="input sm mono" style={{ width: 260 }} value={origin} onChange={(e) => setOrigin(e.target.value)} placeholder={t("web.originPlaceholder")} />
        <select className="input sm" value={attack} onChange={(e) => setAttack(e.target.value as Attack)} title={attackHelp(attack)}>
          {ATTACKS.map(([k, l]) => <option key={k} value={k}>{l}</option>)}
        </select>
        <select className="input sm" value={risk} onChange={(e) => setRisk(e.target.value)} title={t("web.fz.riskTitle")}>
          {["active", "intrusive", "exploitation"].map((k) => <option key={k} value={k}>{capitalized(riskLabel(k))}</option>)}
        </select>
        <span className="muted">{tn("web.fz.positions", positions)}{total !== undefined ? ` · ${tn("web.fz.requests", total + 1)}` : ""}</span>
        <div className="grow" />
        {running ? (
          <button className="btn sm danger" onClick={() => runId && client.call("run.cancel", { runId })}><Square size={12} /> {t("common.stop")}</button>
        ) : (
          <button className="btn sm primary" disabled={positions === 0} onClick={start}><Play size={12} /> {t("web.fz.start")}</button>
        )}
      </div>
      {results ? (
        <div className="fz-progress">
          <div className="bar"><div style={{ width: `${pct}%` }} className={running ? "run" : ""} /></div>
          <span className="muted">
            {results.done}/{results.total ?? "?"} · <b className={results.anomalies ? "warn" : ""}>{tn("web.fz.anomalies", results.anomalies)}</b> · {results.status === "running" ? t("web.fz.status.running") : results.status === "cancelled" ? t("web.fz.status.cancelled") : t("web.fz.status.done")}
          </span>
        </div>
      ) : null}
      <div className="fz-split">
        <div className="fz-config">
          <div className="fz-block">
            <div className="fz-label">
              {t("web.fz.template")} <span className="muted">{t("web.fz.templateHint")}</span>
              <div className="grow" />
              <button className="btn sm ghost" onClick={wrapSelection} title={t("web.fz.markTitle")}><span className="mono">§</span> {t("web.fz.mark")}</button>
              <button className="btn sm ghost" onClick={() => setTemplate(autoMark(template))} title={t("web.fz.autoTitle")}><Wand2 size={12} /> {t("web.fz.auto")}</button>
              <button className="btn sm ghost" onClick={() => setTemplate(template.replace(/§/g, ""))}><Eraser size={12} /> {t("web.fz.clear")}</button>
            </div>
            <textarea ref={area} className="input mono fz-template" spellCheck={false} value={template} onChange={(e) => setTemplate(e.target.value)} />
            <span className="muted" style={{ fontSize: 11.5 }}>{attackHelp(attack)} {t("web.fz.secretHint")}</span>
          </div>
          {sets.slice(0, needed).map((c, i) => (
            <SetEditor key={i} index={i} c={c} label={needed === 1 ? t("web.fz.payloadsLabel") : t("web.fz.position", { n: i + 1 })} onChange={(n) => setSets((s) => s.map((x, j) => (j === i ? n : x)))} />
          ))}
          <div className="fz-block">
            <div className="fz-label">{t("web.fz.grep")}</div>
            <span className="muted" style={{ fontSize: 11.5 }}>{t("web.fz.grepHelp")}</span>
            <textarea className="input mono" rows={3} value={grep} onChange={(e) => setGrep(e.target.value)} placeholder={"error\n/token=\\w+/"} />
            <label className="fz-inline">{t("web.fz.extract")}<input className="input sm mono" value={extract} onChange={(e) => setExtract(e.target.value)} placeholder={'csrf_token" value="(\\w+)'} /></label>
          </div>
          <div className="fz-row">
            <label>{t("web.fz.concurrency")}<input className="input sm" type="number" min={1} max={20} value={concurrency} onChange={(e) => setConcurrency(Number(e.target.value))} /></label>
            <label>{t("web.fz.delay")}<input className="input sm" type="number" min={0} value={delay} onChange={(e) => setDelay(Number(e.target.value))} /></label>
            <label>{t("web.fz.maxRequests")}<input className="input sm" type="number" min={1} max={100000} value={maxRequests} onChange={(e) => setMaxRequests(Number(e.target.value))} /></label>
          </div>
        </div>
        <div className="fz-results">
          <div className="fz-rhead">
            <label className="check"><input type="checkbox" checked={onlyAnomalies} onChange={(e) => setOnlyAnomalies(e.target.checked)} /> {t("web.fz.onlyAnomalies")}</label>
            <span className="muted">{t("web.fz.sort")}</span>
            <div className="seg sm">
              {(["index", "status", "length", "time"] as const).map((k) => <button key={k} className={sort === k ? "on" : ""} onClick={() => setSort(k)}>{{ index: "#", status: t("web.status"), length: t("web.size"), time: t("web.fz.time") }[k]}</button>)}
            </div>
          </div>
          <div className="fz-table">
            <table className="tbl dense">
              <thead>
                <tr><th style={{ width: 50 }}>#</th><th>{t("web.fz.col.payload")}</th><th style={{ width: 60 }}>{t("web.status")}</th><th style={{ width: 70 }}>{t("web.size")}</th><th style={{ width: 60 }}>{t("web.fz.col.words")}</th><th style={{ width: 60 }}>{t("web.ms")}</th><th>{t("web.fz.col.found")}</th><th>{t("web.fz.col.anomalies")}</th></tr>
              </thead>
              <tbody>
                {(results?.rows ?? []).map((r) => (
                  <tr key={r.index} className={`px-row ${selected === r.index ? "on" : ""} ${r.index === 0 ? "fz-base" : ""}`} onClick={() => setSelected(r.index)}>
                    <td className="mono muted">{r.index === 0 ? t("web.fz.base") : r.index}</td>
                    <td className="mono cmd" title={r.payloads.join(" | ")}>{r.payloads.join(" | ")}{r.position !== undefined ? <span className="muted">{t("web.fz.pos", { n: r.position + 1 })}</span> : null}</td>
                    <td>{r.error ? <span className="tag bad">{t("web.error")}</span> : <span className={`tag ${!r.status ? "" : r.status >= 500 ? "bad" : r.status >= 400 ? "warn" : r.status >= 300 ? "accent" : "ok"}`}>{r.status}</span>}</td>
                    <td className="mono">{r.length}</td>
                    <td className="mono muted">{r.words}</td>
                    <td className="mono muted">{r.timeMs}</td>
                    <td className="mono" title={r.extracted ?? r.matches.join(", ")}>{r.extracted ?? r.matches.join(", ")}</td>
                    <td>{r.anomalies.map((a) => <span key={a} className="tag warn" style={{ marginRight: 3 }}>{anomaly(a)}</span>)}</td>
                  </tr>
                ))}
                {!results ? <tr><td colSpan={8} className="px-empty">{t("web.fz.empty")}</td></tr> : null}
              </tbody>
            </table>
          </div>
          {sel ? <pre className="px-raw mono fz-raw">{sel.error ? sel.error : raw ?? (sel.rawId ? t("common.loading") : t("web.fz.notStored"))}</pre> : null}
        </div>
      </div>
    </div>
  );
}
