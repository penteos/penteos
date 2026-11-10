import { Download, Search } from "../ui/icons";
import { useMemo, useState } from "react";
import { useApp, useOperation } from "../state";
import { relTime, toast, useTick } from "../ui/bits";
import { locale, t, tn } from "../i18n";

/** The operator log: every run, as a table in the bottom panel, exportable. */

function download(name: string, text: string, type = "text/csv") {
  const url = URL.createObjectURL(new Blob([text], { type }));
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
}

export function OperatorLogPanel() {
  const { client } = useApp();
  const rows = useOperation<Array<Record<string, string>>>("log.timeline", { limit: 2000 }, { refreshOn: (e) => e.type === "run.started" || e.type === "run.finished" });
  const [q, setQ] = useState("");
  const list = useMemo(() => {
    const needle = q.trim().toLowerCase();
    const all = [...(rows.data ?? [])].reverse();
    return needle ? all.filter((r) => [r.operator, r.attack, r.command, r.targets, r.status].join(" ").toLowerCase().includes(needle)) : all;
  }, [rows.data, q]);
  async function exportAs(format: "csv" | "json") {
    const stamp = new Date().toISOString().slice(0, 10);
    if (format === "csv") {
      const r = await client.call<{ csv: string }>("log.timeline", { format: "csv", limit: 100000 });
      download(`${t("ops.log.fileName")}-${stamp}.csv`, r.csv);
    } else {
      const r = await client.call<unknown>("log.timeline", { format: "json", limit: 100000 });
      download(`${t("ops.log.fileName")}-${stamp}.json`, JSON.stringify(r, null, 2), "application/json");
    }
  }
  const time = (iso: string) => (iso ? new Date(iso).toLocaleString(locale(), { month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit" }) : "");
  return (
    <div className="log-panel">
      <div className="log-head">
        <div className="search-box">
          <Search size={12} />
          <input placeholder={t("ops.log.filter")} value={q} onChange={(e) => setQ(e.target.value)} />
        </div>
        <span className="muted">{tn("ops.log.count", list.length)}</span>
        <div className="grow" />
        <button className="btn sm ghost" onClick={() => exportAs("json")}><Download size={12} /> JSON</button>
        <button className="btn sm" onClick={() => exportAs("csv")}><Download size={12} /> {t("ops.log.csv")}</button>
      </div>
      <div className="table-wrap">
        <table className="tbl dense">
          <thead>
            <tr><th style={{ width: 150 }}>{t("ops.log.col.time")}</th><th style={{ width: 130 }}>{t("ops.log.col.operator")}</th><th style={{ width: 100 }}>{t("ops.log.col.technique")}</th><th>{t("ops.log.col.command")}</th><th style={{ width: 200 }}>{t("ops.log.col.targets")}</th><th style={{ width: 110 }}>{t("ops.log.col.result")}</th></tr>
          </thead>
          <tbody>
            {list.map((r, i) => (
              <tr key={i} className={r.status === "denied" ? "denied" : ""}>
                <td className="mono muted nowrap">{time(r.startedAt ?? "")}</td>
                <td className="nowrap">{r.operator}</td>
                <td className="mono">{r.attack ? <span className="tag">{r.attack}</span> : <span className="muted">-</span>}</td>
                <td className="mono cmd" title={r.command}>{r.command}</td>
                <td className="mono muted" title={r.targets}>{r.targets}</td>
                <td title={r.reason}>{r.status === "denied" ? <span className="tag bad">{t("ops.log.denied")}</span> : r.status === "finished" ? <span className="tag ok">{t("ops.log.ok")}</span> : <span className="tag">{r.status}</span>}</td>
              </tr>
            ))}
            {list.length === 0 ? <tr><td colSpan={6} className="muted" style={{ padding: 14 }}>{t("ops.log.empty")}</td></tr> : null}
          </tbody>
        </table>
      </div>
    </div>
  );
}

