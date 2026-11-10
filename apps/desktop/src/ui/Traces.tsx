import { Check, Footprints, RotateCcw } from "./icons";
import { useApp, useOperation } from "../state";
import { toast } from "./bits";
import { t } from "../i18n";

/** What the tests left in the client's systems, and whether it was cleaned (it goes to the report). */

export interface Trace {
  id: string;
  what: string;
  where: string;
  cleanup?: string;
  status: "pending" | "cleaned" | "accepted";
}

export function useTraces() {
  return useOperation<Trace[]>("trace.list", {}, { refreshOn: (e) => e.type === "traces.changed" });
}

export function TracesSection() {
  const { client } = useApp();
  const { data } = useTraces();
  const list = data ?? [];
  if (!list.length) return null;
  const set = (id: string, status: Trace["status"]) => client.call("trace.resolve", { id, status }).catch((e: Error) => toast("bad", t("ops.traces.failed"), e.message));
  return (
    <section>
      <h2><Footprints size={14} /> {t("ops.traces.title")}</h2>
      <p className="muted">{t("ops.traces.intro")}</p>
      <div className="traces">
        {list.map((tr) => (
          <div key={tr.id} className={`trace ${tr.status}`}>
            <div className="tr-body">
              <div className="tr-what">{tr.what}</div>
              <div className="tr-where mono">{tr.where}</div>
              {tr.cleanup ? <div className="tr-clean">{t("ops.traces.cleanup", { how: tr.cleanup })}</div> : null}
            </div>
            <div className="tr-actions">
              {tr.status === "pending" ? (
                <>
                  <button className="btn sm" onClick={() => void set(tr.id, "cleaned")}><Check size={12} /> {t("ops.traces.cleaned")}</button>
                  <button className="btn sm ghost" onClick={() => void set(tr.id, "accepted")}>{t("ops.traces.accepted")}</button>
                </>
              ) : (
                <>
                  <span className={`tr-state ${tr.status}`}>{t(`ops.traces.state.${tr.status}`)}</span>
                  <button className="icon-btn" title={t("ops.traces.reopen")} aria-label={t("ops.traces.reopen")} onClick={() => void set(tr.id, "pending")}><RotateCcw size={12} /></button>
                </>
              )}
            </div>
          </div>
        ))}
      </div>
    </section>
  );
}
