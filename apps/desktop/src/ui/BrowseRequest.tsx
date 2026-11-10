import { AppWindow } from "./icons";
import { useState } from "react";
import { browseOf, openBrowseRequest, respondBrowse } from "../browse";
import { type Entity, useApp } from "../state";
import { toast } from "./bits";
import { t } from "../i18n";

/**
 * What the Maestro needs the operator to browse: where, the steps, and the decision. Before the
 * browser is open: open it (white) or not now. Once open: done (white), open again, not now.
 */
export function BrowseRequest(props: { task: Entity }) {
  const { client, engagement } = useApp();
  const [busy, setBusy] = useState(false);
  const b = browseOf(props.task);
  if (!b) return null;
  const started = props.task.attributes.status === "in_progress";

  async function run(fn: () => Promise<void>) { // i18n-ignore: type argument, not text
    setBusy(true);
    try {
      await fn();
    } catch (e) {
      toast("bad", t("work.browse.failed"), (e as Error).message);
    } finally {
      setBusy(false);
    }
  }
  const openIt = () => run(() => openBrowseRequest(client, engagement, props.task));
  const done = () => run(() => respondBrowse(client, props.task.id, "done"));
  const decline = () => run(() => respondBrowse(client, props.task.id, "declined"));

  return (
    <div className="browse-req" onMouseDown={(e) => e.stopPropagation()} draggable={false} onDragStart={(e) => e.preventDefault()}>
      <div className="br-head"><AppWindow size={12} /> <span>{String(props.task.attributes.title)}</span></div>
      <div className="br-url mono" title={b.url}>{b.url}</div>
      <ol className="br-steps">
        {b.steps.map((s, i) => (
          <li key={i}><span className="n mono">{String(i + 1).padStart(2, "0")}</span><span>{s}</span></li>
        ))}
      </ol>
      <div className="br-actions">
        {started ? (
          <>
            <button className="btn sm primary" disabled={busy} onClick={done}>{t("work.browse.done")}</button>
            <button className="btn sm" disabled={busy} onClick={openIt}>{t("work.browse.reopen")}</button>
            <button className="btn sm ghost" disabled={busy} onClick={decline}>{t("work.browse.notNow")}</button>
          </>
        ) : (
          <>
            <button className="btn sm primary" disabled={busy} onClick={openIt}>{t("work.browse.open")}</button>
            <button className="btn sm" disabled={busy} onClick={decline}>{t("work.browse.notNow")}</button>
          </>
        )}
      </div>
    </div>
  );
}
