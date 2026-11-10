import { OctagonX } from "../ui/icons";
import { useState } from "react";
import type { CoreClient } from "../client";
import { ProjectWizard } from "../ProjectWizard";
import { MODES } from "../modes";
import { useApp } from "../state";
import { Modal, toast } from "../ui/bits";
import { t, tn } from "../i18n";

export function StopWorkModal(props: { onClose: () => void }) {
  const { engagement, client } = useApp();
  const active = Boolean(engagement?.stopWork?.active);
  const [reason, setReason] = useState("");
  async function confirm() {
    try {
      const r = await client.call<{ cancelledRuns: number }>(active ? "engagement.resume_work" : "engagement.stop_work", active ? {} : { reason: reason || t("shell.stop.defaultReason") });
      toast(active ? "ok" : "bad", active ? t("shell.stop.resumed") : t("shell.stop.activated"), active ? undefined : tn("shell.stop.cancelled", r.cancelledRuns));
      props.onClose();
    } catch (e) {
      toast("bad", t("common.error"), (e as Error).message);
    }
  }
  return (
    <Modal
      title={active ? t("shell.stop.resumeTitle") : t("shell.stop.activateTitle")}
      icon={<OctagonX size={16} color="var(--bad)" />}
      onClose={props.onClose}
      footer={
        <>
          <button className="btn ghost" onClick={props.onClose}>{t("common.cancel")}</button>
          <button className={`btn ${active ? "primary" : "danger"}`} onClick={confirm}>{active ? t("common.resume") : t("shell.stop.stopAll")}</button>
        </>
      }
    >
      {active ? (
        <span>{t("shell.stop.activeText", { reason: engagement?.stopWork?.reason })}</span>
      ) : (
        <>
          <span>{t("shell.stop.explain")}</span>
          <input className="input" autoFocus placeholder={t("shell.stop.reason")} value={reason} onChange={(e) => setReason(e.target.value)} onKeyDown={(e) => e.key === "Enter" && confirm()} />
        </>
      )}
    </Modal>
  );
}


export function HelpModal(props: { kind: "modes" | "keys" | "about"; onClose: () => void }) {
  const keys: Array<[string, string]> = [
    ["Ctrl+K", t("shell.keys.palette")],
    ["Ctrl+N", t("shell.palette.newProject")],
    ["Ctrl+W", t("shell.keys.closeTab")],
    ["Ctrl+J", t("shell.keys.bottom")],
    ["Ctrl+L", t("shell.keys.agent")],
    ["Ctrl+`", t("shell.keys.terminal")],
    ["Enter / Shift+Enter", t("shell.keys.chat")],
  ];
  return (
    <Modal
      title={props.kind === "modes" ? t("shell.help.modes") : props.kind === "keys" ? t("shell.help.keys") : t("shell.help.about")}
      onClose={props.onClose}
      footer={<button className="btn primary" onClick={props.onClose}>{t("common.close")}</button>}
    >
      {props.kind === "modes" ? (
        <div className="help-modes">
          {Object.values(MODES).map((m) => (
            <div key={m.id}>
              <b>{m.title}</b> <span className="muted">- {m.tagline}</span>
              <ul>{m.explain.map((x) => <li key={x}>{x}</li>)}</ul>
            </div>
          ))}
          <p className="muted">{t("shell.help.modesNote")}</p>
        </div>
      ) : props.kind === "keys" ? (
        <table className="tbl">
          <tbody>{keys.map(([k, d]) => <tr key={k}><td className="mono" style={{ width: 150 }}>{k}</td><td>{d}</td></tr>)}</tbody>
        </table>
      ) : (
        <span>{t("shell.help.aboutText")}</span>
      )}
    </Modal>
  );
}

