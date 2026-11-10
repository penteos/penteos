/** Updates: a quiet card when a newer Penteos exists; installing waits for the operator's click. */
import { useEffect, useState } from "react";
import { t } from "../i18n";
import { toast } from "./bits";

export interface UpdateState {
  status: "idle" | "checking" | "current" | "available" | "downloading" | "installing" | "restarting" | "error";
  current: string;
  latest?: string;
  notes?: string;
  url?: string;
  /** How this copy was installed: what "Update" will do. */
  kind?: "appimage" | "deb" | "rpm" | "mac" | "manual";
  progress?: number;
  error?: string;
  automatic?: boolean;
}

const desktop = () => window.penteosDesktop?.updates;

export function useUpdates(): UpdateState | undefined {
  const [state, setState] = useState<UpdateState>();
  useEffect(() => {
    const u = desktop();
    if (!u) return;
    void u.state().then(setState);
    return u.onState(setState);
  }, []);
  return state;
}

/** Help, Check for updates: says the result even when there is nothing new. */
export async function checkForUpdates() {
  const u = desktop();
  if (!u) return;
  const s = await u.check();
  if (s.status === "current") toast("ok", t("shell.update.current", { version: s.current }));
  else if (s.status === "error") toast("bad", t("shell.update.checkFailed"), s.error);
}

export async function setAutomaticUpdates(on: boolean) {
  await desktop()?.setAutomatic(on);
}

export function UpdateNotice() {
  const s = useUpdates();
  const [hidden, setHidden] = useState<string>();
  if (!s || !s.latest || hidden === s.latest) return null;
  if (!["available", "downloading", "installing", "restarting", "error"].includes(s.status)) return null;
  if (s.status === "error" && !s.latest) return null;
  const busy = s.status === "downloading" || s.status === "installing" || s.status === "restarting";
  const action = s.kind === "manual" ? t("shell.update.download") : s.kind === "deb" || s.kind === "rpm" ? t("shell.update.installSystem") : t("shell.update.install");
  return (
    <div className="update-card" role="status">
      <div className="update-head">
        <b>{t("shell.update.available", { version: s.latest })}</b>
        <span className="muted">{t("shell.update.youHave", { version: s.current })}</span>
      </div>
      {s.status === "downloading" ? <div className="update-bar"><i style={{ width: `${s.progress ?? 0}%` }} /></div> : null}
      <span className="muted update-line">
        {s.status === "downloading"
          ? t("shell.update.downloading", { pct: s.progress ?? 0 })
          : s.status === "installing"
            ? t("shell.update.installing")
            : s.status === "restarting"
              ? t("shell.update.restarting")
              : s.status === "error"
                ? t("shell.update.failed", { error: s.error ?? "" })
                : s.kind === "deb" || s.kind === "rpm"
                  ? t("shell.update.systemNote")
                  : s.kind === "manual"
                    ? t("shell.update.manualNote")
                    : t("shell.update.appimageNote")}
      </span>
      <div className="update-actions">
        <button className="btn sm primary" disabled={busy} onClick={() => void desktop()?.apply()}>
          {action}
        </button>
        {s.url ? (
          <a className="btn sm ghost" href={s.url} target="_blank" rel="noreferrer">
            {t("shell.update.notes")}
          </a>
        ) : null}
        <button className="btn sm ghost" disabled={busy} onClick={() => setHidden(s.latest)}>
          {t("shell.update.later")}
        </button>
      </div>
    </div>
  );
}
