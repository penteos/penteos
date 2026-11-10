import { useEffect, useState } from "react";
import { Puzzle, ShieldAlert } from "./icons";
import { useApp } from "../state";
import { Modal, toast } from "./bits";
import { t } from "../i18n";

/**
 * What the operator learns at start about plugins: the ones the host
 * disabled on its own and why, with a way back; and a bar while the app runs in safe mode.
 */

interface Notice {
  id: string;
  name: string;
  code: string;
  detail?: string;
  at: string;
}

interface Notices {
  safeMode: boolean;
  autoSafeMode: boolean;
  stateReset: boolean;
  items: Notice[];
}

/** Failures the operator can try again; the rest need the plugin fixed or approved again first. */
const RETRYABLE = new Set(["CRASH_ON_ACTIVATE", "ACTIVATION_FAILED", "STORAGE_FAILED", "ACTIVATION_TIMEOUT", "TOO_MANY_ERRORS", "TOO_MANY_TIMEOUTS", "TOO_MANY_CRASHES"]);

export function PluginNotices() {
  const { client } = useApp();
  const [notices, setNotices] = useState<Notices>();
  const [open, setOpen] = useState(false);
  const [logs, setLogs] = useState<Record<string, string[]>>({});

  useEffect(() => {
    const load = () =>
      client.call<Notices>("plugin.notices").then(
        (n) => {
          setNotices(n);
          if (n.items.length || n.autoSafeMode || n.stateReset) setOpen(true);
        },
        // A core that cannot answer has nothing to say.
        () => undefined,
      );
    void load();
    return client.onEvent((e) => {
      if (e.type === "plugins.changed") void load();
    });
  }, [client]);

  const enable = (n: Notice) =>
    client.call("plugin.enable", { id: n.id }).then(
      () => {
        toast("ok", t("shell.plugins.enabled"), n.name);
        setNotices((cur) => (cur ? { ...cur, items: cur.items.filter((i) => i.id !== n.id) } : cur));
      },
      (e: Error) => toast("bad", t("shell.plugins.enableFailed"), e.message),
    );
  const toggleLog = (n: Notice) => {
    if (logs[n.id]) {
      setLogs(({ [n.id]: _gone, ...rest }) => rest);
      return;
    }
    void client.call<{ lines: string[] }>("plugin.log", { id: n.id, lines: 30 }).then((r) => setLogs((cur) => ({ ...cur, [n.id]: r.lines })), () => undefined);
  };
  const dismiss = () => {
    setOpen(false);
    void client.call("plugin.dismiss_notices").catch(() => undefined);
  };
  const restartNormal = () => void window.penteosDesktop?.restart?.({ safeMode: false });

  if (!notices) return null;
  return (
    <>
      {notices.safeMode ? (
        <div className="safe-banner" role="status">
          <ShieldAlert size={13} />
          <span>{t("shell.plugins.banner")}</span>
          {window.penteosDesktop?.restart ? <button className="btn sm" onClick={restartNormal}>{t("shell.plugins.restartNormal")}</button> : null}
        </div>
      ) : null}
      {open ? (
        <Modal
          title={notices.safeMode && !notices.items.length ? t("shell.plugins.safe.title") : t("shell.plugins.notices.title")}
          icon={<Puzzle size={16} />}
          onClose={dismiss}
          footer={<button className="btn primary" onClick={dismiss}>{t("shell.plugins.ok")}</button>}
        >
          {notices.safeMode ? <p className="muted">{notices.autoSafeMode ? t("shell.plugins.safe.lead.auto") : t("shell.plugins.safe.lead")}</p> : null}
          {notices.stateReset ? <p className="muted">{t("shell.plugins.stateReset")}</p> : null}
          {notices.items.length ? <p className="muted">{t("shell.plugins.notices.lead")}</p> : null}
          <div className="plugin-notices">
            {notices.items.map((n) => (
              <div key={`${n.id}:${n.code}`} className="plugin-notice">
                <div className="pn-head">
                  <b>{n.name}</b>
                  <span className="muted">{t(`shell.plugins.reason.${n.code}`)}</span>
                </div>
                {n.detail ? <div className="pn-detail mono">{n.detail}</div> : null}
                <div className="pn-actions">
                  {RETRYABLE.has(n.code) && !notices.safeMode ? <button className="btn sm" onClick={() => void enable(n)}>{t("shell.plugins.enable")}</button> : null}
                  <button className="btn sm ghost" onClick={() => toggleLog(n)}>{logs[n.id] ? t("shell.plugins.hideLog") : t("shell.plugins.log")}</button>
                </div>
                {logs[n.id] ? <pre className="pn-log mono">{logs[n.id]!.length ? logs[n.id]!.join("\n") : t("shell.plugins.logEmpty")}</pre> : null}
              </div>
            ))}
          </div>
        </Modal>
      ) : null}
    </>
  );
}
