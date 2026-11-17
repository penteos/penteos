/**
 * How fast Penteos talks to this project's targets (core: pacing.ts). The operator picks the pace;
 * below it, what each host has received and whether one asked to slow down.
 */
import { useEffect } from "react";
import { t } from "../i18n";
import { can, useApp, useOperation } from "../state";
import { toast } from "./bits";
import { Gauge } from "./icons";

type Pace = "quiet" | "normal" | "aggressive" | "off";
interface PaceInfo {
  pace: Pace;
  hosts: Array<{ host: string; sent: number; waitedMs: number; throttled: number; pausedUntil?: string }>;
}

const PACES: Pace[] = ["quiet", "normal", "aggressive", "off"];

export function PaceSection() {
  const { client, me } = useApp();
  const p = useOperation<PaceInfo>("pacing.get", {});
  // What the hosts received keeps moving while the work goes on.
  useEffect(() => {
    const id = setInterval(() => p.reload(), 5000);
    return () => clearInterval(id);
  }, [p.reload]);
  if (!p.data) return null;
  const allowed = can(me, "lead");
  const set = (pace: Pace) =>
    client.call("pacing.set", { pace }).then(
      () => {
        p.reload();
        toast("ok", t("work.scope.pace.changed", { pace: t(`work.scope.pace.${pace}`) }));
      },
      (e: Error) => toast("bad", t("work.scope.pace.title"), e.message),
    );
  const hosts = p.data.hosts.filter((h) => h.sent > 0).slice(0, 6);
  return (
    <div className="pace">
      <div className="rule-group">
        <Gauge size={12} /> {t("work.scope.pace.title")}
      </div>
      <div className="pace-body">
        <div className="seg">
          {PACES.map((k) => (
            <button key={k} className={p.data!.pace === k ? "on" : ""} disabled={!allowed} onClick={() => void set(k)}>
              {t(`work.scope.pace.${k}`)}
            </button>
          ))}
        </div>
        <div className="pace-hint">{t(`work.scope.pace.${p.data.pace}.hint`)}</div>
        <div className="pace-how muted">{t("work.scope.pace.how")}</div>
        {hosts.length ? (
          <div className="pace-hosts">
            {hosts.map((h) => {
              const paused = h.pausedUntil && Date.parse(h.pausedUntil) > Date.now() ? h.pausedUntil : undefined;
              return (
                <div key={h.host} className={`pace-host ${paused ? "paused" : ""}`}>
                  <span className="mono">{h.host}</span>
                  <span>{t("work.scope.pace.sent", { n: h.sent })}</span>
                  {h.throttled ? <span className="warn">{t("work.scope.pace.throttled", { n: h.throttled })}</span> : null}
                  {paused ? <span className="warn">{t("work.scope.pace.paused", { time: new Date(paused).toLocaleTimeString() })}</span> : null}
                </div>
              );
            })}
          </div>
        ) : null}
      </div>
    </div>
  );
}
