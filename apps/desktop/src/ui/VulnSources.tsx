import { CircleCheck, CircleHelp, Loader2, RefreshCw, ShieldAlert } from "./icons";
import { useEffect, useState } from "react";
import { useApp } from "../state";
import { Badge, toast } from "./bits";
import { t } from "../i18n";

/**
 * Freshness of the known-vulnerability feeds. Shows what is cached and how old,
 * and updates them on demand. Cache-first: the agent works offline with what is here; this is the
 * "data as of" indicator with a manual refresh.
 */

interface Feed {
  source: string;
  asOf: string | null;
  ok?: boolean;
  note?: string;
  live?: boolean;
}

export function VulnSources() {
  const { client } = useApp();
  const [feeds, setFeeds] = useState<Feed[]>([]);
  const [busy, setBusy] = useState(false);

  function load() {
    void client.call<{ feeds: Feed[] }>("vuln.sources", {}).then((r) => setFeeds(r.feeds), () => {});
  }
  useEffect(() => {
    load();
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  async function update() {
    setBusy(true);
    try {
      const r = await client.call<{ feeds: Feed[]; failed?: string[] }>("vuln.refresh", {});
      setFeeds(r.feeds);
      if (r.failed?.length) toast("bad", t("data.vuln.updateFailed"), r.failed.join("\n"));
      else toast("ok", t("data.vuln.updated"));
    } catch (e) {
      toast("bad", t("data.vuln.updateFailed"), (e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  const label = (f: Feed) => {
    if (f.live) return t("data.vuln.live");
    if (f.note === "stale") return t("data.vuln.stale");
    if (!f.asOf) return t("data.vuln.never");
    return t("data.vuln.asOf", { date: new Date(f.asOf).toLocaleDateString() });
  };
  const tone = (f: Feed): "ok" | "warn" | "" => (f.live ? "ok" : !f.asOf ? "" : f.note === "stale" ? "warn" : "ok");

  return (
    <div className="vuln-sources">
      <div className="vs-head">
        <ShieldAlert size={14} />
        <h4>{t("data.vuln.title")}</h4>
        <span className="muted vs-hint">{t("data.vuln.hint")}</span>
        <div className="grow" />
        <button className="btn sm" onClick={update} disabled={busy}>
          {busy ? <Loader2 size={12} className="spin" /> : <RefreshCw size={12} />} {busy ? t("data.vuln.updating") : t("data.vuln.update")}
        </button>
      </div>
      <div className="vs-feeds">
        {feeds.map((f) => {
          const ok = tone(f);
          const Icon = ok === "ok" ? CircleCheck : ok === "warn" ? ShieldAlert : CircleHelp;
          return (
            <Badge key={f.source} tone={ok}>
              <Icon size={11} /> {f.source} <span className="muted">· {label(f)}</span>
            </Badge>
          );
        })}
      </div>
    </div>
  );
}
