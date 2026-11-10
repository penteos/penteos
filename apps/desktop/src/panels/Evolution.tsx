import { Camera, CalendarClock, GitCompareArrows, Pause, Play, RotateCcw, Trash2 } from "../ui/icons";
import { useState } from "react";
import { can, useApp, useOperation } from "../state";
import { Badge, relTime, toast, useTick } from "../ui/bits";
import { locale, t } from "../i18n";

interface SnapshotSummary {
  id: string;
  label: string;
  takenAt: string;
  counts: { hosts: number; services: number; domains: number; webapps: number; findings: number };
}
interface SnapFinding {
  fingerprint: string;
  title: string;
  severity: string;
  status: string;
  assets: string[];
  severityBefore?: string;
}
interface Diff {
  from: { label: string; takenAt: string };
  to: { label: string; takenAt: string };
  hosts: { added: string[]; removed: string[] };
  services: { added: string[]; removed: string[]; changed: Array<{ key: string; before: string; after: string }> };
  domains: { added: string[]; removed: string[] };
  webapps: { added: string[]; removed: string[] };
  findings: { new: SnapFinding[]; resolved: SnapFinding[]; persisting: SnapFinding[] };
}
interface Schedule {
  id: string;
  label: string;
  argv: string[];
  everyHours: number;
  enabled: boolean;
  nextAt: string;
  last?: { at: string; status: string; headline?: string };
}
interface EngagementSummary {
  id: string;
  name: string;
  clientName: string;
}

const EVERY = [24, 168, 720];
const everyLabel = (h: number) => (EVERY.includes(h) ? t(`ops.schedule.every.${h}`) : t("ops.schedule.everyHours", { n: h }));
/** "ip|tcp|443" from "default|10.0.0.5|tcp|443" */
const svc = (key: string) => key.split("|").slice(-3).join(" ").replace(/ (tcp|udp) /, ":").replace(/^(.*):(\d+)$/, "$1:$2");

function until(iso: string, now: number): string {
  const s = Math.round((Date.parse(iso) - now) / 1000);
  if (s <= 60) return t("common.time.now");
  if (s < 3600) return t("ops.until.minutes", { n: Math.round(s / 60) });
  if (s < 86400 * 2) return t("ops.until.hours", { n: Math.round(s / 3600) });
  return t("ops.until.days", { n: Math.round(s / 86400) });
}

function Group(props: { title: string; tone: string; items: string[] }) {
  if (!props.items.length) return null;
  return (
    <div className="diff-group">
      <div className={`diff-title ${props.tone}`}>{props.title} <span className="muted">{props.items.length}</span></div>
      {props.items.slice(0, 50).map((i) => <div key={i} className="diff-item mono">{i}</div>)}
      {props.items.length > 50 ? <div className="diff-item muted">{t("ops.diff.more", { n: props.items.length - 50 })}</div> : null}
    </div>
  );
}

function DiffView({ diff }: { diff: Diff }) {
  const f = diff.findings;
  const stats: Array<[string, number, string]> = [
    [t("ops.diff.stat.newFindings"), f.new.length, "bad"],
    [t("ops.diff.stat.resolved"), f.resolved.length, "ok"],
    [t("ops.diff.stat.persisting"), f.persisting.length, ""],
    [t("ops.diff.stat.newServices"), diff.services.added.length, "warn"],
    [t("ops.diff.stat.closedServices"), diff.services.removed.length, ""],
    [t("ops.diff.stat.versionChanges"), diff.services.changed.length, ""],
  ];
  const nothing = stats.every(([, n], i) => n === 0 || i === 2) && !diff.hosts.added.length && !diff.domains.added.length && !diff.webapps.added.length;
  return (
    <>
      <div className="stats diff-stats">
        {stats.map(([label, n, tone]) => (
          <div key={label} className="stat">
            <div className={`v ${n ? tone : ""}`}>{n}</div>
            <div className="l">{label}</div>
          </div>
        ))}
      </div>
      {nothing ? <p className="muted" style={{ fontSize: 12.5 }}>{t("ops.diff.nothing")}</p> : null}
      <Group title={t("ops.diff.newFindings")} tone="bad" items={f.new.map((x) => `${x.severity.toUpperCase()} · ${x.title}`)} />
      <Group title={t("ops.diff.resolvedFindings")} tone="ok" items={f.resolved.map((x) => `${x.severity.toUpperCase()} · ${x.title}`)} />
      <Group title={t("ops.diff.persisting")} tone="" items={f.persisting.map((x) => `${x.severity.toUpperCase()} · ${x.title}${x.severityBefore ? ` ${t("ops.diff.before", { severity: x.severityBefore })}` : ""}`)} />
      <Group title={t("ops.diff.newServices")} tone="warn" items={diff.services.added.map(svc)} />
      <Group title={t("ops.diff.closedServices")} tone="" items={diff.services.removed.map(svc)} />
      <Group title={t("ops.diff.versionChanges")} tone="" items={diff.services.changed.map((c) => `${svc(c.key)}  ${c.before} → ${c.after}`)} />
      <Group title={t("ops.diff.newHosts")} tone="warn" items={diff.hosts.added.map((k) => k.split("|").pop()!)} />
      <Group title={t("ops.diff.newDomains")} tone="warn" items={diff.domains.added} />
      <Group title={t("ops.diff.newWebapps")} tone="warn" items={diff.webapps.added} />
    </>
  );
}

function Schedules() {
  const { client, me } = useApp();
  const now = useTick();
  const list = useOperation<Schedule[]>("schedule.list", {}, { refreshOn: (e) => e.type === "engagement.updated" || e.type === "schedule.completed" });
  const [label, setLabel] = useState("");
  const [command, setCommand] = useState("");
  const [every, setEvery] = useState(168);
  const mayEdit = can(me, "operator");
  const update = (id: string, patch: Record<string, unknown>) => client.call("schedule.update", { id, ...patch }).catch((e: Error) => toast("bad", t("common.error"), e.message));
  async function add() {
    const argv = command.trim().split(/\s+/);
    await client
      .call("schedule.create", { label: label.trim() || argv[0], argv, targets: [], risk: "active", everyHours: every })
      .then(() => {
        setLabel("");
        setCommand("");
      })
      .catch((e: Error) => toast("bad", t("ops.schedule.createFailed"), e.message));
  }
  return (
    <section>
      <h2><CalendarClock size={11} /> {t("ops.schedule.title")}</h2>
      <div className="list">
        {(list.data ?? []).map((s) => (
          <div key={s.id} className="row" style={{ gridTemplateColumns: "20px 1fr auto" }}>
            <span className={`ic ${s.enabled ? "ok" : ""}`}><CalendarClock size={13} /></span>
            <div style={{ minWidth: 0 }}>
              <div className="t">{s.label} <span className="muted" style={{ fontWeight: 400 }}>· {everyLabel(s.everyHours)}{s.enabled ? ` · ${t("ops.schedule.next", { when: until(s.nextAt, now) })}` : ` · ${t("ops.schedule.paused")}`}</span></div>
              <div className="s mono">{s.argv.join(" ")}</div>
              {s.last ? <div className="s">{t("ops.schedule.last", { when: relTime(s.last.at, now) })} · {s.last.headline ?? s.last.status}</div> : null}
            </div>
            {mayEdit ? (
              <div className="when">
                <button className="btn sm ghost" title={t("ops.schedule.runNow")} onClick={() => update(s.id, { runNow: true })}><Play size={12} /></button>
                <button className="btn sm ghost" title={s.enabled ? t("common.pause") : t("common.resume")} onClick={() => update(s.id, { enabled: !s.enabled })}>{s.enabled ? <Pause size={12} /> : <RotateCcw size={12} />}</button>
                <button className="btn sm ghost" title={t("common.delete")} onClick={() => update(s.id, { delete: true })}><Trash2 size={12} /></button>
              </div>
            ) : <span />}
          </div>
        ))}
        {(list.data ?? []).length === 0 ? <div className="row"><span /><span className="muted">{t("ops.schedule.empty")}</span><span /></div> : null}
      </div>
      {mayEdit ? (
        <div style={{ display: "flex", gap: 8, marginTop: 8 }}>
          <input className="input" style={{ width: 170 }} placeholder={t("ops.schedule.namePlaceholder")} value={label} onChange={(e) => setLabel(e.target.value)} />
          <input className="input mono" style={{ flex: 1 }} placeholder={t("ops.schedule.commandPlaceholder")} value={command} onChange={(e) => setCommand(e.target.value)} />
          <select className="input" value={every} onChange={(e) => setEvery(Number(e.target.value))}>
            {EVERY.map((h) => <option key={h} value={h}>{everyLabel(h)}</option>)}
          </select>
          <button className="btn" disabled={!command.trim()} onClick={add}>{t("ops.schedule.create")}</button>
        </div>
      ) : null}
    </section>
  );
}

export function EvolutionPanel() {
  const { client, me, engagement } = useApp();
  const now = useTick();
  const snaps = useOperation<{ snapshots: SnapshotSummary[]; baseline: string | null; previousEngagementId: string | null }>("snapshot.list", {}, {
    refreshOn: (e) => e.type === "engagement.updated" || e.type === "schedule.completed",
  });
  const engagements = useOperation<{ engagements: EngagementSummary[] }>("engagement.list", {});
  const [against, setAgainst] = useState("");
  const [diff, setDiff] = useState<Diff>();
  const [error, setError] = useState<string>();

  const snapshots = snaps.data?.snapshots ?? [];
  const current = engagement;
  const others = (engagements.data?.engagements ?? []).filter((e) => e.id !== engagement?.id);
  const previous = others.find((e) => e.id === snaps.data?.previousEngagementId);

  async function compare(value = against) {
    setError(undefined);
    const input = value.startsWith("eng:") ? { fromEngagementId: value.slice(4) } : value ? { from: value } : {};
    try {
      setDiff(await client.call<Diff>("snapshot.diff", input));
    } catch (e) {
      setDiff(undefined);
      setError((e as Error).message);
    }
  }
  async function photo() {
    await client.call("snapshot.create", { label: `manual ${new Date().toLocaleDateString()}` });
    toast("ok", t("ops.snapshot.saved.title"), t("ops.snapshot.saved.body"));
  }
  async function retest() {
    const r = await client.call<{ id: string; findingsToVerify: number }>("engagement.retest", { sourceEngagementId: engagement?.id }).catch((e: Error) => {
      toast("bad", t("ops.retest.failed"), e.message);
      return undefined;
    });
    if (!r) return;
    toast("ok", t("ops.retest.created.title"), t("ops.retest.created.body", { n: r.findingsToVerify }));
    client.activate(r.id);
  }

  return (
    <div className="panel">
      <div className="panel-toolbar">
        <GitCompareArrows size={14} />
        <h3>{t("ops.evolution.title")}</h3>
        <span className="hint">{previous ? <>{t("ops.evolution.retestOf")} <b>{previous.name}</b></> : t("ops.evolution.hint")}</span>
        <div className="grow" />
        <button className="btn sm" onClick={photo}><Camera size={12} /> {t("ops.snapshot.take")}</button>
        {can(me, "lead") ? <button className="btn sm" onClick={retest}><RotateCcw size={12} /> {t("ops.retest.create")}</button> : null}
      </div>
      <div className="panel-scroll">
        <div className="report">
          <section>
            <h2><GitCompareArrows size={11} /> {t("ops.diff.title")}</h2>
            <div style={{ display: "flex", gap: 8, marginBottom: 12 }}>
              <select className="input" style={{ flex: 1 }} value={against} onChange={(e) => { setAgainst(e.target.value); void compare(e.target.value); }}>
                <option value="">{snaps.data?.baseline ? t("ops.diff.againstOriginal") : t("ops.diff.againstLast")}</option>
                {[...snapshots].reverse().map((s) => <option key={s.id} value={s.id}>{t("ops.diff.againstSnapshot", { name: s.label || t("ops.snapshot.unnamed"), date: new Date(s.takenAt).toLocaleString(locale()) })}</option>)}
                {others.map((e) => <option key={e.id} value={`eng:${e.id}`}>{t("ops.diff.againstProject", { name: e.name, client: e.clientName })}</option>)}
              </select>
              <button className="btn" onClick={() => compare()}>{t("ops.diff.compare")}</button>
            </div>
            {error ? <p className="muted" style={{ fontSize: 12.5 }}>{error.includes("no photo") ? t("ops.diff.noSnapshots") : error}</p> : null}
            {diff ? <><p className="muted" style={{ fontSize: 12, margin: "0 0 10px" }}>{current ? t("ops.diff.rangeIn", { from: diff.from.label, when: relTime(diff.from.takenAt, now), project: current.name }) : t("ops.diff.range", { from: diff.from.label, when: relTime(diff.from.takenAt, now) })}</p><DiffView diff={diff} /></> : null}
          </section>

          <section>
            <h2><Camera size={11} /> {t("ops.snapshot.title")}</h2>
            <div className="list">
              {[...snapshots].reverse().map((s) => (
                <div key={s.id} className="row" style={{ gridTemplateColumns: "20px 1fr auto" }}>
                  <span className="ic"><Camera size={13} /></span>
                  <div style={{ minWidth: 0 }}>
                    <div className="t">{s.label || t("ops.snapshot.one")} {s.id === snaps.data?.baseline ? <Badge tone="accent">{t("ops.snapshot.baseline")}</Badge> : null}</div>
                    <div className="s">{t("ops.snapshot.counts", { hosts: s.counts.hosts, services: s.counts.services, domains: s.counts.domains, findings: s.counts.findings })}</div>
                  </div>
                  <span className="when">{relTime(s.takenAt, now)}</span>
                </div>
              ))}
              {snapshots.length === 0 ? <div className="row"><span /><span className="muted">{t("ops.snapshot.empty")}</span><span /></div> : null}
            </div>
          </section>

          <Schedules />
        </div>
      </div>
    </div>
  );
}
