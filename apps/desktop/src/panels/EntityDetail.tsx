import { MemoryList } from "./Memory";
import { AlertTriangle, ArrowRight, Brain, Bug, GitBranch, History, Puzzle } from "../ui/icons";
import { PluginEntityActions, PluginEntityPanels, PluginExtData, ptext, usePluginCatalog } from "../ui/plugins";
import { type Actor, type Entity, useApp, useOperation } from "../state";
import { ActorBadge, Badge, relTime, ScopeBadge, useTick } from "../ui/bits";
import { locale, t, tn } from "../i18n";

interface Detail extends Entity {
  edges: Array<{ id: string; type: string; direction: "in" | "out"; other: { id: string; kind: string; naturalKey: string } | null; lastSeen: string }>;
  sightings: Array<{ id: string; attributes: Record<string, unknown>; source: Actor; confidence: number; observedAt: string; rawId?: string }>;
}

const KINDS = ["host", "service", "domain", "webapp", "endpoint"];
const kindLabel = (k: string) => (KINDS.includes(k) ? t(`data.entity.kind.${k}`) : k);
const isPluginKind = (k: string) => /^[a-z0-9-]+(\.[a-z0-9-]+)+:[a-z][a-z0-9_]*$/.test(k);
const EDGES = ["runs_on", "resolves_to", "served_by", "hosted_at", "belongs_to"];
const edgeLabel = (type: string, direction: "in" | "out") => (EDGES.includes(type) ? t(`data.entity.edge.${type}.${direction}`) : type);

function fmt(v: unknown): string {
  if (Array.isArray(v)) return v.map(fmt).join(", ");
  if (v && typeof v === "object") return JSON.stringify(v);
  return String(v);
}

/** Natural keys without the default network context, for display. */
function displayKey(key: string): string {
  return key.replace(/^default\|/, "").replaceAll("|", " · ");
}

function title(e: Entity): string {
  const a = e.attributes;
  if (e.kind === "service") return `${e.naturalKey.split("|")[1]}:${a.port}/${a.transport}`;
  if (e.kind === "host") return String(a.ip);
  if (e.kind === "domain") return String(a.fqdn);
  return e.naturalKey;
}

export function EntityDetailPanel(props: { params: { id: string } }) {
  const { workbench } = useApp();
  const now = useTick();
  const offers = usePluginCatalog().plugins;
  const detail = useOperation<Detail>("entity.get", { id: props.params.id, sightings: true }, { refreshOn: (e) => e.id === props.params.id || e.type === "scope.changed" });
  const d = detail.data;
  if (!d) return null;

  // A plugin type's label, and whether it is dormant (its plugin is not running).
  const pluginType = isPluginKind(d.kind) ? offers.flatMap((p) => p.entityTypes).find((x) => x.kind === d.kind) : undefined;
  const dormant = isPluginKind(d.kind) && !pluginType;
  const hidden = new Set(["hostId", "webappId"]);
  const attrs = Object.entries(d.attributes).filter(([k, v]) => !hidden.has(k) && v !== undefined && !(Array.isArray(v) && v.length === 0));

  return (
    <div className="panel">
      <div className="panel-scroll">
        <div className="detail-head">
          <div className="kind">
            {pluginType ? <><Puzzle size={11} /> {ptext(pluginType.label)}</> : kindLabel(d.kind)} <ScopeBadge out={d.outOfScope} /> {d.conflicts.length ? <Badge tone="warn"><AlertTriangle size={11} /> {tn("data.entity.conflicts", d.conflicts.length)}</Badge> : null}
          </div>
          <h2>{title(d)}</h2>
          <div style={{ display: "flex", gap: 8 }}>
            <button className="btn sm primary" onClick={() => workbench.newFinding({ entityId: d.id, label: title(d) })}>
              <Bug size={12} /> {t("data.entity.createFinding")}
            </button>
            <PluginEntityActions entityId={d.id} kind={d.kind} />
            <span style={{ color: "var(--fg-3)", alignSelf: "center", fontSize: 12 }}>
              {t("data.entity.revision", { n: d.revision, time: relTime(d.updatedAt, now) })}
            </span>
          </div>
          {dormant ? <div className="muted" style={{ fontSize: 12, marginTop: 6 }}>{t("plugins.entity.dormant")}</div> : null}
        </div>

        <div className="kv">
          {attrs.map(([k, v]) => {
            const conflict = d.conflicts.find((c) => c.field === k);
            return [
              <div key={`${k}-k`} className="k">{k}</div>,
              <div key={`${k}-v`} className="v mono">
                {fmt(v)}
                {conflict ? (
                  <span style={{ marginLeft: 8 }}>
                    <Badge tone="warn" title={conflict.values.map((x) => `${fmt(x.value)} (${x.source.id})`).join(" vs ")}>{t("data.entity.inConflict")}</Badge>
                  </span>
                ) : null}
              </div>,
            ];
          })}
        </div>

        <PluginExtData ext={d.ext} />
        <PluginEntityPanels entityId={d.id} kind={d.kind} />

        {d.edges.length ? (
          <>
            <div className="section-title"><GitBranch size={12} /> {t("data.entity.relations")}</div>
            {d.edges.map((e) =>
              e.other ? (
                <div key={e.id} className="rel" onClick={() => workbench.openEntity(e.other!.id, displayKey(e.other!.naturalKey))}>
                  <span className="t">{edgeLabel(e.type, e.direction)}</span>
                  <Badge>{kindLabel(e.other.kind)}</Badge>
                  <span className="mono" style={{ color: "var(--fg-0)", flex: 1, overflow: "hidden", textOverflow: "ellipsis" }}>{displayKey(e.other.naturalKey)}</span>
                  <ArrowRight size={13} color="var(--fg-3)" />
                </div>
              ) : null,
            )}
          </>
        ) : null}

        <div className="section-title"><Brain size={12} /> {t("data.entity.memory")}</div>
        <div style={{ padding: "0 20px" }}><MemoryList entityId={d.id} compact /></div>

        <div className="section-title"><History size={12} /> {t("data.entity.provenance")}</div>
        <div className="timeline">
          {d.sightings.length === 0 ? (
            <div style={{ color: "var(--fg-3)" }}>{t("data.entity.noSightings")}</div>
          ) : (
            [...d.sightings].reverse().map((s) => (
              <div key={s.id} className="tl-item">
                <div className="h">
                  <ActorBadge actor={s.source} />
                  <span className="mono" style={{ color: "var(--fg-2)" }}>{new Date(s.observedAt).toLocaleString(locale(), { hourCycle: "h23" })}</span>
                  <Badge>{t("data.entity.confidence", { n: Math.round(s.confidence * 100) })}</Badge>
                  {s.rawId ? <span className="mono" style={{ color: "var(--fg-3)", fontSize: 11 }}>{t("data.entity.raw", { id: s.rawId.slice(0, 10) })}</span> : null}
                </div>
                {Object.keys(s.attributes).length ? (
                  <div className="attrs mono">{Object.entries(s.attributes).map(([k, v]) => `${k}: ${fmt(v)}`).join("\n")}</div>
                ) : null}
              </div>
            ))
          )}
        </div>
      </div>
    </div>
  );
}
