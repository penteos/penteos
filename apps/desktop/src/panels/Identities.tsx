import { Download, Route, Search, Server, Upload } from "../ui/icons";
import { Monitor, Skull, User, Users } from "../ui/icons";
import { type ReactNode, useMemo, useState } from "react";
import { type Entity, useApp, useOperation } from "../state";
import { relTime, toast, useTick } from "../ui/bits";
import { locale, t, tn } from "../i18n";
import { HelpHint } from "../ui/HelpHint";
import { importFile } from "../ui/importFile";

/** Identities (Active Directory principals) with their attack paths drawn as a graph. */

export interface PathStep {
  id: string;
  label: string;
  via?: "member_of" | "admin_to" | "session";
}

const VIA = ["member_of", "admin_to", "session"];
const viaLabel = (via?: string) => (via && VIA.includes(via) ? t(`ops.path.via.${via}`) : via);

function download(name: string, text: string, type = "text/csv") {
  const url = URL.createObjectURL(new Blob([text], { type }));
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
}

const principalIcon = (type: unknown, size = 13): ReactNode =>
  type === "computer" ? <Monitor size={size} /> : type === "group" ? <Users size={size} /> : <User size={size} />;
const nameOf = (p: Entity) => String(p.attributes.displayName ?? p.naturalKey);

export function usePrincipals() {
  return useOperation<Entity[]>("entity.query", { kind: "principal", limit: 100000 }, { refreshOn: (e) => e.kind === "principal" });
}
export function usePaths(to?: string) {
  return useOperation<PathStep[][]>("graph.paths", { maxPaths: 25, ...(to ? { to: [to] } : {}) }, { refreshOn: (e) => e.kind === "principal", deps: [to] });
}

// ---------------------------------------------------------------------------------------------
// Attack path graph

const NODE_W = 184;
const NODE_H = 34;
const COL_GAP = 84;
const ROW_GAP = 16;

export function PathGraph(props: { paths: PathStep[][]; principals: Map<string, Entity> }) {
  const [focus, setFocus] = useState<string>();
  const layout = useMemo(() => {
    const depth = new Map<string, number>();
    const label = new Map<string, string>();
    const edges = new Map<string, { from: string; to: string; via?: string }>();
    for (const path of props.paths) {
      path.forEach((s, i) => {
        depth.set(s.id, Math.min(depth.get(s.id) ?? Infinity, i));
        label.set(s.id, s.label);
        if (i > 0) edges.set(`${path[i - 1]!.id}>${s.id}`, { from: path[i - 1]!.id, to: s.id, ...(s.via ? { via: s.via } : {}) });
      });
    }
    const columns: string[][] = [];
    for (const [id, d] of depth) (columns[d] ??= []).push(id);
    const pos = new Map<string, { x: number; y: number }>();
    columns.forEach((col, c) => col.forEach((id, r) => pos.set(id, { x: 12 + c * (NODE_W + COL_GAP), y: 22 + r * (NODE_H + ROW_GAP) })));
    const width = 24 + columns.length * NODE_W + Math.max(0, columns.length - 1) * COL_GAP;
    const height = 34 + Math.max(...columns.map((c) => c.length), 1) * (NODE_H + ROW_GAP) - ROW_GAP;
    return { pos, label, edges: [...edges.values()], width, height };
  }, [props.paths]);

  const lit = useMemo(() => {
    if (!focus) return undefined;
    const ids = new Set<string>();
    for (const p of props.paths) if (p.some((s) => s.id === focus)) for (const s of p) ids.add(s.id);
    return ids;
  }, [focus, props.paths]);

  const starts = new Set(props.paths.map((p) => p[0]!.id));
  const goals = new Set(props.paths.map((p) => p.at(-1)!.id));

  return (
    <div className="graph-wrap">
      <svg width={layout.width} height={layout.height} className="path-graph">
        <defs>
          <marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
            <path d="M 0 0 L 10 5 L 0 10 z" fill="var(--fg-3)" />
          </marker>
        </defs>
        {layout.edges.map((e) => {
          const a = layout.pos.get(e.from)!;
          const b = layout.pos.get(e.to)!;
          const x1 = a.x + NODE_W;
          const y1 = a.y + NODE_H / 2;
          const x2 = b.x - 2;
          const y2 = b.y + NODE_H / 2;
          const mx = (x1 + x2) / 2;
          const dim = lit && !(lit.has(e.from) && lit.has(e.to));
          return (
            <g key={`${e.from}>${e.to}`} opacity={dim ? 0.18 : 1}>
              <path d={`M${x1},${y1} C${mx},${y1} ${mx},${y2} ${x2},${y2}`} fill="none" stroke="var(--fg-3)" strokeWidth={1.3} markerEnd="url(#arrow)" />
              <text x={mx} y={(y1 + y2) / 2 - 6} textAnchor="middle" className="edge-label">{viaLabel(e.via)}</text>
            </g>
          );
        })}
        {[...layout.pos].map(([id, p]) => {
          const pr = props.principals.get(id);
          const kind = starts.has(id) ? "start" : goals.has(id) ? "goal" : "";
          const dim = lit && !lit.has(id);
          return (
            <g key={id} transform={`translate(${p.x},${p.y})`} className={`gnode ${kind} ${focus === id ? "focus" : ""}`} opacity={dim ? 0.25 : 1} onClick={() => setFocus(focus === id ? undefined : id)}>
              <rect width={NODE_W} height={NODE_H} rx={4} />
              <foreignObject x={8} y={0} width={NODE_W - 12} height={NODE_H}>
                <div className="gnode-label" title={layout.label.get(id)}>
                  {kind === "start" ? <Skull size={12} /> : principalIcon(pr?.attributes.principalType, 12)}
                  <span>{layout.label.get(id)}</span>
                </div>
              </foreignObject>
            </g>
          );
        })}
      </svg>
    </div>
  );
}

// ---------------------------------------------------------------------------------------------
// Identities

type Filter = "all" | "owned" | "privileged" | "user" | "group" | "computer";
const FILTERS: Filter[] = ["all", "owned", "privileged", "user", "group", "computer"];

export function IdentitiesPanel() {
  const { client } = useApp();
  const principals = usePrincipals();
  const [target, setTarget] = useState("");
  const paths = usePaths(target || undefined);
  const [q, setQ] = useState("");
  const [filter, setFilter] = useState<Filter>("all");
  const all = principals.data ?? [];
  const byId = useMemo(() => new Map(all.map((p) => [p.id, p])), [all]);
  const owned = all.filter((p) => p.tags.includes("owned"));
  const privileged = all.filter((p) => p.attributes.privileged === true);

  const rows = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return all.filter((p) => {
      if (needle && !nameOf(p).toLowerCase().includes(needle)) return false;
      if (filter === "owned") return p.tags.includes("owned");
      if (filter === "privileged") return p.attributes.privileged === true;
      if (filter === "user" || filter === "group" || filter === "computer") return p.attributes.principalType === filter;
      return true;
    });
  }, [all, q, filter]);

  const toggle = (p: Entity) =>
    client.call("entity.tag", p.tags.includes("owned") ? { id: p.id, remove: ["owned"] } : { id: p.id, add: ["owned"] }).catch((e: Error) => toast("bad", t("common.error"), e.message));

  return (
    <div className="panel">
      <div className="panel-toolbar">
        <Route size={14} />
        <h3>{t("ops.identities.title")}</h3>
        <span className="count">{all.length}</span>
        <span className="hint">{t("ops.identities.counts", { owned: owned.length, privileged: privileged.length })}</span>
        <div className="grow" />
        <button className="btn sm" onClick={() => importFile(client)}><Upload size={12} /> {t("ops.importBloodHound")}</button>
      </div>
      {all.length === 0 ? (
        <div className="empty-state">
          <Route size={28} />
          <div className="t">{t("ops.identities.empty.title")}</div>
          <div className="d">{t("ops.identities.empty.body")}</div>
          <button className="btn primary" onClick={() => importFile(client)}><Upload size={13} /> {t("ops.importBloodHound")}</button>
        </div>
      ) : (
        <div className="split-v">
          <div className="graph-pane">
            <div className="pane-head">
              <span className="title">{t("ops.paths.title")}</span>
              <span className="muted">{t("ops.paths.from")}</span>
              <select className="input sm" value={target} onChange={(e) => setTarget(e.target.value)}>
                <option value="">{t("ops.paths.anyPrivileged")}</option>
                {privileged.map((p) => <option key={p.id} value={p.id}>{nameOf(p)}</option>)}
              </select>
              <div className="grow" />
              <span className="muted">{(paths.data ?? []).length ? tn("ops.paths.count", (paths.data ?? []).length) : ""}</span>
            </div>
            {(paths.data ?? []).length ? (
              <PathGraph paths={paths.data ?? []} principals={byId} />
            ) : (
              <div className="graph-empty">
                {owned.length ? t("ops.paths.none") : t("ops.paths.markOwned")}
              </div>
            )}
          </div>
          <div className="table-pane">
            <div className="pane-head">
              <div className="search-box">
                <Search size={12} />
                <input placeholder={t("ops.identities.search")} value={q} onChange={(e) => setQ(e.target.value)} />
              </div>
              <div className="seg">
                {FILTERS.map((id) => <button key={id} className={filter === id ? "on" : ""} onClick={() => setFilter(id)}>{t(`ops.identities.filter.${id}`)}</button>)}
              </div>
            </div>
            <div className="table-wrap">
              <table className="tbl">
                <thead>
                  <tr><th style={{ width: 34 }} /><th>{t("ops.identities.col.identity")}</th><th>{t("ops.identities.col.type")}</th><th>{t("ops.identities.col.state")}</th><th>{t("ops.identities.col.privilege")}</th><th style={{ width: 170 }} /></tr>
                </thead>
                <tbody>
                  {rows.slice(0, 500).map((p) => {
                    const isOwned = p.tags.includes("owned");
                    return (
                      <tr key={p.id} className={isOwned ? "owned" : ""}>
                        <td className="ic">{isOwned ? <Skull size={13} /> : principalIcon(p.attributes.principalType)}</td>
                        <td className="mono">{nameOf(p)}</td>
                        <td className="muted">{p.attributes.principalType === "computer" ? t("ops.identities.type.computer") : p.attributes.principalType === "group" ? t("ops.identities.type.group") : t("ops.identities.type.user")}</td>
                        <td className="muted">{p.attributes.enabled === false ? t("ops.identities.disabled") : t("ops.identities.enabled")}</td>
                        <td>{p.attributes.privileged ? <span className="tag accent">{t("ops.identities.privileged")}</span> : null}</td>
                        <td style={{ textAlign: "right" }}>
                          <button className={`btn sm ${isOwned ? "danger" : "ghost"}`} onClick={() => toggle(p)}>{isOwned ? t("ops.identities.owned") : t("ops.identities.markOwned")}</button>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
              {rows.length > 500 ? <div className="muted" style={{ padding: 10, fontSize: 12 }}>{t("ops.identities.truncated", { n: rows.length })}</div> : null}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

// ---------------------------------------------------------------------------------------------
// Operation: objectives and infrastructure

