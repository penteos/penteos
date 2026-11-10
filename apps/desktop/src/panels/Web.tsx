import { ChevronDown, ChevronRight, ExternalLink, FileCode2, Globe, Send, Upload, Zap } from "../ui/icons";
import { openProjectBrowser } from "./Proxy";
import { useMemo, useState } from "react";
import { type Entity, useApp, useOperation } from "../state";
import { ScopeBadge, toast } from "../ui/bits";
import { importFile } from "../ui/importFile";
import { t, tn } from "../i18n";
import { wstgName } from "../labels";

/**
 * The web side of the engagement: applications, the map of each one (endpoints as a path tree,
 * with methods, statuses and parameters) and how far the OWASP testing went.
 */

const COV: Record<string, { label: string; tone: string }> = {
  untested: { label: "web.cov.untested", tone: "" },
  in_progress: { label: "web.cov.in_progress", tone: "accent" },
  tested: { label: "web.cov.tested", tone: "ok" },
  vulnerable: { label: "web.cov.vulnerable", tone: "bad" },
  "n/a": { label: "web.cov.na", tone: "muted" },
};

interface TreeNode {
  name: string;
  path: string;
  endpoint?: Entity;
  children: Map<string, TreeNode>;
}

function buildTree(endpoints: Entity[]): TreeNode {
  const root: TreeNode = { name: "/", path: "/", children: new Map() };
  for (const e of endpoints) {
    const parts = String(e.attributes.pathTemplate).split("/").filter(Boolean);
    let node = root;
    let path = "";
    for (const part of parts) {
      path += `/${part}`;
      if (!node.children.has(part)) node.children.set(part, { name: part, path, children: new Map() });
      node = node.children.get(part)!;
    }
    if (parts.length === 0) root.endpoint = e;
    else node.endpoint = e;
  }
  return root;
}

function Tree(props: { node: TreeNode; depth: number; selected?: string; onSelect: (e: Entity) => void }) {
  const [open, setOpen] = useState(props.depth < 2);
  const kids = [...props.node.children.values()].sort((a, b) => (a.children.size ? 0 : 1) - (b.children.size ? 0 : 1) || a.name.localeCompare(b.name));
  const ep = props.node.endpoint;
  return (
    <>
      {props.depth > 0 ? (
        <div
          className={`tree-row ${ep && props.selected === ep.id ? "on" : ""} ${ep ? "" : "dir"}`}
          style={{ paddingLeft: 8 + props.depth * 14 }}
          onClick={() => (ep ? props.onSelect(ep) : setOpen((v) => !v))}
        >
          {kids.length ? (
            <span className="tw" onClick={(e) => { e.stopPropagation(); setOpen((v) => !v); }}>{open ? <ChevronDown size={12} /> : <ChevronRight size={12} />}</span>
          ) : <span className="tw" />}
          <span className="mono name">{props.node.name}</span>
          {ep ? <span className="methods">{((ep.attributes.methods as string[]) ?? []).join(" ")}</span> : null}
        </div>
      ) : null}
      {open || props.depth === 0 ? kids.map((k) => <Tree key={k.path} node={k} depth={props.depth + 1} {...(props.selected ? { selected: props.selected } : {})} onSelect={props.onSelect} />) : null}
    </>
  );
}

function Coverage(props: { app: Entity }) {
  const { client } = useApp();
  const cov = useOperation<Array<{ id: string; title: string; titleEn?: string; status: string; note?: string; by?: string }>>("webapp.coverage", { webappId: props.app.id }, {
    refreshOn: (e) => e.kind === "webapp",
    deps: [props.app.id],
  });
  const set = (category: string, status: string) =>
    client.call("webapp.set_coverage", { webappId: props.app.id, category, status }).catch((e: Error) => toast("bad", t("common.error"), e.message));
  const list = cov.data ?? [];
  const done = list.filter((c) => c.status !== "untested").length;
  return (
    <div className="op-section">
      <div className="sec-head">
        <span>{t("web.cov.title")}</span>
        <span className="muted">{t("web.cov.progress", { done, total: list.length })}</span>
        {list.length ? <div className="progress"><div style={{ width: `${(done / list.length) * 100}%` }} /></div> : null}
      </div>
      <table className="tbl boxed dense">
        <tbody>
          {list.map((c) => (
            <tr key={c.id}>
              <td className="mono muted" style={{ width: 60 }}>{c.id}</td>
              <td>{wstgName(c)}{c.note ? <div className="muted" style={{ fontSize: 11.5 }}>{c.note}</div> : null}</td>
              <td style={{ width: 150 }}>
                <select className={`input sm cov ${COV[c.status]?.tone ?? ""}`} value={c.status} onChange={(e) => set(c.id, e.target.value)}>
                  {Object.entries(COV).map(([k, v]) => <option key={k} value={k}>{t(v.label)}</option>)}
                </select>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function requestFor(ep: Entity, method?: string): string {
  const params = (ep.attributes.params as Array<{ name: string; location: string }> | undefined) ?? [];
  const query = params.filter((p) => p.location === "query").map((p) => `${encodeURIComponent(p.name)}=`).join("&");
  const body = params.filter((p) => p.location === "body").map((p) => `${encodeURIComponent(p.name)}=`).join("&");
  const m = method ?? (body ? "POST" : "GET");
  const path = String(ep.attributes.pathTemplate).replace(/\{id\}/g, "1");
  return [`${m} ${path}${query ? `?${query}` : ""} HTTP/1.1`, ...(m === "POST" ? ["Content-Type: application/x-www-form-urlencoded"] : []), "", m === "POST" ? body : ""].join("\n");
}

export function WebPanel() {
  const { client, workbench, engagement } = useApp();
  const apps = useOperation<Entity[]>("entity.query", { kind: "webapp", limit: 5000 }, { refreshOn: (e) => e.kind === "webapp" });
  const endpoints = useOperation<Entity[]>("entity.query", { kind: "endpoint", limit: 100000 }, { refreshOn: (e) => e.kind === "endpoint" });
  const [appId, setAppId] = useState<string>();
  const [epId, setEpId] = useState<string>();
  const list = apps.data ?? [];
  const app = list.find((a) => a.id === appId) ?? list[0];
  const eps = useMemo(() => (endpoints.data ?? []).filter((e) => e.attributes.webappId === app?.id), [endpoints.data, app?.id]);
  const tree = useMemo(() => buildTree(eps), [eps]);
  const ep = eps.find((e) => e.id === epId);

  if (list.length === 0) {
    return (
      <div className="panel">
        <div className="panel-toolbar"><Globe size={14} /><h3>{t("web.map.title")}</h3></div>
        <div className="empty-state">
          <Globe size={28} />
          <div className="t">{t("web.map.empty.title")}</div>
          <div className="d">{t("web.map.empty.body")}</div>
          <div style={{ display: "flex", gap: 8 }}>
            <button className="btn primary" onClick={() => openProjectBrowser(client, engagement)}><ExternalLink size={13} /> {t("web.openProjectBrowser")}</button>
            <button className="btn" onClick={() => importFile(client)}><Upload size={13} /> {t("web.importBurpHar")}</button>
            <button className="btn" onClick={() => workbench.openRequest({ origin: "http://", raw: "GET / HTTP/1.1\n\n" })}><Send size={13} /> {t("web.newRequest")}</button>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="panel">
      <div className="panel-toolbar">
        <Globe size={14} />
        <h3>{t("web.map.title")}</h3>
        <select className="input sm" value={app?.id} onChange={(e) => { setAppId(e.target.value); setEpId(undefined); }}>
          {list.map((a) => <option key={a.id} value={a.id}>{String(a.attributes.origin)}{a.outOfScope ? t("web.map.outOfScope") : ""}</option>)}
        </select>
        <span className="hint">{tn("web.map.endpoints", eps.length)}</span>
        <div className="grow" />
        <button className="btn sm primary" onClick={() => app && openProjectBrowser(client, engagement, String(app.attributes.origin))}><ExternalLink size={12} /> {t("web.map.browse")}</button>
        <button className="btn sm" onClick={() => importFile(client)}><Upload size={12} /> {t("web.importBurpHar")}</button>
        <button className="btn sm" onClick={() => app && workbench.openRequest({ origin: String(app.attributes.origin), raw: "GET / HTTP/1.1\n\n" })}><Send size={12} /> {t("web.newRequest")}</button>
      </div>
      <div className="web-split">
        <div className="web-tree">
          <div className={`tree-row app ${!ep ? "on" : ""}`} onClick={() => setEpId(undefined)}>
            <Globe size={12} /> <span className="mono name">{app ? new URL(String(app.attributes.origin)).host : ""}</span>
          </div>
          <Tree node={tree} depth={0} {...(epId ? { selected: epId } : {})} onSelect={(e) => setEpId(e.id)} />
          {eps.length === 0 ? <div className="muted" style={{ padding: 12, fontSize: 12 }}>{t("web.map.noRoutes")}</div> : null}
        </div>
        <div className="web-detail">
          {ep ? (
            <div className="op">
              <div className="ep-head">
                <FileCode2 size={15} />
                <span className="mono path">{String(ep.attributes.pathTemplate)}</span>
                {ep.outOfScope ? <ScopeBadge out /> : null}
                <div className="grow" />
                <button className="btn sm ghost" onClick={() => workbench.openFuzzer({ origin: String(app!.attributes.origin), template: requestFor(ep) })}><Zap size={12} /> {t("web.map.fuzz")}</button>
                {((ep.attributes.methods as string[]) ?? ["GET"]).map((m) => (
                  <button key={m} className="btn sm" onClick={() => workbench.openRequest({ origin: String(app!.attributes.origin), raw: requestFor(ep, m) })}>
                    <Send size={12} /> {t("web.map.methodInEditor", { method: m })}
                  </button>
                ))}
              </div>
              <div className="kv">
                <span>{t("web.map.methods")}</span><span className="mono">{((ep.attributes.methods as string[]) ?? []).join(", ") || "-"}</span>
                <span>{t("web.map.statusesSeen")}</span><span className="mono">{((ep.attributes.statusesSeen as number[]) ?? []).join(", ") || "-"}</span>
              </div>
              <div className="op-section">
                <div className="sec-head"><span>{t("web.map.params")}</span></div>
                <table className="tbl boxed dense">
                  <tbody>
                    {((ep.attributes.params as Array<{ name: string; location: string }>) ?? []).map((p) => (
                      <tr key={`${p.location}:${p.name}`}><td className="mono">{p.name}</td><td className="muted">{p.location}</td></tr>
                    ))}
                    {((ep.attributes.params as unknown[]) ?? []).length === 0 ? <tr><td className="muted">{t("web.map.noParams")}</td></tr> : null}
                  </tbody>
                </table>
              </div>
            </div>
          ) : app ? (
            <div className="op">
              <div className="ep-head">
                <Globe size={15} />
                <span className="mono path">{String(app.attributes.origin)}</span>
                {app.outOfScope ? <ScopeBadge out /> : null}
              </div>
              <div className="kv">
                <span>{t("web.map.appTitle")}</span><span>{String(app.attributes.title ?? "-")}</span>
                <span>{t("web.map.technologies")}</span>
                <span>{((app.attributes.technologies as Array<{ name: string; version?: string }>) ?? []).map((tech) => <span key={tech.name} className="tag" style={{ marginRight: 4 }}>{tech.name}{tech.version ? ` ${tech.version}` : ""}</span>)}</span>
              </div>
              <Coverage app={app} />
            </div>
          ) : null}
        </div>
      </div>
    </div>
  );
}
