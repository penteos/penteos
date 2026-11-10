import type { ColumnDef } from "@tanstack/react-table";
import { Globe, Lock, Radar, Search, Server, Upload } from "../ui/icons";
import { importFile } from "../ui/importFile";
import { useMemo, useState } from "react";
import { type Entity, useApp, useOperation } from "../state";
import { Badge, Empty, relTime, ScopeBadge, useTick } from "../ui/bits";
import { DataTable } from "../ui/DataTable";
import { t } from "../i18n";

type Col = ColumnDef<Entity, any> & { width?: string };

function useEntities(kind: string) {
  return useOperation<Entity[]>("entity.query", { kind, limit: 5000 }, { refreshOn: (e) => e.kind === kind || e.type === "scope.changed" });
}

function Toolbar(props: { icon: React.ReactNode; title: string; count: number; filter: string; setFilter: (v: string) => void; extra?: React.ReactNode }) {
  return (
    <div className="panel-toolbar">
      {props.icon}
      <h3>{props.title}</h3>
      <span className="count">{props.count}</span>
      {props.extra}
      <div className="grow" />
      <div className="input-icon">
        <Search size={13} />
        <input className="input" style={{ width: 240 }} placeholder={t("common.filter")} value={props.filter} onChange={(e) => props.setFilter(e.target.value)} />
      </div>
    </div>
  );
}

export function ServicesPanel() {
  const { workbench } = useApp();
  const now = useTick();
  const services = useEntities("service");
  const hosts = useEntities("host");
  const [filter, setFilter] = useState("");
  const [state, setState] = useState<"open" | "all">("open");
  const [selected, setSelected] = useState<string>();

  const hostIp = useMemo(() => new Map((hosts.data ?? []).map((h) => [h.id, String(h.attributes.ip)])), [hosts.data]);
  const rows = useMemo(
    () =>
      (services.data ?? [])
        .filter((s) => state === "all" || s.attributes.state === "open")
        .map((s) => ({ ...s, host: hostIp.get(s.attributes.hostId) ?? "?" })),
    [services.data, hostIp, state],
  );

  const columns: Col[] = [
    { id: "state", header: "", width: "34px", accessorFn: (r) => r.attributes.state, cell: (c) => <span className={`dot ${String(c.getValue()).split("|")[0]}`} title={c.getValue()} /> },
    { id: "host", header: () => t("data.assets.col.host"), width: "150px", accessorFn: (r: any) => r.host, cell: (c) => <span className="mono strong" style={{ color: "var(--fg-0)" }}>{c.getValue()}</span> },
    {
      id: "port", header: () => t("data.assets.col.port"), width: "100px", accessorFn: (r) => r.attributes.port,
      cell: (c) => <span className="mono">{c.getValue()}<span style={{ color: "var(--fg-3)" }}>/{c.row.original.attributes.transport}</span></span>,
    },
    {
      id: "protocol", header: () => t("data.assets.col.service"), width: "130px", accessorFn: (r) => r.attributes.protocol ?? "",
      cell: (c) => (
        <span style={{ display: "flex", alignItems: "center", gap: 6 }}>
          {c.row.original.attributes.tls ? <Lock size={11} color="var(--ok)" /> : null}
          {c.getValue() || <span style={{ color: "var(--fg-3)" }}>-</span>}
        </span>
      ),
    },
    { id: "product", header: () => t("data.assets.col.product"), width: "1.2fr", accessorFn: (r) => r.attributes.product ?? "", cell: (c) => <span style={{ color: "var(--fg-0)" }}>{c.getValue() || <span style={{ color: "var(--fg-3)" }}>-</span>}</span> },
    { id: "version", header: () => t("data.assets.col.version"), width: "1.3fr", accessorFn: (r) => r.attributes.version ?? "", cell: (c) => <span className="mono">{c.getValue()}</span> },
    {
      id: "flags", header: () => t("data.assets.col.status"), width: "150px", accessorFn: (r) => (r.outOfScope ? 1 : 0),
      cell: (c) => (
        <span style={{ display: "flex", gap: 6 }}>
          <ScopeBadge out={c.row.original.outOfScope} />
          {c.row.original.conflicts.length ? <Badge tone="warn">{t("data.assets.conflict")}</Badge> : null}
        </span>
      ),
    },
    { id: "updated", header: () => t("data.assets.col.seen"), width: "100px", accessorFn: (r) => r.updatedAt, cell: (c) => <span style={{ color: "var(--fg-3)" }}>{relTime(c.getValue(), now)}</span> },
  ];

  return (
    <div className="panel">
      <Toolbar
        icon={<Radar size={14} color="var(--ok)" />}
        title={t("data.assets.services")}
        count={rows.length}
        filter={filter}
        setFilter={setFilter}
        extra={
          <div className="seg" style={{ marginLeft: 8 }}>
            <button className={state === "open" ? "on" : ""} onClick={() => setState("open")}>{t("data.assets.filter.open")}</button>
            <button className={state === "all" ? "on" : ""} onClick={() => setState("all")}>{t("data.assets.filter.all")}</button>
          </div>
        }
      />
      <DataTable
        data={rows}
        columns={columns as any}
        filter={filter}
        rowKey={(r) => r.id}
        selected={selected}
        initialSort={[{ id: "host", desc: false }]}
        rowClassName={(r) => (r.outOfScope ? "muted" : "")}
        onRowClick={(r) => {
          setSelected(r.id);
          workbench.openEntity(r.id, `${(r as any).host}:${r.attributes.port}`);
        }}
        empty={<Empty icon={<Radar size={20} />} title={t("data.assets.services.empty.title")}>{t("data.assets.services.empty.body")}</Empty>}
      />
    </div>
  );
}

export function HostsPanel() {
  const { workbench, client } = useApp();
  const now = useTick();
  const hosts = useEntities("host");
  const services = useEntities("service");
  const [filter, setFilter] = useState("");
  const [selected, setSelected] = useState<string>();

  const openCount = useMemo(() => {
    const m = new Map<string, number>();
    for (const s of services.data ?? []) if (s.attributes.state === "open") m.set(s.attributes.hostId, (m.get(s.attributes.hostId) ?? 0) + 1);
    return m;
  }, [services.data]);
  // What is open on each host, the thing an operator looks at first.
  const openPorts = useMemo(() => {
    const m = new Map<string, string[]>();
    for (const s of [...(services.data ?? [])].sort((a, b) => Number(a.attributes.port) - Number(b.attributes.port))) {
      if (s.attributes.state !== "open") continue;
      const list = m.get(s.attributes.hostId) ?? [];
      list.push(`${s.attributes.port}${s.attributes.product ? ` ${s.attributes.product}` : s.attributes.protocol ? ` ${s.attributes.protocol}` : ""}`);
      m.set(s.attributes.hostId, list);
    }
    return m;
  }, [services.data]);

  const columns: Col[] = [
    { id: "status", header: "", width: "34px", accessorFn: (r) => r.attributes.status, cell: (c) => <span className={`dot ${c.getValue()}`} /> },
    { id: "ip", header: () => t("data.assets.col.address"), width: "160px", accessorFn: (r) => r.attributes.ip, cell: (c) => <span className="mono" style={{ color: "var(--fg-0)" }}>{c.getValue()}</span> },
    { id: "names", header: () => t("data.assets.col.names"), width: "1.2fr", accessorFn: (r) => (r.attributes.hostnames ?? []).join(", "), cell: (c) => <span>{c.getValue() || <span style={{ color: "var(--fg-3)" }}>-</span>}</span> },
    {
      id: "open",
      header: () => t("data.assets.col.openServices"),
      width: "2fr",
      accessorFn: (r) => openCount.get(r.id) ?? 0,
      cell: (c) => {
        const ports = openPorts.get(c.row.original.id) ?? [];
        if (!ports.length) return <span style={{ color: "var(--fg-3)" }}>{t("data.assets.noneSeen")}</span>;
        return (
          <span className="ports" title={ports.join(", ")}>
            <span className="mono" style={{ color: "var(--ok)" }}>{ports.length}</span>
            {ports.slice(0, 6).map((p) => <span key={p} className="port mono">{p}</span>)}
            {ports.length > 6 ? <span className="muted">+{ports.length - 6}</span> : null}
          </span>
        );
      },
    },
    { id: "os", header: () => t("data.assets.col.os"), width: "0.8fr", accessorFn: (r) => r.attributes.os?.name ?? "", cell: (c) => c.getValue() || <span style={{ color: "var(--fg-3)" }}>-</span> },
    { id: "ctx", header: () => t("data.assets.col.network"), width: "100px", accessorFn: (r) => r.attributes.networkContext, cell: (c) => <Badge>{c.getValue() === "default" ? t("data.assets.defaultNetwork") : c.getValue()}</Badge> },
    { id: "scope", header: () => t("data.assets.col.scope"), width: "110px", accessorFn: (r) => (r.outOfScope ? 1 : 0), cell: (c) => <ScopeBadge out={c.row.original.outOfScope} /> },
    { id: "updated", header: () => t("data.assets.col.seen"), width: "100px", accessorFn: (r) => r.updatedAt, cell: (c) => <span style={{ color: "var(--fg-3)" }}>{relTime(c.getValue(), now)}</span> },
  ];

  return (
    <div className="panel">
      <Toolbar icon={<Server size={14} color="var(--info)" />} title={t("data.assets.hosts")} count={hosts.data?.length ?? 0} filter={filter} setFilter={setFilter} />
      <DataTable
        data={hosts.data ?? []}
        columns={columns}
        filter={filter}
        rowKey={(r) => r.id}
        selected={selected}
        rowClassName={(r) => (r.outOfScope ? "muted" : "")}
        onRowClick={(r) => {
          setSelected(r.id);
          workbench.openEntity(r.id, String(r.attributes.ip));
        }}
        empty={
          <Empty icon={<Server size={20} />} title={t("data.assets.hosts.empty.title")}>
            {t("data.assets.hosts.empty.body")}
            <div className="empty-actions">
              <button className="btn sm primary" onClick={() => workbench.openPanel("home")}><Radar size={12} /> {t("data.assets.hosts.scan")}</button>
              <button className="btn sm" onClick={() => void importFile(client)}><Upload size={12} /> {t("data.assets.hosts.importNmap")}</button>
            </div>
          </Empty>
        }
      />
    </div>
  );
}

export function DomainsPanel() {
  const { workbench } = useApp();
  const now = useTick();
  const domains = useEntities("domain");
  const [filter, setFilter] = useState("");
  const columns: Col[] = [
    { id: "fqdn", header: () => t("data.assets.col.name"), width: "1.6fr", accessorFn: (r) => r.attributes.fqdn, cell: (c) => <span className="mono" style={{ color: "var(--fg-0)" }}>{c.getValue()}</span> },
    { id: "apex", header: () => t("data.assets.col.domain"), width: "1fr", accessorFn: (r) => r.attributes.apex, cell: (c) => <span className="mono">{c.getValue()}</span> },
    { id: "scope", header: () => t("data.assets.col.scope"), width: "110px", accessorFn: (r) => (r.outOfScope ? 1 : 0), cell: (c) => <ScopeBadge out={c.row.original.outOfScope} /> },
    { id: "updated", header: () => t("data.assets.col.seen"), width: "100px", accessorFn: (r) => r.updatedAt, cell: (c) => <span style={{ color: "var(--fg-3)" }}>{relTime(c.getValue(), now)}</span> },
  ];
  return (
    <div className="panel">
      <Toolbar icon={<Globe size={14} color="var(--agent)" />} title={t("data.assets.domains")} count={domains.data?.length ?? 0} filter={filter} setFilter={setFilter} />
      <DataTable
        data={domains.data ?? []}
        columns={columns}
        filter={filter}
        rowKey={(r) => r.id}
        rowClassName={(r) => (r.outOfScope ? "muted" : "")}
        onRowClick={(r) => workbench.openEntity(r.id, String(r.attributes.fqdn))}
        empty={<Empty icon={<Globe size={20} />} title={t("data.assets.domains.empty.title")} />}
      />
    </div>
  );
}
