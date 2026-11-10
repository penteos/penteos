import { label, risk, RUN_ORIGIN_ES, RUN_STATUS_ES } from "../labels";
import { t } from "../i18n";
import type { ColumnDef } from "@tanstack/react-table";
import { Ban, CheckCircle2, Loader2, Play, Square, TerminalSquare, X, XCircle } from "../ui/icons";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { type Run, useApp, useOperation } from "../state";
import { ActorBadge, Badge, Empty, relTime, useTick, toast } from "../ui/bits";
import { DataTable } from "../ui/DataTable";
import { summarize } from "./Home";

export function RunStatus(props: { run: Run; compact?: boolean }) {
  const { run } = props;
  const map = {
    running: { icon: <Loader2 size={13} className="spin" />, tone: "agent" },
    finished: { icon: <CheckCircle2 size={13} />, tone: "ok" },
    failed: { icon: <XCircle size={13} />, tone: "bad" },
    denied: { icon: <Ban size={13} />, tone: "bad" },
    cancelled: { icon: <X size={13} />, tone: "" },
  }[run.status];
  if (props.compact) return <div className={`ic ${map.tone}`}>{map.icon}</div>;
  return (
    <Badge tone={map.tone}>
      {map.icon} {label(RUN_STATUS_ES, run.status)}
    </Badge>
  );
}

/** How many runs are in progress right now (for the tab and the status bar). */
export function useRunningRuns(): number {
  const runs = useOperation<Run[]>("run.list", { limit: 200 }, { refreshOn: (e) => e.type === "run.started" || e.type === "run.finished" });
  return (runs.data ?? []).filter((r) => r.status === "running").length;
}

/** Cancels a run and says so when nothing could be cancelled. */
export async function cancelRun(client: { call: <T = unknown>(op: string, input?: unknown) => Promise<T> }, runId: string): Promise<void> { // i18n-ignore: type arguments
  try {
    const r = await client.call<{ cancelled: boolean }>("run.cancel", { runId });
    if (!r.cancelled) toast("info", t("data.run.cancel.nothing"), t("data.run.cancel.nothingBody"));
  } catch (e) {
    toast("bad", t("data.run.cancel.failed"), (e as Error).message);
  }
}

function CancelButton(props: { runId: string; small?: boolean }) {
  const { client } = useApp();
  const [busy, setBusy] = useState(false);
  return (
    <button
      className={`btn sm danger ${props.small ? "run-cancel" : ""}`}
      disabled={busy}
      onClick={(e) => {
        e.stopPropagation();
        setBusy(true);
        void cancelRun(client, props.runId).finally(() => setTimeout(() => setBusy(false), 1500));
      }}
    >
      <Square size={11} /> {busy ? t("data.run.cancelling") : t("common.cancel")}
    </button>
  );
}

export function RunsPanel() {
  const { workbench } = useApp();
  const now = useTick();
  const runs = useOperation<Run[]>("run.list", { limit: 500 }, { refreshOn: (e) => e.type.startsWith("run.") });
  const columns: Array<ColumnDef<Run, any> & { width?: string }> = [
    { id: "status", header: () => t("data.runs.col.status"), width: "170px", accessorFn: (r) => r.status, cell: (c) => <span className="run-status-cell"><RunStatus run={c.row.original} />{c.row.original.status === "running" ? <CancelButton runId={c.row.original.id} small /> : null}</span> },
    { id: "cmd", header: () => t("data.runs.col.command"), width: "2fr", accessorFn: (r) => r.command ?? "", cell: (c) => <span className="mono" style={{ color: "var(--fg-0)" }}>{c.getValue()}</span> },
    {
      id: "result", header: () => t("data.runs.col.result"), width: "1.4fr", accessorFn: (r) => r.policy.reason ?? "",
      cell: (c) => {
        const r = c.row.original;
        if (r.status === "denied") return <span style={{ color: "var(--bad)" }}>{r.policy.reason}</span>;
        if (r.summary?.ingested) return <span style={{ color: "var(--ok)" }}>{summarize(r.summary.ingested)}</span>;
        if (r.summary?.ingestError) return <span style={{ color: "var(--warn)" }}>{r.summary.ingestError}</span>;
        return <span style={{ color: "var(--fg-3)" }}>{r.targets.join(", ")}</span>;
      },
    },
    { id: "origin", header: () => t("data.runs.col.origin"), width: "130px", accessorFn: (r) => r.origin, cell: (c) => <span className="run-origin"><Badge>{c.getValue() === "terminal" ? <TerminalSquare size={11} /> : <Play size={11} />} {label(RUN_ORIGIN_ES, c.getValue())}</Badge>{/^offline sandbox/.test(c.row.original.policy.reason ?? "") ? <span className="tag offline" title={t("data.run.offline.hint")}>{t("data.run.offline")}</span> : null}</span> },
    { id: "actor", header: () => t("data.runs.col.actor"), width: "110px", accessorFn: (r) => r.actor.type, cell: (c) => <ActorBadge actor={c.row.original.actor} /> },
    { id: "started", header: () => t("data.runs.col.started"), width: "100px", accessorFn: (r) => r.startedAt, cell: (c) => <span style={{ color: "var(--fg-3)" }}>{relTime(c.getValue(), now)}</span> },
  ];
  return (
    <div className="panel">
      <DataTable
        data={runs.data ?? []}
        columns={columns}
        rowKey={(r) => r.id}
        onRowClick={(r) => workbench.openRun(r.id)}
        empty={<Empty icon={<Play size={20} />} title={t("data.runs.empty.title")}>{t("data.runs.empty.body")}</Empty>}
      />
    </div>
  );
}

function elapsed(from: string, to: number): string {
  const s = Math.max(0, Math.round((to - Date.parse(from)) / 1000));
  return s < 60 ? `${s}s` : `${Math.floor(s / 60)}m ${String(s % 60).padStart(2, "0")}s`;
}

/** What nmap is doing right now, read from its verbose output. */
function nmapProgress(output: string) {
  const progress = [...output.matchAll(/About ([\d.]+)% done(?:; ETC: (\d{1,2}:\d{2}))?/g)].at(-1);
  const phase = [...output.matchAll(/^(?:Initiating|Completed) (.+?) at \d/gm)].at(-1);
  const ports = [...new Set([...output.matchAll(/Discovered open port (\d+)\/(\w+) on (\S+)/g)].map((m) => `${m[1]}/${m[2]}`))];
  return {
    pct: progress ? Number.parseFloat(progress[1]!) : undefined,
    etc: progress?.[2],
    phase: phase?.[1],
    ports,
  };
}

export function RunDetailPanel(props: { params: { runId: string } }) {
  const { client, workbench } = useApp();
  const runId = props.params.runId;
  const run = useOperation<Run>("run.get", { runId }, { refreshOn: (e) => e.id === runId });
  const [output, setOutput] = useState("");
  const text = useRef("");
  const scroller = useRef<HTMLDivElement>(null);
  const stick = useRef(true);
  const r = run.data;
  const now = useTick(r?.status === "running" ? 1000 : 60000);

  const refetch = useCallback(() => {
    client
      .call<{ content: unknown }>("run.output", { runId, length: 1_000_000 })
      .then((o) => {
        const content = typeof o.content === "string" ? o.content : "";
        if (content.length >= text.current.length) {
          text.current = content;
          setOutput(content);
        }
      })
      .catch(() => {});
  }, [client, runId]);

  // Catch up with what already happened, and again when the run finishes (stored output).
  useEffect(() => refetch(), [refetch, r?.status]);

  // Live chunks: the offset says where each one goes, so nothing is duplicated or lost.
  useEffect(
    () =>
      client.onEvent((e) => {
        if (e.type !== "run.output" || e.id !== runId) return;
        const chunk = String(e.chunk ?? "");
        const offset = typeof e.offset === "number" ? e.offset : text.current.length;
        if (offset > text.current.length) return refetch();
        const tail = chunk.slice(text.current.length - offset);
        if (!tail) return;
        text.current += tail;
        setOutput(text.current);
      }),
    [client, runId, refetch],
  );

  useEffect(() => {
    const el = scroller.current;
    if (el && stick.current) el.scrollTop = el.scrollHeight;
  }, [output]);

  const live = useMemo(() => (r?.tool === "nmap" ? nmapProgress(output) : undefined), [output, r?.tool]);

  if (!r) return null;
  const running = r.status === "running";
  return (
    <div className="panel">
      <div className="detail-head">
        <div className="kind">
          <RunStatus run={r} /> <ActorBadge actor={r.actor} /> <Badge>{label(RUN_ORIGIN_ES, r.origin)}</Badge> <Badge tone="accent">{risk(r.risk)}</Badge>
          <span style={{ marginLeft: "auto", textTransform: "none", letterSpacing: 0, fontWeight: 400 }} className="mono">
            {elapsed(r.startedAt, r.endedAt ? Date.parse(r.endedAt) : now)}
          </span>
          {running ? (
            <CancelButton runId={runId} />
          ) : null}
        </div>
        <h2>{r.command}</h2>
        <div style={{ color: "var(--fg-2)", display: "flex", gap: 14, flexWrap: "wrap" }}>
          <span>{t("data.run.targets")} <span className="mono" style={{ color: "var(--fg-0)" }}>{r.targets.join(", ") || "-"}</span></span>
          <span>{t("data.run.policy")} <b style={{ color: r.policy.result === "denied" ? "var(--bad)" : "var(--ok)" }}>{["allowed", "approved", "denied"].includes(r.policy.result) ? t(`data.run.policy.${r.policy.result}`) : r.policy.result}</b></span>
          {r.exitCode !== undefined ? <span>{t("data.run.exitCode")} <span className="mono">{r.exitCode}</span></span> : null}
        </div>

        {running && live ? (
          <div className="live">
            <div className="live-top">
              <Loader2 size={13} className="spin" />
              <span>{live.phase ?? t("data.run.starting")}</span>
              <span style={{ flex: 1 }} />
              {live.pct !== undefined ? <span className="mono">{live.pct.toFixed(0)}%{live.etc ? ` · ${t("data.run.eta", { time: live.etc })}` : ""}</span> : null}
            </div>
            <div className="bar-track"><div className={`bar-fill ${live.pct === undefined ? "indeterminate" : ""}`} style={live.pct !== undefined ? { width: `${live.pct}%` } : undefined} /></div>
          </div>
        ) : null}
        {live && live.ports.length ? (
          <div className="ports">
            <span className="muted">{t("data.run.openPortsFound")}</span>
            {live.ports.map((p) => <span key={p} className="badge ok mono">{p}</span>)}
          </div>
        ) : null}

        {r.policy.reason ? <div className="verdict deny" style={{ marginTop: 12 }}><Ban size={16} /> {r.policy.reason}</div> : null}
        {r.summary?.ingested ? (
          <div className="verdict allow" style={{ marginTop: 12 }}>
            <CheckCircle2 size={16} /> {summarize(r.summary.ingested)} · {t("data.run.edges", { n: r.summary.ingested.edges })}
            <div style={{ flex: 1 }} />
            <button className="btn sm" onClick={() => workbench.openPanel("services")}>{t("data.run.viewServices")}</button>
          </div>
        ) : null}
      </div>
      <div
        className="panel-scroll"
        ref={scroller}
        style={{ background: "var(--bg-0)" }}
        onScroll={(e) => {
          const el = e.currentTarget;
          stick.current = el.scrollHeight - el.scrollTop - el.clientHeight < 40;
        }}
      >
        <pre className="run-out">
          {output ||
            (running
              ? t("data.run.output.waiting")
              : r.origin === "terminal"
                ? t("data.run.output.terminal")
                : "")}
        </pre>
      </div>
    </div>
  );
}
