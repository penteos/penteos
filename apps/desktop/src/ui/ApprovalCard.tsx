import { Bot, Check, ChevronDown, Copy, FileWarning, Milestone, ShieldCheck, SquareTerminal } from "./icons";
import { useState } from "react";
import { type Approval, useApp } from "../state";
import { toast, useTick } from "./bits";
import { ago, locale, t, tn } from "../i18n";
import { approvalNotes, approvalSummary, approvalWhy } from "./approvalText";
import { severity } from "../labels";
import { permissionText, ProposalCode, ptext } from "./plugins";
import { timeLeft } from "./timeLeft";

/** Approval kinds with their own wording (catalog keys agent.approval.<kind>.title/.accept/.note). */
const KINDS: Record<string, { note: boolean }> = {
  scope: { note: true },
  install: { note: true },
  install_kit: { note: true },
  capability: { note: true },
  manifest: { note: true },
  phase: { note: false },
  proxy_rules: { note: true },
  findings: { note: true },
  plugin: { note: true },
};

function titles(kind: string): { title: string; accept: string; note?: string } {
  const k = KINDS[kind];
  if (!k) return { title: t("agent.approval.default.title"), accept: t("common.accept") };
  return {
    title: t(`agent.approval.${kind}.title`),
    accept: t(`agent.approval.${kind}.accept`),
    ...(k.note ? { note: t(`agent.approval.${kind}.note`) } : {}),
  };
}

export type ApprovalResult = { status: string; command?: string; runId?: string };
type Result = ApprovalResult;

/** Puts a command in the integrated terminal without running it, so the operator decides. */
function toTerminal(command: string, openTerminal: () => void) {
  openTerminal();
  setTimeout(() => (window as unknown as { __penteosTerm?: (t: string) => void }).__penteosTerm?.(command), 200);
}

/** What remains on screen after accepting an install: the command to run, or the live install. */
export function InstallFollowUp(props: { result: ApprovalResult; inline?: boolean }) {
  const { workbench } = useApp();
  const { result } = props;
  if (result.status === "manual_install" && result.command) {
    return (
      <div className={`approval-card ${props.inline ? "inline" : ""}`}>
        <div className="head"><SquareTerminal size={13} /> {t("agent.install.manual.title")}</div>
        <div className="why">{t("agent.install.manual.body")}</div>
        <code className="cmd mono">{result.command}</code>
        <div className="actions">
          <button className="btn sm primary" onClick={() => toTerminal(result.command!, () => workbench.openPanel("terminal"))}>
            <SquareTerminal size={12} /> {t("agent.install.toTerminal")}
          </button>
          <button className="btn sm" onClick={() => navigator.clipboard.writeText(result.command!).then(() => toast("ok", t("agent.commandCopied")))}>
            <Copy size={12} /> {t("common.copy")}
          </button>
        </div>
      </div>
    );
  }
  if (result.status === "running" && result.runId) {
    return (
      <div className="approval-done approved">
        <Check size={12} /> {t("agent.install.running")} <button className="btn ghost sm" onClick={() => workbench.openRun(result.runId!)}>{t("agent.install.progress")}</button>
      </div>
    );
  }
  return null;
}

export function ApprovalCard(props: { approval: Approval; inline?: boolean; onDecided?: (approved: boolean, summary: string, result?: ApprovalResult) => void }) {
  const { client, workbench } = useApp();
  const a = props.approval;
  const kind = a.request?.kind ?? "exec";
  const meta = titles(kind);
  const summary = approvalSummary(a);
  // How long it can still wait: shown always, in amber in its last half hour.
  const now = useTick(30_000);
  const msLeft = a.expiresAt ? Date.parse(a.expiresAt) - now : undefined;
  const left = msLeft === undefined ? "" : msLeft <= 0 ? t("agent.approval.expiringNow") : timeLeft(msLeft);
  const soon = msLeft !== undefined && msLeft < 30 * 60_000;
  const [busy, setBusy] = useState(false);
  const [showManifest, setShowManifest] = useState(false);
  // A code plugin the Maestro wrote: reviewed by a person, isolated unless they free it (Python runs free).
  const code = a.request?.kind === "plugin" ? a.request.proposal?.code : undefined;
  const [showCode, setShowCode] = useState(false);
  const [reviewed, setReviewed] = useState(false);
  const [trust, setTrust] = useState<"isolated" | "free">(code?.runtime === "python" ? "free" : "isolated");
  // Findings: everything ticked to start; what the operator unticks stays in review.
  const findings = a.request?.kind === "findings" ? (a.request.findings ?? []) : [];
  const [picked, setPicked] = useState<Set<string>>(() => new Set(findings.map((f) => f.id)));
  const toggle = (id: string) => setPicked((p) => { const n = new Set(p); if (n.has(id)) n.delete(id); else n.add(id); return n; });

  const canGrant = (kind === "exec" || kind === "nmap") && (a.request?.kind === "nmap" || (a.request?.targets ?? []).length > 0);

  async function decide(approve: boolean, forSession = false) {
    setBusy(true);
    try {
      const r = await client.call<Result>(approve ? "approval.approve" : "approval.reject", { approvalId: a.id, ...(approve && forSession ? { forSession: true } : {}), ...(approve && kind === "findings" ? { only: [...picked] } : {}), ...(approve && code ? { plugin: { reviewedCode: reviewed, trust } } : {}) });
      const followUp = approve && (kind === "install" || kind === "install_kit") ? r : undefined;
      if (!followUp) toast(approve ? "ok" : "info", approve ? t("agent.approval.accepted") : t("agent.approval.rejected"), summary);
      props.onDecided?.(approve, summary, followUp);
    } catch (e) {
      toast("bad", t("agent.approval.failed"), (e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div id={`approval-${a.id}`} className={`approval-card ${props.inline ? "inline" : ""}`}>
      <div className="head">{kind === "phase" ? <Milestone size={13} color="var(--accent)" /> : kind === "findings" ? <ShieldCheck size={13} color="var(--accent)" /> : <Bot size={13} color="var(--accent)" />} <span className="head-t">{meta.title}</span><span className={`kick mono ${soon ? "soon" : ""}`} title={`${ago(a.createdAt)}${a.expiresAt ? ` · ${new Date(a.expiresAt).toLocaleString(locale())}` : ""}`}>{left ? t("agent.approval.expiresIn", { time: left }) : ago(a.createdAt)}</span></div>
      <div className={`s ${kind === "exec" || kind === "nmap" ? "mono cmdline" : ""}`} title={summary}>{summary}</div>
      <div className={`why ${kind === "phase" ? "phase-summary" : ""}`}>{approvalWhy(a)}</div>
      {[...(a.warnings ?? []), ...approvalNotes(a)].map((w) => (
        <div key={w} className="warn-line"><FileWarning size={12} /> {w}</div>
      ))}
      {kind === "plugin" && a.request?.proposal ? (
        <div className="plugin-proposal">
          {a.request.proposal.description ? <div className="pp-desc">{ptext(a.request.proposal.description)}</div> : null}
          <div className="pp-row"><span className="pp-k">{t("plugins.proposal.ops")}</span> {a.request.proposal.operations.map((o) => `${ptext(o.title)}${o.agent ? ` (${t("plugins.proposal.maestroTool")})` : ""}`).join(" · ") || "-"}</div>
          {a.request.proposal.entityTypes.length || a.request.proposal.menus || a.request.proposal.events.length || a.request.proposal.providers.length ? (
            <div className="pp-row"><span className="pp-k">{t("plugins.proposal.adds")}</span> {[
              a.request.proposal.entityTypes.length ? tn("plugins.proposal.types", a.request.proposal.entityTypes.length) : "",
              a.request.proposal.menus ? tn("plugins.proposal.menus", a.request.proposal.menus) : "",
              a.request.proposal.events.length ? tn("plugins.proposal.events", a.request.proposal.events.length) : "",
              a.request.proposal.providers.length ? tn("plugins.proposal.providers", a.request.proposal.providers.length) : "",
            ].filter(Boolean).join(" · ")}</div>
          ) : null}
          <ul className="plugin-perms">
            {a.request.proposal.permissions.map((p) => <li key={p} className={p.startsWith("net:") ? "warn" : ""}>{permissionText(p)}</li>)}
          </ul>
          <div className="pp-row">{a.request.proposal.sendsTo.length ? <span className="pp-warn">{t("plugins.sendsTo", { hosts: a.request.proposal.sendsTo.join(", ") })}</span> : t("plugins.local")}</div>
          {a.request.proposal.evidence ? <div className="pp-evidence">{a.request.proposal.evidence}</div> : null}
          {a.request.proposal.live ? (
            <details className="pp-live">
              <summary>{t("plugins.proposal.live", { input: Object.values(a.request.proposal.live.input).map(String).join(", ").slice(0, 80) || a.request.proposal.live.operation })}</summary>
              {a.request.proposal.live.checks.length ? <div className="pp-row muted">{t("plugins.proposal.checks")}: {a.request.proposal.live.checks.join(" · ")}</div> : null}
              <pre className="code-view mono">{[...a.request.proposal.live.requests, "", a.request.proposal.live.sample].join("\n")}</pre>
            </details>
          ) : (
            <div className="pp-row muted">{t("plugins.proposal.tested", { op: a.request.proposal.test.operation, steps: a.request.proposal.test.steps, requests: a.request.proposal.test.requests })}</div>
          )}
          {code ? (
            <>
              <div className="pp-row">
                <span className="pp-k">{t("plugins.proposal.code")}</span> {tn("plugins.proposal.files", code.files.length)} · {code.runtime === "python" ? "Python" : "Node.js"}
                <button className="link-btn" onClick={() => setShowCode((v) => !v)}>{showCode ? t("plugins.proposal.hideCode") : code.diff ? t("plugins.proposal.showChanges") : t("plugins.proposal.showCode")}</button>
              </div>
              {showCode ? <ProposalCode pluginId={a.request.proposal.pluginId} code={code} /> : null}
              {code.runtime === "python" ? (
                <div className="pp-row muted">{t("plugins.proposal.pythonFree")}</div>
              ) : (
                <div className="pp-trust">
                  {(["isolated", "free"] as const).map((v) => (
                    <label key={v} className={trust === v ? "on" : ""} title={t(`plugins.trust.${v}.hint`)}>
                      <input type="radio" name={`trust-${a.id}`} checked={trust === v} onChange={() => setTrust(v)} /> {t(`plugins.trust.${v}`)}
                    </label>
                  ))}
                </div>
              )}
              <label className="pp-reviewed">
                <input type="checkbox" checked={reviewed} onChange={(e) => setReviewed(e.target.checked)} /> {t("plugins.proposal.reviewed")}
              </label>
            </>
          ) : null}
        </div>
      ) : null}
      {kind === "findings" ? (
        <div className="finding-picks">
          {findings.map((f) => (
            <label key={f.id} className={`fp ${picked.has(f.id) ? "on" : ""}`}>
              <input type="checkbox" checked={picked.has(f.id)} onChange={() => toggle(f.id)} />
              <span className="fp-body">
                <span className="fp-t">{f.title}</span>
                <span className="fp-meta">
                  <span className={`sev ${f.severity}`}>{severity(f.severity)}</span>
                  <span className={`fp-v ${f.verdict === "reproduced" ? "ok" : "warn"}`}>{f.verdict ? t(`agent.verdict.${f.verdict}`) : t("agent.approval.findings.unverified")}</span>
                </span>
              </span>
            </label>
          ))}
        </div>
      ) : null}
      {meta.note ? <div className="note">{meta.note}</div> : null}
      {kind === "manifest" && a.request?.manifest ? (
        <>
          <button className="btn ghost sm" style={{ marginTop: 6, paddingLeft: 0 }} onClick={() => setShowManifest((v) => !v)}>
            <ChevronDown size={12} style={{ transform: showManifest ? "none" : "rotate(-90deg)" }} /> {t("agent.approval.showManifest")}
          </button>
          {showManifest ? <pre className="manifest mono">{JSON.stringify(a.request.manifest, null, 2)}</pre> : null}
        </>
      ) : null}
      {kind === "findings" ? (
        <div className="actions">
          <button className="btn sm primary" disabled={busy || picked.size === 0} onClick={() => decide(true)}>
            {tn("agent.approval.findings.accept", picked.size)}
          </button>
          <button className="btn sm" disabled={busy} onClick={() => workbench.openPanel("findings")}>
            {t("agent.approval.findings.review")}
          </button>
          <button className="link-btn fp-later" disabled={busy} onClick={() => decide(false)} title={t("agent.approval.findings.laterHint")}>
            {t("agent.approval.findings.later")}
          </button>
        </div>
      ) : (
      <div className="actions">
        <button className="btn sm primary" disabled={busy || (Boolean(code) && !reviewed)} onClick={() => decide(true)} title={canGrant ? t("agent.approval.once.hint") : undefined}>{canGrant ? t("agent.approval.once") : meta.accept}</button>
        {canGrant ? (
          <button className="btn sm" disabled={busy} onClick={() => decide(true, true)} title={t("agent.approval.session.hint")}>
            {t("agent.approval.session")}
          </button>
        ) : null}
        <button className="btn sm danger" disabled={busy} onClick={() => decide(false)}>{t("common.reject")}</button>
      </div>
      )}
    </div>
  );
}
