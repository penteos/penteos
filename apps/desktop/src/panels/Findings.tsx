import { Bot, Bug, Plus, X } from "../ui/icons";
import { useEffect, useState } from "react";
import { type Entity, useApp, useOperation } from "../state";
import { ActorBadge, Badge, Empty, relTime, toast, useTick } from "../ui/bits";
import { VerificationBadge, type VerificationState } from "../ui/Verification";
import { ImpactBadge, type ImpactState } from "../ui/Impact";
import { FINDING_STATUS_ES as STATUS_ES, SEVERITY_ES as SEV_ES } from "../labels";
import { t, tn } from "../i18n";

const SEVERITIES = ["critical", "high", "medium", "low", "info"] as const;

export function FindingsPanel(props: { params?: { prefill?: { entityId: string; label: string } } }) {
  const { client, workbench, engagement } = useApp();
  const now = useTick();
  const findings = useOperation<Entity[]>("entity.query", { kind: "finding", limit: 2000 }, { refreshOn: (e) => e.kind === "finding" });
  const observations = useOperation<Entity[]>("entity.query", { kind: "observation", limit: 2000 }, { refreshOn: (e) => e.kind === "observation" });
  const [prefill, setPrefill] = useState<{ entityId: string; label: string } | undefined>(props.params?.prefill);
  // The observation being turned into this finding: promoting links the two, so it leaves the list.
  const [fromObservation, setFromObservation] = useState<string>();
  const [creating, setCreating] = useState(Boolean(props.params?.prefill));
  const [title, setTitle] = useState("");
  const [severity, setSeverity] = useState<string>("medium");
  const [description, setDescription] = useState("");
  const [template, setTemplate] = useState("");
  const templates = useOperation<Array<{ id: string; title: string; severity: string; source: string }>>("library.list", {}, { refreshOn: () => false });

  useEffect(() => {
    if (props.params?.prefill) {
      setPrefill(props.params.prefill);
      setCreating(true);
    }
  }, [props.params?.prefill]);

  async function create() {
    if (!title.trim()) return;
    try {
      const instances = prefill ? [{ entityId: prefill.entityId }] : [];
      const created = template
        ? await client.call<{ id: string }>("finding.from_template", { templateId: template, title: title.trim(), severity, description, instances })
        : fromObservation
          ? await client.call<{ id: string }>("observation.promote", { observationIds: [fromObservation], title: title.trim(), severity, description })
          : await client.call<{ id: string }>("finding.create", { title: title.trim(), severity, description, instances });
      workbench.openFinding(created.id, title.trim());
      setTemplate("");
      toast("ok", t("work.findings.created"), title);
      setTitle("");
      setDescription("");
      setPrefill(undefined);
      setFromObservation(undefined);
      setCreating(false);
    } catch (e) {
      toast("bad", t("work.findings.createFailed"), (e as Error).message);
    }
  }

  async function promote(o: Entity) {
    const affected = (o.attributes.affects ?? [])[0] as { id: string } | undefined;
    let label = "";
    if (affected) {
      const target = await client.call<Entity>("entity.get", { id: affected.id }).catch(() => undefined);
      label = target ? String(target.attributes.fqdn ?? target.attributes.origin ?? target.attributes.ip ?? target.naturalKey) : "";
    }
    setTitle(String(o.attributes.title));
    setDescription(String(o.attributes.detail ?? ""));
    setSeverity(String(o.attributes.severityHint ?? "info"));
    setPrefill(affected ? { entityId: affected.id, label } : undefined);
    setFromObservation(o.id);
    setCreating(true);
  }

  // Only what nobody has assessed yet: confirmed ones already live in their finding, and false
  // positives, duplicates and accepted risks were decided.
  const pendingObservations = (observations.data ?? []).filter((o) => !o.attributes.findingId && (o.attributes.triage ?? "new") === "new");
  const list = [...(findings.data ?? [])].sort((a, b) => SEVERITIES.indexOf(a.attributes.severity) - SEVERITIES.indexOf(b.attributes.severity));

  return (
    <div className="panel">
      <div className="panel-toolbar">
        <Bug size={14} color="var(--sev-high)" />
        <h3>{t("work.findings.title")}</h3>
        <span className="count">{list.length}</span>
        <div className="grow" />
        <button className="btn sm primary" onClick={() => { setCreating((v) => !v); setFromObservation(undefined); }}>
          <Plus size={13} /> {t("work.findings.newShort")}
        </button>
      </div>
      {creating ? (
        <div className="form" style={{ borderBottom: "1px solid var(--line)" }}>
          {prefill ? (
            <div style={{ display: "flex", gap: 8, alignItems: "center", color: "var(--fg-2)" }}>
              {t("work.findings.affects")} <Badge tone="accent">{prefill.label}</Badge>
              <button className="btn ghost sm" onClick={() => { setPrefill(undefined); setFromObservation(undefined); }}><X size={12} /></button>
            </div>
          ) : null}
          <select
            className="input"
            value={template}
            onChange={async (e) => {
              const id = e.target.value;
              setTemplate(id);
              if (!id) return;
              const tpl = await client.call<{ title: string; severity: string; description: string }>("library.get", { id });
              setTitle(tpl.title);
              setSeverity(tpl.severity);
              setDescription(tpl.description);
            }}
          >
            <option value="">{t("work.findings.noTemplate")}</option>
            {(templates.data ?? []).map((tpl) => (
              <option key={tpl.id} value={tpl.id}>{tpl.title}{tpl.source === "custom" ? ` · ${t("work.findings.customTemplate")}` : tpl.source === "plugin" ? ` · ${t("work.findings.pluginTemplate")}` : ""}</option>
            ))}
          </select>
          <input className="input" autoFocus placeholder={t("work.findings.titlePlaceholder")} value={title} onChange={(e) => setTitle(e.target.value)} />
          <div className="seg" style={{ alignSelf: "flex-start" }}>
            {SEVERITIES.map((s) => (
              <button key={s} className={severity === s ? "on" : ""} onClick={() => setSeverity(s)}>
                <span className={`sev ${s}`}>{SEV_ES[s]}</span>
              </button>
            ))}
          </div>
          <textarea className="input" rows={4} placeholder={t("work.findings.descriptionPlaceholder")} value={description} onChange={(e) => setDescription(e.target.value)} />
          <div className="row" style={{ justifyContent: "flex-end", display: "flex" }}>
            <button className="btn ghost" style={{ flex: "0 0 auto" }} onClick={() => { setCreating(false); setFromObservation(undefined); }}>{t("common.cancel")}</button>
            <button className="btn primary" style={{ flex: "0 0 auto" }} onClick={create}>{t("work.findings.createDraft")}</button>
          </div>
        </div>
      ) : null}
      <div className="panel-scroll">
        {list.length === 0 && !creating ? (
          <Empty icon={<Bug size={20} />} title={t("work.findings.empty.title")}>
            {t("work.findings.empty.body")}
            <div className="empty-actions">
              <button className="btn sm primary" onClick={() => setCreating(true)}><Plus size={12} /> {t("work.findings.new")}</button>
              {engagement ? <button className="btn sm" onClick={() => window.dispatchEvent(new CustomEvent("penteos:ask-maestro", { detail: t("work.findings.empty.maestroPrompt") }))}><Bot size={12} /> {t("work.findings.empty.askMaestro")}</button> : null}
            </div>
          </Empty>
        ) : (
          list.map((f) => {
            const sev = String(f.attributes.severity);
            const n = (f.attributes.instances ?? []).length;
            const ev = (f.attributes.evidenceIds ?? []).length;
            return (
              <div key={f.id} className={`finding-row sev-${sev}`} onClick={() => workbench.openFinding(f.id, String(f.attributes.title))}>
                <div className="fr-main">
                  <div className="fr-title">{f.attributes.title}</div>
                  <div className="fr-meta">
                    <span className={`sev ${sev}`}>{SEV_ES[sev]}</span>
                    <Badge tone={f.attributes.status === "approved" || f.attributes.status === "reported" ? "ok" : f.attributes.status === "in_review" ? "accent" : ""}>{STATUS_ES[String(f.attributes.status)] ?? f.attributes.status}</Badge>
                    <VerificationBadge {...(f.attributes.verification ? { v: f.attributes.verification as VerificationState } : {})} />
                    <ImpactBadge {...(f.attributes.deepening ? { d: f.attributes.deepening as ImpactState } : {})} />
                    <span className="muted">{n ? tn("work.findings.assets", n) : t("work.findings.noAssets")} · {ev ? tn("work.findings.evidence", ev) : <span style={{ color: "var(--warn)" }}>{t("work.findings.noEvidence")}</span>}</span>
                  </div>
                </div>
                <div className="fr-side">
                  <ActorBadge actor={f.createdBy} />
                  <span className="muted">{relTime(f.createdAt, now)}</span>
                </div>
              </div>
            );
          })
        )}
        {pendingObservations.length ? (
          <>
            <div className="section-title">{t("work.findings.observations")}</div>
            {pendingObservations.map((o) => (
              <div key={o.id} className="row obs-row">
                <span className="obs-rule mono" title={String(o.attributes.sourceRule ?? "")}>{String(o.attributes.sourceRule ?? "")}</span>
                <div style={{ minWidth: 0 }}>
                  <div className="t obs-text" title={String(o.attributes.title)}>{String(o.attributes.title)}</div>
                  {o.attributes.detail ? <div className="s obs-text clamp" title={String(o.attributes.detail)}>{String(o.attributes.detail)}</div> : null}
                </div>
                <div className="when">
                  <ActorBadge actor={o.createdBy} />
                  <button className="btn sm" onClick={() => promote(o)}>{t("work.findings.promote")}</button>
                </div>
              </div>
            ))}
          </>
        ) : null}
      </div>
    </div>
  );
}
