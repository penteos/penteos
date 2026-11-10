import { CvssCalculator } from "../ui/CvssCalculator";
import { PluginEntityActions, PluginEntityPanels, PluginExtData } from "../ui/plugins";
import { ArrowRight, BookPlus, Bot, Check, CornerUpLeft, Send, User } from "../ui/icons";
import { useEffect, useState } from "react";
import { type Entity, useApp, useOperation } from "../state";
import { Badge, toast } from "../ui/bits";
import { Markdown } from "../ui/Markdown";
import { VerificationBox, type VerificationState } from "../ui/Verification";
import { ImpactBox, type ImpactState } from "../ui/Impact";
import { FINDING_STATUS_ES as STATUS_ES, SEVERITY_ES as SEV_ES } from "../labels";
import { t } from "../i18n";

const SEVERITIES = ["critical", "high", "medium", "low", "info"] as const;
const RETEST = ["fixed", "partially_fixed", "not_fixed", "not_verifiable"] as const;

interface Evidence extends Entity {
  excerpt: string;
}

function EvidenceItem(props: { id: string }) {
  const { client } = useApp();
  const [ev, setEv] = useState<Evidence>();
  useEffect(() => {
    client.call<Evidence>("evidence.get", { id: props.id }).then(setEv, () => {});
  }, [client, props.id]);
  if (!ev) return null;
  return (
    <div className="evidence">
      <div className="cap">{String(ev.attributes.caption)}</div>
      <pre className="mono">{ev.excerpt || t("work.detail.evidenceEmpty")}</pre>
    </div>
  );
}

function AssetLink(props: { id: string; location?: string }) {
  const { client, workbench } = useApp();
  const [entity, setEntity] = useState<Entity>();
  useEffect(() => {
    client.call<Entity>("entity.get", { id: props.id }).then(setEntity, () => {});
  }, [client, props.id]);
  const label = entity ? String(entity.attributes.origin ?? entity.attributes.fqdn ?? entity.attributes.ip ?? entity.naturalKey) : "…";
  return (
    <div className="rel" onClick={() => entity && workbench.openEntity(entity.id, label)}>
      <span className="t">{entity?.kind ?? ""}</span>
      <span className="mono" style={{ color: "var(--fg-0)", flex: 1 }}>{label}</span>
      {props.location ? <span className="muted">{props.location}</span> : null}
      <ArrowRight size={13} color="var(--fg-3)" />
    </div>
  );
}

export function FindingDetailPanel(props: { params: { id: string } }) {
  const { client } = useApp();
  const finding = useOperation<Entity>("entity.get", { id: props.params.id }, { refreshOn: (e) => e.id === props.params.id });
  const f = finding.data;
  const [form, setForm] = useState<Record<string, string>>({});
  const [dirty, setDirty] = useState(false);

  useEffect(() => {
    if (!f || dirty) return;
    setForm({
      title: String(f.attributes.title ?? ""),
      severity: String(f.attributes.severity ?? "medium"),
      description: String(f.attributes.description ?? ""),
      impact: String(f.attributes.impact ?? ""),
      remediation: String(f.attributes.remediation ?? ""),
    });
  }, [f, dirty]);

  if (!f) return null;
  const a = f.attributes;
  const status = String(a.status);
  const byAgent = f.createdBy.type === "agent";
  const set = (k: string, v: string) => {
    setForm((x) => ({ ...x, [k]: v }));
    setDirty(true);
  };

  async function save() {
    try {
      await client.call("finding.update", { id: f!.id, ...form });
      setDirty(false);
      toast("ok", t("work.detail.saved"));
    } catch (e) {
      toast("bad", t("common.notSaved"), (e as Error).message);
    }
  }
  async function move(next: string) {
    const v = a.verification as VerificationState | undefined;
    if (next === "approved" && v?.state === "done" && v.verdict === "not_reproduced" && !window.confirm(t("work.detail.approveNotReproduced", { summary: v.summary ?? "" }))) return;
    try {
      if (dirty) await save();
      await client.call("finding.set_status", { id: f!.id, status: next });
      toast("ok", t("work.detail.statusChanged", { status: STATUS_ES[next] }));
    } catch (e) {
      toast("bad", t("work.detail.statusFailed"), (e as Error).message);
    }
  }

  const missing = [
    !((a.evidenceIds as string[] | undefined) ?? []).length ? t("work.detail.missing.evidence") : "",
    !form.remediation?.trim() ? t("work.detail.missing.remediation") : "",
    !form.description?.trim() ? t("work.detail.missing.description") : "",
  ].filter(Boolean);

  return (
    <div className="panel">
      <div className="panel-scroll">
        <div className="detail-head">
          <div className="kind">
            {t("work.detail.kind")} {a.templateRef ? <Badge>{t("work.detail.template", { id: String(a.templateRef) })}</Badge> : null} <Badge tone={status === "approved" || status === "reported" ? "ok" : status === "in_review" ? "accent" : ""}>{STATUS_ES[status] ?? status}</Badge>
            <Badge tone={byAgent ? "agent" : "info"}>{byAgent ? <Bot size={11} /> : <User size={11} />} {byAgent ? t("work.detail.byAgent") : t("work.detail.byOperator")}</Badge>
          </div>
          <input className="input finding-title" value={form.title ?? ""} onChange={(e) => set("title", e.target.value)} />
          <div className="seg" style={{ marginTop: 8 }}>
            {SEVERITIES.map((s) => (
              <button key={s} className={form.severity === s ? "on" : ""} onClick={() => set("severity", s)}>
                <span className={`sev ${s}`}>{SEV_ES[s]}</span>
              </button>
            ))}
          </div>
          <div className="workflow">
            {status === "draft" ? <button className="btn sm" onClick={() => move("in_review")}><Send size={12} /> {t("work.detail.toReview")}</button> : null}
            {status === "draft" || status === "in_review" ? (
              <button className="btn sm primary" onClick={() => move("approved")} title={missing.length ? t("work.detail.missing", { list: missing.join(", ") }) : t("work.detail.approveHint")}>
                <Check size={12} /> {t("common.approve")}
              </button>
            ) : null}
            {status === "in_review" || status === "approved" ? <button className="btn sm ghost" onClick={() => move("draft")}><CornerUpLeft size={12} /> {t("work.detail.backToDraft")}</button> : null}
            {status === "approved" ? <button className="btn sm" onClick={() => move("reported")}>{t("work.detail.markReported")}</button> : null}
            {f!.tags.includes("retest") || ["reported", "fixed", "partially_fixed", "not_fixed", "not_verifiable", "reopened"].includes(status) ? (
              <span className="retest-pick">
                <span className="muted">{t("work.detail.retest")}</span>
                {RETEST.map((k) => (
                  <button key={k} className={`btn sm ${status === k ? "primary" : "ghost"}`} onClick={() => move(k)}>{t(`work.detail.retest.${k}`)}</button>
                ))}
              </span>
            ) : null}
            <button
              className="btn sm ghost"
              title={t("work.detail.library.hint")}
              onClick={() =>
                client
                  .call<{ id: string }>("library.save", { fromFindingId: f!.id })
                  .then((saved) => toast("ok", t("work.detail.library.saved"), t("work.detail.library.savedBody", { id: saved.id })))
                  .catch((e: Error) => toast("bad", t("common.notSaved"), e.message))
              }
            >
              <BookPlus size={12} /> {t("work.detail.library.save")}
            </button>
            <PluginEntityActions entityId={f!.id} kind="finding" />
            {dirty ? <button className="btn sm primary" onClick={save}>{t("work.detail.saveChanges")}</button> : null}
            {missing.length && (status === "draft" || status === "in_review") ? <span className="muted" style={{ fontSize: 12 }}>{t("work.detail.missing", { list: missing.join(", ") })}</span> : null}
          </div>
        </div>

        <PluginExtData ext={f.ext} />
        <PluginEntityPanels entityId={f.id} kind="finding" />

        <VerificationBox
          findingId={f.id}
          {...(a.verification ? { v: a.verification as VerificationState } : {})}
          evidence={(ids) => ids.map((id) => <EvidenceItem key={id} id={id} />)}
        />

        <ImpactBox findingId={f.id} closed={["fixed", "wont_fix", "not_verifiable"].includes(status)} {...(a.deepening ? { d: a.deepening as ImpactState } : {})} />

        <div className="form">
          <label>{t("work.detail.field.description")}
            <textarea className="input" rows={5} value={form.description ?? ""} onChange={(e) => set("description", e.target.value)} placeholder={t("work.detail.field.descriptionPlaceholder")} />
          </label>
          <label>{t("work.detail.field.impact")}
            <textarea className="input" rows={3} value={form.impact ?? ""} onChange={(e) => set("impact", e.target.value)} placeholder={t("work.detail.field.impactPlaceholder")} />
          </label>
          <label>{t("work.detail.field.remediation")}
            <textarea className="input" rows={3} value={form.remediation ?? ""} onChange={(e) => set("remediation", e.target.value)} placeholder={t("work.detail.field.remediationPlaceholder")} />
          </label>
        </div>

        <CvssCalculator findingId={f!.id} severity={String(a.severity)} {...(a.cvss ? { current: a.cvss as { version: string; vector: string; score: number } } : {})} />

        <div className="section-title">{t("work.detail.affectedAssets")}</div>
        {((a.instances as Array<{ id: string; entity: { id: string }; location?: string }>) ?? []).map((i) => (
          <AssetLink key={i.id} id={i.entity.id} {...(i.location ? { location: i.location } : {})} />
        ))}

        <div className="section-title">{t("work.detail.evidence")}</div>
        <div style={{ padding: "0 20px 20px", display: "flex", flexDirection: "column", gap: 10 }}>
          {((a.evidenceIds as string[]) ?? []).length === 0 ? (
            <span className="muted">{t("work.detail.noEvidence")}</span>
          ) : (
            (a.evidenceIds as string[]).map((id) => <EvidenceItem key={id} id={id} />)
          )}
        </div>

        {form.description ? (
          <>
            <div className="section-title">{t("work.detail.preview")}</div>
            <div className="turn-agent" style={{ padding: "0 20px 24px" }}><Markdown text={form.description} /></div>
          </>
        ) : null}
      </div>
    </div>
  );
}
