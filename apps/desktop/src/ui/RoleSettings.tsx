import { ShieldCheck, Users } from "./icons";
import { useEffect, useState } from "react";
import type { Provider } from "../panels/AgentSidebar";
import { useApp } from "../state";
import { Modal, toast } from "./bits";
import { t } from "../i18n";

export interface RoleInfo {
  provider?: string;
  model?: string;
  resolved?: string;
  reason?: string;
}

export type AgentRole = "verifier";

const roleText = (role: AgentRole) => ({ title: t(`team.roleSettings.${role}.title`), what: t(`team.roleSettings.${role}.what`) });

/** Model per role: the verifier runs alongside the Maestro, so API providers only. */
export function RoleSettingsModal(props: { role: AgentRole; providers: Provider[]; onClose: () => void }) {
  const { client } = useApp();
  const { role } = props;
  const [info, setInfo] = useState<RoleInfo>();
  const [provider, setProvider] = useState("");
  const [model, setModel] = useState("");
  useEffect(() => {
    client.request<{ roles: Record<AgentRole, RoleInfo> }>("agent.roles").then((r) => {
      setInfo(r.roles[role]);
      setProvider(r.roles[role]?.provider ?? "");
      setModel(r.roles[role]?.model ?? "");
    }, () => {});
  }, [client, role]);
  const usable = props.providers.filter((p) => p.kind !== "cli");
  async function save() {
    const r = await client.request<{ roles: Record<AgentRole, RoleInfo>; error?: string }>("agent.set_role", { role, settings: { ...(provider ? { provider } : {}), ...(model.trim() ? { model: model.trim() } : {}) } });
    if (r.error) return toast("bad", t("common.notSaved"), r.error);
    setInfo(r.roles[role]);
    toast(r.roles[role]?.reason ? "info" : "ok", r.roles[role]?.reason ? t("common.saved") : t("team.roleSettings.resolved", { title: roleText(role).title, model: r.roles[role]?.resolved }), r.roles[role]?.reason);
    props.onClose();
  }
  return (
    <Modal
      title={roleText(role).title}
      icon={role === "verifier" ? <ShieldCheck size={16} /> : <Users size={16} />}
      onClose={props.onClose}
      footer={
        <>
          <button className="btn ghost" onClick={props.onClose}>{t("common.cancel")}</button>
          <button className="btn primary" onClick={save}>{t("common.save")}</button>
        </>
      }
    >
      <span>{roleText(role).what}</span>
      <span style={{ color: "var(--warn)" }}>
        {t("team.roleSettings.apiOnly.before")}<b>{t("team.roleSettings.apiOnly.bold")}</b>{t("team.roleSettings.apiOnly.after")}
      </span>
      <label>{t("team.roleSettings.provider")}
        <select className="input" value={provider} onChange={(e) => setProvider(e.target.value)}>
          <option value="">{t("team.roleSettings.auto")}</option>
          {usable.map((p) => <option key={p.id} value={p.id} disabled={!p.available}>{p.label}{p.available ? "" : ` - ${p.reason ?? t("team.roleSettings.unavailable")}`}</option>)}
        </select>
      </label>
      <label>{t("team.roleSettings.model")} <span className="muted">{t("team.roleSettings.modelHint")}</span>
        <input className="input mono" value={model} onChange={(e) => setModel(e.target.value)} placeholder={t("team.roleSettings.modelPlaceholder")} />
      </label>
      {info ? <span className={info.reason ? "" : "muted"} style={info.reason ? { color: "var(--warn)" } : {}}>{info.reason ?? t("team.roleSettings.current", { model: info.resolved })}</span> : null}
    </Modal>
  );
}
