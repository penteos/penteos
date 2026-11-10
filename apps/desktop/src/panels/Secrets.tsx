import { risk } from "../labels";
import { Copy, Eye, EyeOff, KeyRound, ShieldCheck, Trash2 } from "../ui/icons";
import { useState } from "react";
import { can, useApp, useOperation } from "../state";
import { ActorBadge, relTime, toast, useTick } from "../ui/bits";
import { t } from "../i18n";
import { HelpHint } from "../ui/HelpHint";

interface Secret {
  name: string;
  kind: string;
  note?: string;
  createdBy: { type: "human" | "agent" | "parser" | "system"; id: string };
  createdAt: string;
  ref: string;
}
interface Grant {
  id: string;
  tool: string;
  targets: string[];
  risk: string;
  at: string;
}

const KINDS = ["password", "token", "cookie", "api_key", "key", "other"];
const kindLabel = (k: string) => (KINDS.includes(k) ? t(`data.secrets.kind.${k}`) : k);

/**
 * Credentials and sessions of the engagement. Agents use them as {{secret:name}}: the value is
 * substituted only when a command runs and is hidden from logs, outputs and the conversation.
 */
export function SecretsPanel() {
  const { client, me } = useApp();
  const now = useTick();
  const secrets = useOperation<Secret[]>("secret.list", {}, { refreshOn: (e) => e.type === "engagement.updated" });
  const grants = useOperation<Grant[]>("approval.grants", {}, { refreshOn: (e) => e.type === "engagement.updated" });
  const [shown, setShown] = useState<Record<string, string>>({});
  const [name, setName] = useState("");
  const [kind, setKind] = useState("password");
  const [value, setValue] = useState("");
  const [note, setNote] = useState("");
  const mayReveal = can(me, "operator");

  async function reveal(s: Secret) {
    if (shown[s.name]) {
      setShown(({ [s.name]: _, ...rest }) => rest);
      return;
    }
    try {
      const r = await client.call<{ value: string }>("secret.reveal", { name: s.name });
      setShown((m) => ({ ...m, [s.name]: r.value }));
    } catch (e) {
      toast("bad", t("data.secrets.revealFailed"), (e as Error).message);
    }
  }
  async function add() {
    try {
      await client.call("secret.save", { name: name.trim(), kind, value, ...(note.trim() ? { note: note.trim() } : {}) });
      toast("ok", t("data.secrets.saved"), t("data.secrets.savedBody", { ref: `{{secret:${name.trim().toLowerCase()}}}` }));
      setName("");
      setValue("");
      setNote("");
    } catch (e) {
      toast("bad", t("common.notSaved"), (e as Error).message);
    }
  }

  return (
    <div className="panel">
      <div className="panel-toolbar">
        <KeyRound size={14} />
        <h3>{t("data.secrets.title")}</h3>
        <span className="count">{(secrets.data ?? []).length}</span>
        <HelpHint id="secrets" text={t("data.secrets.hint")} />
      </div>
      <div className="panel-scroll">
        <div className="op">
          <section className="op-section">
            <table className="tbl boxed">
              <thead>
                <tr><th style={{ width: 34 }} /><th>{t("data.secrets.col.name")}</th><th>{t("data.secrets.col.kind")}</th><th>{t("data.secrets.col.purpose")}</th><th>{t("data.secrets.col.value")}</th><th>{t("data.secrets.col.savedBy")}</th><th style={{ width: 110 }} /></tr>
              </thead>
              <tbody>
                {(secrets.data ?? []).map((s) => (
                  <tr key={s.name}>
                    <td className="ic"><KeyRound size={13} /></td>
                    <td>
                      <div className="mono">{s.name}</div>
                      <button className="ref-chip mono" title={t("data.secrets.copyRef")} onClick={() => navigator.clipboard.writeText(s.ref).then(() => toast("ok", t("data.secrets.refCopied"), s.ref))}>
                        {s.ref} <Copy size={10} />
                      </button>
                    </td>
                    <td className="muted">{kindLabel(s.kind)}</td>
                    <td className="muted">{s.note ?? "-"}</td>
                    <td className="mono">{shown[s.name] ? <span className="secret-value">{shown[s.name]}</span> : <span className="muted">••••••••</span>}</td>
                    <td className="muted nowrap"><ActorBadge actor={s.createdBy} /> {relTime(s.createdAt, now)}</td>
                    <td style={{ textAlign: "right", whiteSpace: "nowrap" }}>
                      {mayReveal ? (
                        <button className="btn sm ghost" title={shown[s.name] ? t("common.hide") : t("data.secrets.revealTitle")} onClick={() => reveal(s)}>
                          {shown[s.name] ? <EyeOff size={12} /> : <Eye size={12} />}
                        </button>
                      ) : null}
                      {mayReveal ? (
                        <button className="btn sm ghost" title={t("common.delete")} onClick={() => client.call("secret.delete", { name: s.name }).catch((e: Error) => toast("bad", t("common.error"), e.message))}>
                          <Trash2 size={12} />
                        </button>
                      ) : null}
                    </td>
                  </tr>
                ))}
                {(secrets.data ?? []).length === 0 ? (
                  <tr><td /><td colSpan={6} className="muted">{t("data.secrets.empty")}</td></tr>
                ) : null}
              </tbody>
            </table>
            {mayReveal ? (
              <div className="add-row">
                <input className="input mono" style={{ width: 170 }} placeholder={t("data.secrets.placeholder.name")} value={name} onChange={(e) => setName(e.target.value)} />
                <select className="input" value={kind} onChange={(e) => setKind(e.target.value)}>
                  {KINDS.map((k) => <option key={k} value={k}>{kindLabel(k)}</option>)}
                </select>
                <input className="input mono" style={{ flex: 1 }} type="password" placeholder={t("data.secrets.placeholder.value")} value={value} onChange={(e) => setValue(e.target.value)} />
                <input className="input" style={{ width: 200 }} placeholder={t("data.secrets.placeholder.purpose")} value={note} onChange={(e) => setNote(e.target.value)} />
                <button className="btn" disabled={!name.trim() || !value} onClick={add}>{t("common.save")}</button>
              </div>
            ) : null}
          </section>

          <section className="op-section">
            <div className="sec-head"><ShieldCheck size={13} /> <span>{t("data.secrets.grants.title")}</span></div>
            <table className="tbl boxed">
              <tbody>
                {(grants.data ?? []).map((g) => (
                  <tr key={g.id}>
                    <td className="mono">{g.tool}</td>
                    <td className="mono muted">{g.targets.join(", ")}</td>
                    <td className="muted">{t("data.secrets.grants.upTo", { risk: risk(g.risk) })}</td>
                    <td className="muted">{relTime(g.at, now)}</td>
                    <td style={{ textAlign: "right" }}>
                      {mayReveal ? <button className="btn sm ghost" onClick={() => client.call("approval.revoke_grant", { id: g.id })}>{t("data.secrets.grants.revoke")}</button> : null}
                    </td>
                  </tr>
                ))}
                {(grants.data ?? []).length === 0 ? (
                  <tr><td className="muted">{t("data.secrets.grants.empty")}</td></tr>
                ) : null}
              </tbody>
            </table>
          </section>
        </div>
      </div>
    </div>
  );
}
