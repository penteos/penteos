import { KeyRound, Plus, Save, Trash2, UserRound } from "./icons";
import { useEffect, useState } from "react";
import { can, useApp, useOperation } from "../state";
import { toast } from "./bits";
import { t } from "../i18n";

/**
 * Rules of engagement: what the operator settles up front so the agents do not
 * have to ask in the middle of the work - test accounts, what is allowed, what to avoid.
 * Passwords go to the vault as secrets; the rules only name them.
 */

export interface AccountDraft {
  label: string;
  username: string;
  password: string;
  role: string;
  /** Secret already saved for this account (editing an existing one). */
  secret?: string;
}

/** Role names, read from the catalogs when used (getters keep `ROLE_ES[k]` and `Object.entries` working). */
export const ROLE_ES: Record<string, string> = Object.defineProperties(
  {} as Record<string, string>,
  Object.fromEntries(["admin", "user", "low", "service", "other"].map((k) => [k, { enumerable: true, get: () => t(`start.rules.role.${k}`) }])),
);

const slug = (s: string) => s.toLowerCase().normalize("NFD").replace(/[̀-ͯ]/g, "").replace(/[^a-z0-9]+/g, "_").replace(/^_|_$/g, "").slice(0, 40) || "cuenta";

/** Saves the passwords as secrets and the rules that point to them. Used by Alcance and by the project assistant. */
export async function saveRules(
  client: { call: <T = unknown>(op: string, input?: unknown) => Promise<T> }, // i18n-ignore: type arguments, not text
  accounts: AccountDraft[],
  allowed: string,
  avoid: string,
  noSubdomains?: boolean,
): Promise<void> {
  const out = [];
  for (const a of accounts.filter((x) => x.username.trim())) {
    let secret = a.secret;
    if (a.password) {
      secret = `cuenta_${slug(a.label || a.username)}`;
      await client.call("secret.save", { name: secret, kind: "password", value: a.password });
    }
    out.push({ label: a.label.trim() || a.username.trim(), username: a.username.trim(), role: a.role, ...(secret ? { secret } : {}) });
  }
  await client.call("rules.set", { accounts: out, allowed: allowed.trim(), avoid: avoid.trim(), ...(noSubdomains !== undefined ? { noSubdomains } : {}) });
}

export function AccountRows(props: { accounts: AccountDraft[]; onChange: (a: AccountDraft[]) => void; disabled?: boolean }) {
  const set = (i: number, patch: Partial<AccountDraft>) => props.onChange(props.accounts.map((a, j) => (j === i ? { ...a, ...patch } : a)));
  return (
    <div className="accounts">
      {props.accounts.map((a, i) => (
        <div key={i} className="account-row">
          <UserRound size={13} className="muted" />
          <input className="input sm" placeholder={t("start.rules.account.purpose")} value={a.label} disabled={props.disabled} onChange={(e) => set(i, { label: e.target.value })} />
          <input className="input sm mono" placeholder={t("start.rules.account.username")} value={a.username} disabled={props.disabled} onChange={(e) => set(i, { username: e.target.value })} />
          <input className="input sm mono" type="password" placeholder={a.secret ? t("start.rules.account.passwordKept") : t("start.rules.account.password")} value={a.password} disabled={props.disabled} onChange={(e) => set(i, { password: e.target.value })} />
          <select className="input sm" value={a.role} disabled={props.disabled} onChange={(e) => set(i, { role: e.target.value })}>
            {Object.entries(ROLE_ES).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
          </select>
          {props.disabled ? null : <button className="btn sm ghost" title={t("common.remove")} onClick={() => props.onChange(props.accounts.filter((_, j) => j !== i))}><Trash2 size={12} /></button>}
        </div>
      ))}
      {props.disabled ? null : (
        <button className="btn sm ghost" style={{ alignSelf: "flex-start" }} onClick={() => props.onChange([...props.accounts, { label: "", username: "", password: "", role: props.accounts.length ? "low" : "admin" }])}>
          <Plus size={12} /> {t("start.rules.account.add")}
        </button>
      )}
    </div>
  );
}

interface Rules {
  accounts: Array<{ label: string; username: string; secret?: string; role: string }>;
  allowed: string;
  avoid: string;
  noSubdomains?: boolean;
}

export function RulesSection() {
  const { client, me } = useApp();
  const rules = useOperation<Rules>("rules.get", {}, { refreshOn: (e) => e.type === "engagement.updated" });
  const editable = can(me, "lead");
  const [accounts, setAccounts] = useState<AccountDraft[]>([]);
  const [allowed, setAllowed] = useState("");
  const [avoid, setAvoid] = useState("");
  const [noSubdomains, setNoSubdomains] = useState(false);
  const [dirty, setDirty] = useState(false);
  useEffect(() => {
    if (!rules.data || dirty) return;
    setAccounts(rules.data.accounts.map((a) => ({ label: a.label, username: a.username, password: "", role: a.role, ...(a.secret ? { secret: a.secret } : {}) })));
    setAllowed(rules.data.allowed);
    setAvoid(rules.data.avoid);
    setNoSubdomains(Boolean(rules.data.noSubdomains));
  }, [rules.data, dirty]);
  async function save() {
    try {
      await saveRules(client, accounts, allowed, avoid, noSubdomains);
      setDirty(false);
      rules.reload();
      toast("ok", t("start.rules.saved"), t("start.rules.saved.body"));
    } catch (e) {
      toast("bad", t("common.notSaved"), (e as Error).message);
    }
  }
  const touch = <T,>(fn: (v: T) => void) => (v: T) => {
    setDirty(true);
    fn(v);
  };
  return (
    <div className="rules-section">
      <div className="section-title"><KeyRound size={12} /> {t("start.rules.title")}</div>
      <div className="muted" style={{ fontSize: 12, lineHeight: 1.5, marginBottom: 8 }}>
        {t("start.rules.lead")}
      </div>
      <AccountRows accounts={accounts} onChange={touch(setAccounts)} disabled={!editable} />
      <div className="rules-texts">
        <label>{t("start.rules.allowed")}<textarea className="input" rows={3} disabled={!editable} placeholder={t("start.rules.allowedPlaceholder")} value={allowed} onChange={(e) => touch(setAllowed)(e.target.value)} /></label>
        <label>{t("start.rules.avoid")}<textarea className="input" rows={3} disabled={!editable} placeholder={t("start.rules.avoidPlaceholder")} value={avoid} onChange={(e) => touch(setAvoid)(e.target.value)} /></label>
      </div>
      <label className="check" style={{ flexDirection: "row", margin: "4px 0 10px" }}>
        <input type="checkbox" disabled={!editable} checked={noSubdomains} onChange={(e) => touch(setNoSubdomains)(e.target.checked)} />
        {t("start.rules.noSubdomains")}
      </label>
      {editable ? <button className="btn sm primary" disabled={!dirty} onClick={save}><Save size={12} /> {t("start.rules.save")}</button> : null}
    </div>
  );
}
