import { risk as riskLabel } from "../labels";
import { Ban, CheckCircle2, CircleHelp, Plus, ShieldCheck, Trash2 } from "../ui/icons";
import { useState } from "react";
import { type ScopeRule, useApp } from "../state";
import { Badge, toast } from "../ui/bits";
import { RulesSection } from "../ui/Rules";
import { wwwCompanion } from "../ProjectWizard";
import { t, tn } from "../i18n";

type Decision = { decision: "allow" | "ask" | "deny"; reason?: string; code?: string; ruleId?: string; warnings?: string[] };

function ruleLabel(r: ScopeRule): string {
  return r.target.value ?? `${r.target.from} - ${r.target.to}`;
}

export function ScopePanel() {
  const { engagement, client } = useApp();
  const [target, setTarget] = useState("");
  const [risk, setRisk] = useState("active");
  const [verdict, setVerdict] = useState<Decision & { target: string }>();
  const [effect, setEffect] = useState<"include" | "exclude">("include");
  const [type, setType] = useState("domain");
  const [value, setValue] = useState("");
  const [reason, setReason] = useState("");
  const [subdomains, setSubdomains] = useState(true);

  if (!engagement) return null;
  const rules = engagement.scope;

  async function check() {
    if (!target.trim()) return;
    const d = await client.call<Decision>("scope.check", { target: target.trim(), risk }).catch((e: Error) => ({ decision: "deny" as const, reason: e.message }));
    setVerdict({ ...d, target: target.trim() });
  }

  async function add() {
    if (!value.trim()) return;
    try {
      const v = value.trim();
      await client.call("scope.add_rule", { rule: { effect, target: { type, value: v }, ...(reason ? { reason } : {}) } });
      // A bare domain rarely means "only the apex": add its subdomains too unless told otherwise,
      // and when not, at least its www name (the same site), as a rule of its own.
      if (type === "domain" && subdomains) {
        await client.call("scope.add_rule", { rule: { effect, target: { type: "wildcard", value: `*.${v}` }, ...(reason ? { reason } : {}) } });
      } else if (effect === "include") {
        const other = wwwCompanion({ type, value: v });
        if (other && !rules.some((r) => r.target.type === other.type && String(r.target.value ?? "").toLowerCase() === other.value.toLowerCase())) {
          await client.call("scope.add_rule", { rule: { effect, target: other, reason: t("start.wizard.wwwReason", { domain: v }) } });
        }
      }
      setValue("");
      setReason("");
      toast("ok", effect === "include" ? t("work.scope.added.include") : t("work.scope.added.exclude"), value);
    } catch (e) {
      toast("bad", t("work.scope.invalidRule"), (e as Error).message);
    }
  }

  async function remove(id: string) {
    await client.call("scope.remove_rule", { ruleId: id });
  }

  const ruleById = (id?: string) => rules.find((r) => r.id === id);

  return (
    <div className="panel">
      <div className="panel-toolbar">
        <ShieldCheck size={14} color="var(--ok)" />
        <h3>{t("work.scope.title")}</h3>
        <span className="count">{tn("work.scope.rules", rules.length)}</span>
      </div>
      <div className="panel-scroll">
        <div style={{ padding: 14, borderBottom: "1px solid var(--line)" }}>
          <div style={{ display: "flex", gap: 8 }}>
            <input className="input mono" style={{ flex: 1 }} placeholder={t("work.scope.check.placeholder")} value={target} onChange={(e) => setTarget(e.target.value)} onKeyDown={(e) => e.key === "Enter" && check()} />
            <select className="input" value={risk} onChange={(e) => setRisk(e.target.value)}>
              {["passive", "active", "intrusive", "exploitation"].map((r) => <option key={r} value={r}>{riskLabel(r)}</option>)}
            </select>
            <button className="btn" onClick={check}>{t("work.scope.check.button")}</button>
          </div>
          {verdict ? (
            <div className={`verdict ${verdict.decision}`}>
              {verdict.decision === "allow" ? <CheckCircle2 size={18} /> : verdict.decision === "ask" ? <CircleHelp size={18} /> : <Ban size={18} />}
              <div>
                <b className="mono">{verdict.target}</b>{" "}
                {verdict.decision === "allow" ? t("work.scope.verdict.allow") : verdict.decision === "ask" ? t("work.scope.verdict.ask") : t("work.scope.verdict.deny")}
                <div style={{ fontSize: 12, marginTop: 2 }}>
                  {verdict.decision === "allow" ? t("work.scope.verdict.rule", { rule: ruleLabel(ruleById(verdict.ruleId) ?? ({ target: {} } as ScopeRule)) }) : verdict.reason}
                </div>
              </div>
            </div>
          ) : null}
        </div>

        {(["include", "exclude"] as const).map((eff) => (
          <div key={eff}>
            <div className="rule-group">
              {eff === "include" ? <span className="dot open" /> : <span className="dot" style={{ background: "var(--bad)" }} />}
              {eff === "include" ? t("work.scope.group.include") : t("work.scope.group.exclude")}
            </div>
            {rules.filter((r) => r.effect === eff).length === 0 ? (
              <div style={{ padding: "4px 14px 10px", color: "var(--fg-3)" }}>{eff === "include" ? t("work.scope.empty.include") : t("work.scope.empty.exclude")}</div>
            ) : (
              rules
                .filter((r) => r.effect === eff)
                .map((r) => (
                  <div key={r.id} className="rule">
                    <Badge tone={eff === "include" ? "ok" : "bad"}>{r.target.type}</Badge>
                    <div style={{ minWidth: 0 }}>
                      <div className="v mono">
                        {ruleLabel(r)}
                        {r.ports ? <span style={{ color: "var(--fg-3)" }}> · {t("work.scope.ports", { ports: r.ports })}</span> : null}
                      </div>
                      {r.reason || r.maxRisk ? (
                        <div className="r">
                          {r.maxRisk ? t("work.scope.maxRisk", { risk: riskLabel(r.maxRisk) }) : ""}
                          {r.maxRisk && r.reason ? " · " : ""}
                          {r.reason}
                        </div>
                      ) : null}
                    </div>
                    <button className="btn ghost sm" title={t("work.scope.removeRule")} onClick={() => remove(r.id)}>
                      <Trash2 size={13} />
                    </button>
                  </div>
                ))
            )}
          </div>
        ))}

        <div className="form scope-form" style={{ borderTop: "1px solid var(--line)", marginTop: 8 }}>
          <div className="row">
            <div className="seg" style={{ flex: "0 0 auto" }}>
              <button className={effect === "include" ? "on" : ""} onClick={() => setEffect("include")}>{t("work.scope.include")}</button>
              <button className={effect === "exclude" ? "on" : ""} onClick={() => setEffect("exclude")}>{t("work.scope.exclude")}</button>
            </div>
            <select className="input" value={type} onChange={(e) => setType(e.target.value)}>
              <option value="domain">{t("work.scope.type.domain")}</option>
              <option value="wildcard">{t("work.scope.type.wildcard")}</option>
              <option value="ip">IP</option>
              <option value="cidr">CIDR</option>
              <option value="url">{t("work.scope.type.url")}</option>
            </select>
          </div>
          <input className="input mono" placeholder={type === "wildcard" ? t("work.scope.example.wildcard") : type === "cidr" ? "10.0.0.0/24" : type === "url" ? t("work.scope.example.url") : t("work.scope.example.domain")} value={value} onChange={(e) => setValue(e.target.value)} onKeyDown={(e) => e.key === "Enter" && add()} />
          {type === "domain" ? (
            <label className="check">
              <input type="checkbox" checked={subdomains} onChange={(e) => setSubdomains(e.target.checked)} />
              {t(effect === "include" ? "work.scope.subdomains.include" : "work.scope.subdomains.exclude", { domain: value.trim() || t("work.scope.type.domain") })}
            </label>
          ) : null}
          <input className="input" placeholder={t("work.scope.reason")} value={reason} onChange={(e) => setReason(e.target.value)} />
          <button className="btn primary" onClick={add}>
            <Plus size={14} /> {t("work.scope.addRule")}
          </button>
        </div>

        <RulesSection />
      </div>
    </div>
  );
}
