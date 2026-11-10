import { ArrowLeft, ArrowRight, Bot, Check, Crown, Plus, Crosshair, FlaskConical, GitCompareArrows, Globe, LayoutGrid, Network, RotateCcw, Shield, User, Users, X, Mark, Puzzle } from "./ui/icons";
import { ptext, usePluginCatalog } from "./ui/plugins";
import { type ReactNode, useEffect, useState } from "react";
import { MODE_ORDER, MODES, type ModeId } from "./modes";
import type { Provider } from "./panels/AgentSidebar";
import { ChatGptConnect } from "./ui/Providers";
import { useApp } from "./state";
import { toast } from "./ui/bits";
import { type AccountDraft, AccountRows, saveRules } from "./ui/Rules";
import { lang, LANGS, t, tn, type Lang } from "./i18n";
import { risk as riskLabel } from "./labels";

/**
 * The first-run assistant and the "new project" flow: how you work (asked once), what kind of
 * engagement this is (each mode explained), and the essentials to start.
 */

const MODE_ICON: Record<ModeId, ReactNode> = {
  web: <Globe size={18} />,
  infra: <Network size={18} />,
  custom: <LayoutGrid size={18} />,
};

const cap = (s: string) => s.charAt(0).toUpperCase() + s.slice(1);
const RISK_IDS = ["passive", "active", "intrusive", "exploitation"] as const;
/** [id, label, help], read from the catalogs when used. */
const risks = (): Array<[string, string, string]> => RISK_IDS.map((id) => [id, cap(riskLabel(id)), t(`start.risk.${id}.help`)]);

/** A line of the scope box as a rule: "10.0.0.5:8080" becomes the IP restricted to that port. */
export function scopeRuleFor(value: string): { target: { type: string; value: string }; ports?: string } {
  const m = /^(\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5})$/.exec(value.trim());
  return m ? { target: { type: "ip", value: m[1]! }, ports: m[2]! } : { target: scopeTargetFor(value) };
}

/**
 * The other name of the same site: example.com ↔ www.example.com (also for URLs). A bare domain
 * almost always redirects to its www or the other way round; leaving one out blocks the work, and
 * the only alternative the agents would see is a whole wildcard.
 */
export function wwwCompanion(target: { type: string; value: string }): { type: string; value: string } | undefined {
  const flip = (host: string) => (host.toLowerCase().startsWith("www.") ? host.slice(4) : host.split(".").length >= 2 ? `www.${host}` : undefined);
  if (target.type === "domain") {
    const other = flip(target.value.trim());
    return other ? { type: "domain", value: other } : undefined;
  }
  if (target.type === "url") {
    try {
      const u = new URL(target.value);
      if (/^[\d.]+$/.test(u.hostname) || u.hostname.includes(":")) return undefined;
      const other = flip(u.hostname);
      if (!other) return undefined;
      u.hostname = other;
      return { type: "url", value: target.value.endsWith("/") || u.pathname !== "/" ? u.href : u.href.replace(/\/$/, "") };
    } catch {
      return undefined;
    }
  }
  return undefined;
}

export function scopeTargetFor(value: string): { type: string; value: string } {
  const v = value.trim();
  if (v.startsWith("*.")) return { type: "wildcard", value: v };
  if (/^https?:\/\//i.test(v)) return { type: "url", value: v };
  if (v.includes("/")) return { type: "cidr", value: v };
  if (/^[\d.]+$/.test(v) || v.includes(":")) return { type: "ip", value: v };
  return { type: "domain", value: v };
}

type Step = "mode" | "details" | "ai";

export type AutonomyId = "copilot" | "maestro" | "maestro_auto";

/** How autonomous the AI is: one control, copilot → maestro → maestro auto. */
type Level = { id: AutonomyId; title: string; tagline: string; explain: string[]; icon: ReactNode };
/** The texts are getters so they are read in the operator's language when shown. */
const makeLevel = (id: AutonomyId, explained: number, icon: ReactNode): Level => ({
  id,
  icon,
  get title() {
    return t(`start.level.${id}.title`);
  },
  get tagline() {
    return t(`start.level.${id}.tagline`);
  },
  get explain() {
    return Array.from({ length: explained }, (_, i) => t(`start.level.${id}.explain${i + 1}`));
  },
});
export const LEVELS: Level[] = [
  makeLevel("copilot", 2, <Bot size={18} />),
  makeLevel("maestro", 2, <Crown size={18} />),
  makeLevel("maestro_auto", 2, <Shield size={18} />),
];

/** A wide scope (whole networks, wildcards, many targets) is where autopilot pays off. */
export function suggestLevel(scopeLines: string[]): AutonomyId {
  const wide = scopeLines.some((l) => /\/\d{1,2}$/.test(l.trim()) || l.trim().startsWith("*."));
  return wide || scopeLines.length >= 6 ? "maestro_auto" : "maestro";
}

/** What the Maestro is asked to do first, by project type. */
const firstAskFor = (m: ModeId): string => t(`start.firstAsk.${m}`);

/** The folder name the core will use for "<Client - Project>" - mirrors Workspace.freeFolder's sanitising. */
function folderPreview(clientName: string, name: string): string {
  return `${clientName.trim()} - ${name.trim()}`.replace(/[^\p{L}\p{N} ._-]+/gu, "-").replace(/\s+/g, " ").trim() || "Proyecto";
}

export function ProjectWizard(props: { firstRun: boolean; onClose: () => void }) {
  const { client, workbench, teamMode } = useApp();
  const [step, setStep] = useState<Step>("mode");
  const [mode, setMode] = useState<ModeId>("web");
  const [clientName, setClientName] = useState("");
  const [name, setName] = useState("");
  const [scope, setScope] = useState("");
  const [subdomains, setSubdomains] = useState(true);
  const [risk, setRisk] = useState(MODES.web.risk);
  const [busy, setBusy] = useState(false);
  const [providers, setProviders] = useState<Provider[]>([]);
  const [provider, setProvider] = useState<string>();
  const [startAgent, setStartAgent] = useState(true);
  const [autonomy, setAutonomy] = useState<AutonomyId>("maestro");
  const [language, setLanguage] = useState<Lang>(lang());
  const [accounts, setAccounts] = useState<AccountDraft[]>([]);
  const [allowed, setAllowed] = useState("");
  const [avoid, setAvoid] = useState("");
  const [showRules, setShowRules] = useState(false);
  const [autonomyTouched, setAutonomyTouched] = useState(false);
  const [firstAsk, setFirstAsk] = useState(() => firstAskFor("web"));
  const [cfgKey, setCfgKey] = useState("");
  const [cfgModel, setCfgModel] = useState("");
  const [cfgUrl, setCfgUrl] = useState("");
  const [configuring, setConfiguring] = useState(false);
  const [root, setRoot] = useState<string>();
  const [saveDir, setSaveDir] = useState<string>();
  // Installed plugins, offered for this project; none is on unless the operator ticks it.
  const offers = usePluginCatalog().plugins;
  const [chosenPlugins, setChosenPlugins] = useState<string[]>([]);

  // Where this project will be created, shown in the details step (solo mode, desktop only).
  useEffect(() => {
    if (teamMode || !window.penteosDesktop?.projectDir) return;
    void (async () => {
      const prefs = await client.call<{ projectsRoot?: string }>("workspace.prefs", {}).catch(() => null);
      const info = await window.penteosDesktop?.projectDir?.().catch(() => undefined);
      setRoot(prefs?.projectsRoot ?? (info?.home ? `${info.home}/Penteos` : undefined));
    })();
  }, [client, teamMode]);
  const loadProviders = (refresh = false) =>
    client
      .request<{ selected?: string; providers: Provider[] }>("agent.providers", { refresh })
      .then((r) => {
        setProviders(r.providers);
        setProvider((cur) => cur ?? (r.providers.find((p) => p.id === r.selected && p.available) ?? r.providers.find((p) => p.available) ?? r.providers[0])?.id);
        return r.providers;
      })
      .catch(() => [] as Provider[]);
  useEffect(() => {
    void loadProviders(true);
  }, [client]);
  const chosen = providers.find((p) => p.id === provider);
  useEffect(() => {
    setCfgModel(chosen?.settings.model ?? "");
    setCfgUrl(chosen?.settings.baseUrl ?? "");
    setCfgKey("");
  }, [chosen?.id]);
  useEffect(() => {
    setStartAgent(Boolean(chosen?.available));
  }, [chosen?.available]);

  async function configure() {
    if (!chosen) return;
    setConfiguring(true);
    try {
      const settings: Record<string, string> = {};
      if (chosen.fields.includes("apiKey") && cfgKey) settings.apiKey = cfgKey;
      if (chosen.fields.includes("model")) settings.model = cfgModel;
      if (chosen.fields.includes("baseUrl")) settings.baseUrl = cfgUrl;
      const r = await client.request<{ providers: Provider[] }>("agent.configure", { provider: chosen.id, settings });
      setProviders(r.providers);
      const now = r.providers.find((p) => p.id === chosen.id);
      toast(now?.available ? "ok" : "info", now?.available ? t("start.provider.ready", { name: chosen.label }) : t("start.provider.saved", { name: chosen.label }), now?.available ? undefined : now?.reason);
    } catch (e) {
      toast("bad", t("common.notSaved"), (e as Error).message);
    } finally {
      setConfiguring(false);
    }
  }

  useEffect(() => {
    if (props.firstRun) return;
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && props.onClose();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [props]);

  const pick = (m: ModeId) => {
    setMode(m);
    setRisk(MODES[m].risk);
    setFirstAsk(firstAskFor(m));
    setStep("details");
  };

  async function finish(open?: () => void) {
    await client.call("workspace.set_prefs", { onboarded: true, workStyle: "solo", autonomy }).catch(() => undefined);
    props.onClose();
    open?.();
  }

  async function create() {
    setBusy(true);
    try {
      const plugins = chosenPlugins.filter((id) => offers.some((p) => p.id === id));
      await client.call("engagement.create", { clientName: clientName.trim(), name: name.trim(), mode, maxRisk: risk, autonomy, language, ...(saveDir ? { dir: saveDir } : {}), ...(plugins.length ? { plugins } : {}) });
      const lines = scope.split(/[\n,]+/).map((s) => s.trim()).filter(Boolean);
      const added = new Set<string>();
      let domains = 0;
      for (const line of lines) {
        const { target, ports } = scopeRuleFor(line);
        if (added.has(`${target.type}|${target.value.toLowerCase()}`)) continue;
        added.add(`${target.type}|${target.value.toLowerCase()}`);
        await client.call("scope.add_rule", { rule: { effect: "include", target, ...(ports ? { ports } : {}) } });
        if (target.type === "domain" || target.type === "url") domains++;
        if (target.type === "domain" && subdomains) {
          await client.call("scope.add_rule", { rule: { effect: "include", target: { type: "wildcard", value: `*.${target.value}` } } });
          continue;
        }
        // The www name of the same site goes with it, as its own visible rule.
        const other = wwwCompanion(target);
        if (other && !added.has(`${other.type}|${other.value.toLowerCase()}`) && !lines.some((l) => scopeRuleFor(l).target.value.toLowerCase() === other.value.toLowerCase())) {
          added.add(`${other.type}|${other.value.toLowerCase()}`);
          await client.call("scope.add_rule", { rule: { effect: "include", target: other, ...(ports ? { ports } : {}), reason: t("start.wizard.wwwReason", { domain: target.value }) } });
        }
      }
      // Subdomains unchecked is an answer: the agents must not propose them later.
      const noSubdomains = domains > 0 && !subdomains;
      if (accounts.some((a) => a.username.trim()) || allowed.trim() || avoid.trim() || noSubdomains) {
        await saveRules(client, accounts, allowed, avoid, noSubdomains).catch((e: Error) => toast("bad", t("start.wizard.rulesNotSaved"), t("start.wizard.rulesNotSaved.body", { error: e.message })));
      }
      toast("ok", t("start.wizard.projectCreated"), `${clientName.trim()} / ${name.trim()} · ${MODES[mode].title}`);
      if (chosen?.available) {
        // The default provider for the next conversations, also in the chat panel.
        client.notify("agent.select", { provider: chosen.id });
        window.dispatchEvent(new CustomEvent("penteos:provider-selected", { detail: chosen.id }));
        if (startAgent && firstAsk.trim()) {
          client.notify("agent.send", { provider: chosen.id, text: firstAsk.trim() });
          window.dispatchEvent(new Event("penteos:open-agent"));
        }
      }
      await finish();
    } catch (e) {
      toast("bad", t("start.wizard.createFailed"), (e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  const steps: Step[] = ["mode", "details", "ai"];
  const scopeLines = scope.split(/[\n,]+/).map((s) => s.trim()).filter(Boolean);
  const suggested = suggestLevel(scopeLines);
  const goAi = () => {
    if (!autonomyTouched) setAutonomy(suggested);
    setStep("ai");
  };
  /**
   * A URL typed as the client or the project name ("https://app.acme.com/login") becomes the site's
   * name (app.acme.com), and when the scope is still empty it is what the person meant to test.
   */
  const fromUrl = (value: string): string => {
    const v = value.trim();
    if (!/^[a-z][a-z0-9+.-]*:\/\/\S+$/i.test(v)) return value;
    try {
      const u = new URL(v);
      if (!scope.trim() && /^https?:$/.test(u.protocol)) setScope(u.origin);
      return u.hostname.replace(/^www\./, "");
    } catch {
      return value;
    }
  };
  const valid = Boolean(clientName.trim() && name.trim());
  const info = MODES[mode];

  return (
    <div className="wizard">
      <div className="wizard-card">
        <div className="wizard-head">
          <div className="brand-mark"><Mark size={22} /></div>
          <div className="wtitle">{props.firstRun ? t("start.wizard.welcome") : t("start.wizard.newProject")}</div>
          <div className="wsteps">
            {steps.map((s, i) => (
              <span key={s} className={`wstep ${s === step ? "on" : steps.indexOf(step) > i ? "done" : ""}`}>
                {steps.indexOf(step) > i ? <Check size={10} /> : i + 1} {t(`start.wizard.step.${s}`)}
              </span>
            ))}
          </div>
          <div className="grow" />
          {!props.firstRun ? <button className="icon-btn" onClick={props.onClose} title={t("start.wizard.closeEsc")}><X size={15} /></button> : null}
        </div>

        {step === "mode" ? (
          <div className="wizard-body">
            <h2>{t("start.wizard.mode.title")}</h2>
            <p className="lead">{t("start.wizard.mode.lead")}</p>
            <div className="choice-grid">
              {MODE_ORDER.map((m) => {
                const mi = MODES[m];
                return (
                  <button key={m} className={`choice ${mode === m ? "on" : ""}`} onClick={() => pick(m)}>
                    <div className="ch-icon">{MODE_ICON[m]}</div>
                    <div className="ch-title">{mi.title}</div>
                    <div className="ch-tag">{mi.tagline}</div>
                    <ul className="ch-list">{mi.explain.map((x) => <li key={x}>{x}</li>)}</ul>
                  </button>
                );
              })}
            </div>
            <div className="wizard-foot">
              <button className="btn ghost" onClick={() => finish(() => workbench.openPanel("home"))}>
                <FlaskConical size={13} /> {t("start.wizard.style.lab")}
              </button>
            </div>
          </div>
        ) : null}

        {step === "details" ? (
          <div className="wizard-body narrow">
            <div className="mode-pill">{MODE_ICON[mode]} {info.title}<span className="muted"> · {info.tagline}</span></div>
              <>
                <h2>{t("start.wizard.details.title")}</h2>
                <div className="row2">
                  <label>{t("start.wizard.details.client")}<input className="input" autoFocus value={clientName} onChange={(e) => setClientName(e.target.value)} onBlur={() => setClientName(fromUrl(clientName))} placeholder={t("start.wizard.details.clientPlaceholder")} /></label>
                  <label>{t("start.wizard.details.name")}<input className="input" value={name} onChange={(e) => setName(e.target.value)} onBlur={() => setName(fromUrl(name))} placeholder={t("start.wizard.details.namePlaceholder.default")} /></label>
                </div>
                {!teamMode && window.penteosDesktop?.projectDir && (saveDir ?? root) ? (
                  <div className="save-location">
                    <span className="muted">{t("start.wizard.details.saveIn")}</span>
                    <span className="mono path" title={`${saveDir ?? root}/${folderPreview(clientName, name)}`}>{saveDir ?? root}/{folderPreview(clientName, name)}</span>
                    <button className="btn ghost sm" onClick={async () => { const d = await window.penteosDesktop?.chooseProjectsRoot?.(); if (d) setSaveDir(d); }}>{t("start.wizard.details.changeLocation")}</button>
                  </div>
                ) : null}
                <label><span>{t("start.wizard.details.language")} <span className="muted">{t("start.wizard.details.languageHint")}</span></span>
                  <select className="input" value={language} onChange={(e) => setLanguage(e.target.value as Lang)}>
                    {LANGS.map((l) => <option key={l.id} value={l.id}>{t(`labels.lang.${l.id}`)}</option>)}
                  </select>
                </label>
                <label><span>{t("start.wizard.details.scope")} <span className="muted">{t("start.wizard.details.scopeHint")}</span></span>
                  <textarea className="input mono" rows={4} value={scope} onChange={(e) => setScope(e.target.value)} placeholder={mode === "infra" ? "10.10.0.0/16\ncorp.local" : t("start.wizard.details.scopePlaceholder")} />
                </label>
                <label className="check" style={{ flexDirection: "row" }}>
                  <input type="checkbox" checked={subdomains} onChange={(e) => setSubdomains(e.target.checked)} />
                  {t("start.wizard.details.subdomains")}
                </label>
                <div className="rules-pick">
                  <button className="btn ghost sm" style={{ paddingLeft: 0 }} onClick={() => setShowRules((v) => !v)}>
                    {showRules ? "▾" : "▸"} {t("start.wizard.details.rules")} <span className="muted">{t("start.wizard.details.rulesHint")}</span>
                  </button>
                  {showRules ? (
                    <>
                      <AccountRows accounts={accounts} onChange={setAccounts} />
                      <div className="rules-texts">
                        <label>{t("start.rules.allowed")}<textarea className="input" rows={2} placeholder={t("start.wizard.details.allowedPlaceholder")} value={allowed} onChange={(e) => setAllowed(e.target.value)} /></label>
                        <label>{t("start.rules.avoid")}<textarea className="input" rows={2} placeholder={t("start.wizard.details.avoidPlaceholder")} value={avoid} onChange={(e) => setAvoid(e.target.value)} /></label>
                      </div>
                    </>
                  ) : null}
                </div>
                <div className="risk-pick">
                  <div className="lbl">{t("start.wizard.details.maxRisk")} <span className="muted">{t("start.wizard.details.maxRiskHint", { mode: info.title.toLowerCase(), risk: riskLabel(info.risk) })}</span></div>
                  <div className="seg">
                    {risks().map(([id, label, help]) => <button key={id} className={risk === id ? "on" : ""} title={help} onClick={() => setRisk(id as typeof risk)}>{label}</button>)}
                  </div>
                  <div className="muted help">{t(`start.risk.${risk}.help`)}</div>
                </div>
              </>
            <div className="wizard-foot">
              <button className="btn ghost" onClick={() => setStep("mode")}><ArrowLeft size={13} /> {t("start.wizard.details.changeType")}</button>
              <div className="grow" />
              <button className="btn primary" disabled={!valid} onClick={goAi}>{t("common.next")} <ArrowRight size={13} /></button>
            </div>
          </div>
        ) : null}

        {step === "ai" ? (
          <div className="wizard-body narrow">
            <h2>{t("start.wizard.ai.title")}</h2>
            <p className="lead">{t("start.wizard.ai.lead")}</p>
            <div className="choice-grid">
              {LEVELS.map((l) => (
                <button key={l.id} className={`choice ${autonomy === l.id ? "on" : ""}`} onClick={() => { setAutonomy(l.id); setAutonomyTouched(true); }}>
                  <div className="ch-icon">{l.icon}</div>
                  <div className="ch-title">{l.title}{l.id === suggested ? <span className="muted" style={{ fontWeight: 400 }}>{t("start.wizard.ai.suggested")}</span> : null}</div>
                  <div className="ch-tag">{l.tagline}</div>
                  <ul className="ch-list">{l.explain.map((x) => <li key={x}>{x}</li>)}</ul>
                </button>
              ))}
            </div>
            <h2 style={{ marginTop: 14 }}>{t("start.wizard.agent.title")}</h2>
            <div className="prov-list">
              {(["plan", "api", "local", "cli"] as const).map((kind) => (
                <div key={kind}>
                  <div className="pp-group">{t(`start.wizard.agent.group.${kind}`)}</div>
                  {providers.filter((p) => p.kind === kind).map((p) => (
                    <button key={p.id} className={`prov ${provider === p.id ? "on" : ""}`} onClick={() => setProvider(p.id)}>
                      <span className={`led ${p.available ? "ok" : ""}`} />
                      <span className="n">{p.label}</span>
                      <span className="d">{p.available ? p.description : p.reason}</span>
                    </button>
                  ))}
                </div>
              ))}
              {providers.length === 0 ? <span className="muted">{t("start.wizard.agent.detecting")}</span> : null}
            </div>
            {chosen && (!chosen.available || chosen.fields.length) ? (
              <div className="prov-config">
                <div className="lbl">{chosen.available ? t("start.wizard.agent.settingsOf", { name: chosen.label }) : t("start.wizard.agent.configure", { name: chosen.label })}</div>
                {chosen.kind === "plan" ? <ChatGptConnect onChanged={() => void loadProviders(true)} /> : null}
                {chosen.kind === "cli" && !chosen.available ? (
                  <span className="muted">{t("start.wizard.agent.cliMissing", { reason: chosen.reason })}</span>
                ) : null}
                {chosen.fields.includes("baseUrl") ? (
                  <input className="input mono" placeholder={t("start.wizard.agent.baseUrl")} value={cfgUrl} onChange={(e) => setCfgUrl(e.target.value)} />
                ) : null}
                {chosen.fields.includes("apiKey") ? (
                  <input className="input mono" type="password" placeholder={chosen.settings.hasApiKey ? t("start.wizard.agent.apiKeyKept") : t("start.wizard.agent.apiKey")} value={cfgKey} onChange={(e) => setCfgKey(e.target.value)} />
                ) : null}
                {chosen.fields.includes("model") && (chosen.kind !== "plan" || chosen.available) ? (
                  chosen.models?.length ? (
                    <select className="input" value={cfgModel} onChange={(e) => setCfgModel(e.target.value)}>
                      {chosen.models.map((m) => <option key={m} value={m}>{m}</option>)}
                    </select>
                  ) : (
                    <input className="input mono" placeholder={chosen.kind === "cli" ? t("start.wizard.agent.modelCli") : t("start.wizard.agent.model")} value={cfgModel} onChange={(e) => setCfgModel(e.target.value)} />
                  )
                ) : null}
                <div style={{ display: "flex", gap: 8 }}>
                  {chosen.fields.length ? <button className="btn sm" disabled={configuring} onClick={configure}>{configuring ? t("start.wizard.agent.saving") : t("common.save")}</button> : null}
                  <button className="btn sm ghost" onClick={() => void loadProviders(true)}>{t("start.wizard.agent.redetect")}</button>
                </div>
              </div>
            ) : null}
            <label className="check" style={{ flexDirection: "row", marginTop: 4 }}>
              <input type="checkbox" checked={startAgent && Boolean(chosen?.available)} disabled={!chosen?.available} onChange={(e) => setStartAgent(e.target.checked)} />
              {t("start.wizard.agent.startNow")}
            </label>
            {startAgent && chosen?.available ? (
              <textarea className="input" rows={3} value={firstAsk} onChange={(e) => setFirstAsk(e.target.value)} />
            ) : !chosen?.available ? (
              <span className="muted" style={{ fontSize: 12 }}>{t("start.wizard.agent.later")}</span>
            ) : null}
            {offers.length ? (
              <div className="wizard-plugins">
                <h2 style={{ marginTop: 14 }}><Puzzle size={15} /> {t("plugins.wizard.title")}</h2>
                <p className="lead">{t("plugins.wizard.hint")}</p>
                {offers.map((p) => (
                  <label key={p.id} className="check wizard-plugin" style={{ flexDirection: "row" }}>
                    <input type="checkbox" checked={chosenPlugins.includes(p.id)} onChange={(e) => setChosenPlugins((cur) => (e.target.checked ? [...cur, p.id] : cur.filter((x) => x !== p.id)))} />
                    <span>
                      <b>{p.name}</b>
                      {p.description ? <span className="muted"> · {ptext(p.description)}</span> : null}
                      {p.sendsTo.length ? <span className="wizard-plugin-warn">{t("plugins.sendsTo", { hosts: p.sendsTo.join(", ") })}</span> : null}
                    </span>
                  </label>
                ))}
              </div>
            ) : null}
            <div className="wizard-foot">
              <button className="btn ghost" onClick={() => setStep("details")}><ArrowLeft size={13} /> {t("common.back")}</button>
              <div className="grow" />
              <button className="btn primary" disabled={!valid || busy} onClick={create}>
                <Plus size={13} /> {t("start.wizard.createProject")}
                {startAgent && chosen?.available ? t("start.wizard.andStart") : ""}
              </button>
            </div>
          </div>
        ) : null}
      </div>
    </div>
  );
}

/** Changing the mode of the current project, from Proyecto → Cambiar tipo. */
export function ModePicker(props: { onClose: () => void }) {
  const { client, engagement } = useApp();
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && props.onClose();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [props]);
  async function choose(m: ModeId) {
    try {
      await client.call("engagement.update", { mode: m });
      toast("ok", t("start.modePicker.changed"), t("start.modePicker.changed.body", { mode: MODES[m].title }));
      props.onClose();
    } catch (e) {
      toast("bad", t("start.picker.changeFailed"), (e as Error).message);
    }
  }
  return (
    <div className="wizard" onMouseDown={(e) => e.target === e.currentTarget && props.onClose()}>
      <div className="wizard-card">
        <div className="wizard-head">
          <div className="wtitle">{t("start.wizard.step.mode")}</div>
          <div className="grow" />
          <button className="icon-btn" onClick={props.onClose}><X size={15} /></button>
        </div>
        <div className="wizard-body">
          <p className="lead">{t("start.modePicker.lead")}</p>
          <div className="choice-grid">
            {MODE_ORDER.map((m) => (
              <button key={m} className={`choice ${engagement?.mode === m ? "on" : ""}`} onClick={() => choose(m)}>
                <div className="ch-icon">{MODE_ICON[m]}</div>
                <div className="ch-title">{MODES[m].title}</div>
                <div className="ch-tag">{MODES[m].tagline}</div>
                <ul className="ch-list">{MODES[m].explain.map((x) => <li key={x}>{x}</li>)}</ul>
              </button>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

/** Changing how autonomous the AI is in the current project, from Proyecto → Autonomía. */
export function AiLevelPicker(props: { onClose: () => void }) {
  const { client, engagement } = useApp();
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && props.onClose();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [props]);
  async function choose(l: AutonomyId) {
    try {
      await client.call("engagement.update", { autonomy: l });
      const lv = LEVELS.find((x) => x.id === l)!;
      toast("ok", t("start.levelPicker.changed"), t("start.levelPicker.plain", { level: lv.title }));
      props.onClose();
    } catch (e) {
      toast("bad", t("start.picker.changeFailed"), (e as Error).message);
    }
  }
  return (
    <div className="wizard" onMouseDown={(e) => e.target === e.currentTarget && props.onClose()}>
      <div className="wizard-card">
        <div className="wizard-head">
          <div className="wtitle">{t("start.wizard.step.ai")}</div>
          <div className="grow" />
          <button className="icon-btn" onClick={props.onClose}><X size={15} /></button>
        </div>
        <div className="wizard-body">
          <p className="lead">{t("start.levelPicker.lead")}</p>
          <div className="choice-grid">
            {LEVELS.map((l) => (
              <button key={l.id} className={`choice ${engagement?.autonomy === l.id ? "on" : ""}`} onClick={() => choose(l.id)}>
                <div className="ch-icon">{l.icon}</div>
                <div className="ch-title">{l.title}</div>
                <div className="ch-tag">{l.tagline}</div>
                <ul className="ch-list">{l.explain.map((x) => <li key={x}>{x}</li>)}</ul>
              </button>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
