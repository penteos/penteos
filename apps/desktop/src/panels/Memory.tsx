import { Brain, Check, Lightbulb, ListChecks, Pencil, RotateCcw, ShieldAlert, XCircle } from "../ui/icons";
import { type ReactNode, useState } from "react";
import { type Entity, useApp, useOperation } from "../state";
import { ActorBadge, relTime, toast, useTick } from "../ui/bits";
import { t } from "../i18n";
import { HelpHint } from "../ui/HelpHint";

/** What the team remembers: attempts, decisions, hypotheses. Nothing hidden; everything editable. */

type Memory = Entity & { reverify: boolean };

const TYPES: Record<string, { icon: ReactNode }> = {
  attempt: { icon: <RotateCcw size={12} /> },
  decision: { icon: <Check size={12} /> },
  hypothesis: { icon: <Lightbulb size={12} /> },
  fact: { icon: <ListChecks size={12} /> },
  lesson: { icon: <Brain size={12} /> },
  preference: { icon: <Brain size={12} /> },
};
const typeLabel = (k: string) => (k in TYPES ? t(`work.memory.type.${k}`) : k);

const PLURAL = ["attempt", "decision", "hypothesis", "fact", "lesson"];

export function MemoryList(props: { entityId?: string; compact?: boolean }) {
  const { client } = useApp();
  const now = useTick();
  const [type, setType] = useState("");
  const [showInvalid, setShowInvalid] = useState(false);
  const mem = useOperation<Memory[]>(
    "memory.query",
    { ...(props.entityId ? { entityId: props.entityId } : {}), ...(type ? { memoryType: type } : {}), includeInvalidated: showInvalid, limit: 500 },
    { refreshOn: (e) => e.kind === "memory", deps: [type, showInvalid, props.entityId] },
  );
  const [editing, setEditing] = useState<string>();
  const [text, setText] = useState("");
  const [newType, setNewType] = useState("decision");
  const [draft, setDraft] = useState("");

  async function save(m: Memory) {
    await client.call("memory.update", { id: m.id, content: text }).catch((e: Error) => toast("bad", t("common.error"), e.message));
    setEditing(undefined);
  }
  async function invalidate(m: Memory) {
    const reason = window.prompt(t("work.memory.invalidate.prompt"), t("work.memory.invalidate.default"));
    if (!reason) return;
    await client.call("memory.update", { id: m.id, invalidate: reason }).catch((e: Error) => toast("bad", t("common.error"), e.message));
  }
  async function add() {
    await client.call("memory.write", { memoryType: newType, content: draft.trim(), entityIds: props.entityId ? [props.entityId] : [] }).catch((e: Error) => toast("bad", t("common.error"), e.message));
    setDraft("");
  }

  const list = mem.data ?? [];
  return (
    <div className="memory">
      {!props.compact ? (
        <div className="pane-head" style={{ padding: "0 0 8px", border: 0 }}>
          <div className="seg">
            <button className={type === "" ? "on" : ""} onClick={() => setType("")}>{t("work.memory.filter.all")}</button>
            {PLURAL.map((k) => <button key={k} className={type === k ? "on" : ""} onClick={() => setType(k)}>{t(`work.memory.filter.${k}`)}</button>)}
          </div>
          <label className="check" style={{ marginLeft: 8, fontSize: 12 }}><input type="checkbox" checked={showInvalid} onChange={(e) => setShowInvalid(e.target.checked)} /> {t("work.memory.showInvalidated")}</label>
        </div>
      ) : null}
      {list.map((m) => {
        const a = m.attributes as { memoryType: string; content: string; trusted: boolean; invalidated?: { reason: string } };
        return (
          <div key={m.id} className={`mem ${a.invalidated ? "invalid" : ""}`}>
            <span className={`mem-type ${a.memoryType}`}>{TYPES[a.memoryType]?.icon} {typeLabel(a.memoryType)}</span>
            <div className="mem-body">
              {editing === m.id ? (
                <div style={{ display: "flex", gap: 6 }}>
                  <textarea className="input" rows={2} style={{ flex: 1 }} value={text} onChange={(e) => setText(e.target.value)} />
                  <button className="btn sm primary" onClick={() => save(m)}>{t("common.save")}</button>
                </div>
              ) : (
                <div className="c">{a.content}</div>
              )}
              <div className="meta">
                <ActorBadge actor={m.createdBy} /> {relTime(m.createdAt, now)}
                {m.reverify ? <span className="tag warn" title={t("work.memory.reverify.hint")}>{t("work.memory.reverify")}</span> : null}
                {!a.trusted ? <span className="tag bad" title={t("work.memory.untrusted.hint")}><ShieldAlert size={10} /> {t("work.memory.untrusted")}</span> : null}
                {a.invalidated ? <span className="tag muted">{t("work.memory.invalidated", { reason: a.invalidated.reason })}</span> : null}
              </div>
            </div>
            {!a.invalidated ? (
              <div className="mem-actions">
                <button className="btn sm ghost" title={t("work.memory.correct")} onClick={() => { setEditing(m.id); setText(a.content); }}><Pencil size={12} /></button>
                <button className="btn sm ghost" title={t("work.memory.invalidate")} onClick={() => invalidate(m)}><XCircle size={12} /></button>
              </div>
            ) : null}
          </div>
        );
      })}
      {list.length === 0 ? <div className="muted" style={{ fontSize: 12, padding: "6px 0" }}>{t("work.memory.empty")}</div> : null}
      <div className="add-row" style={{ marginTop: 8 }}>
        <select className="input sm" value={newType} onChange={(e) => setNewType(e.target.value)}>
          {Object.keys(TYPES).slice(0, 5).map((k) => <option key={k} value={k}>{typeLabel(k)}</option>)}
        </select>
        <input className="input sm" style={{ flex: 1 }} placeholder={t("work.memory.placeholder")} value={draft} onChange={(e) => setDraft(e.target.value)} onKeyDown={(e) => e.key === "Enter" && draft.trim() && add()} />
        <button className="btn sm" disabled={!draft.trim()} onClick={add}>{t("common.add")}</button>
      </div>
    </div>
  );
}

export function MemoryPanel() {
  return (
    <div className="panel">
      <div className="panel-toolbar">
        <Brain size={14} />
        <h3>{t("work.memory.title")}</h3>
        <HelpHint id="memory" text={t("work.memory.hint")} />
      </div>
      <div className="panel-scroll">
        <div className="op"><MemoryList /></div>
      </div>
    </div>
  );
}
