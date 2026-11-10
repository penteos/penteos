import { Eye, NotebookPen, Pencil, Plus } from "../ui/icons";
import { useEffect, useRef, useState } from "react";
import { type Entity, useApp, useOperation } from "../state";
import { ActorBadge, relTime, toast, useTick } from "../ui/bits";
import { Markdown } from "../ui/Markdown";
import { MentionPicker } from "../ui/MentionPicker";
import { t } from "../i18n";

/** Shared notes in markdown, with mentions that link to the graph. */
export function NotesPanel() {
  const { client } = useApp();
  const now = useTick();
  const notes = useOperation<Entity[]>("entity.query", { kind: "note", limit: 2000 }, { refreshOn: (e) => e.kind === "note" });
  const list = [...(notes.data ?? [])].sort((a, b) => b.updatedAt.localeCompare(a.updatedAt));
  const [sel, setSel] = useState<string>();
  const note = list.find((n) => n.id === sel) ?? list[0];
  const [title, setTitle] = useState("");
  const [body, setBody] = useState("");
  const [editing, setEditing] = useState(false);
  const area = useRef<HTMLTextAreaElement>(null);

  useEffect(() => {
    setTitle(String(note?.attributes.title ?? ""));
    setBody(String(note?.attributes.body ?? ""));
  }, [note?.id, note?.revision]);

  async function create() {
    const n = await client.call<Entity>("note.create", { title: t("work.notes.newTitle"), body: "" });
    setSel(n.id);
    setEditing(true);
  }
  async function save() {
    if (!note) return;
    await client.call("note.update", { id: note.id, title: title.trim() || t("work.notes.untitled"), body }).catch((e: Error) => toast("bad", t("common.notSaved"), e.message));
    setEditing(false);
  }
  function insert(md: string) {
    const el = area.current;
    if (!el) return setBody((b) => `${b}${md}`);
    const start = el.selectionStart;
    setBody((b) => `${b.slice(0, start)}${md}${b.slice(el.selectionEnd)}`);
  }

  return (
    <div className="panel">
      <div className="panel-toolbar">
        <NotebookPen size={14} />
        <h3>{t("work.notes.title")}</h3>
        <span className="count">{list.length}</span>
        <div className="grow" />
        <button className="btn sm" onClick={create}><Plus size={12} /> {t("work.notes.new")}</button>
      </div>
      <div className="web-split">
        <div className="web-tree">
          {list.map((n) => (
            <div key={n.id} className={`note-row ${note?.id === n.id ? "on" : ""}`} onClick={() => { setSel(n.id); setEditing(false); }}>
              <div className="t">{String(n.attributes.title)}</div>
              <div className="s"><ActorBadge actor={n.createdBy} /> {relTime(n.updatedAt, now)}</div>
            </div>
          ))}
          {list.length === 0 ? <div className="muted" style={{ padding: 12, fontSize: 12 }}>{t("work.notes.empty")}</div> : null}
        </div>
        <div className="web-detail">
          {note ? (
            <div className="op">
              <div className="ep-head">
                {editing ? <input className="input" style={{ flex: 1 }} value={title} onChange={(e) => setTitle(e.target.value)} /> : <span className="note-title">{String(note.attributes.title)}</span>}
                <div className="grow" />
                {editing ? (
                  <>
                    <MentionPicker onPick={insert} />
                    <button className="btn sm ghost" onClick={() => setEditing(false)}><Eye size={12} /> {t("work.notes.preview")}</button>
                    <button className="btn sm primary" onClick={save}>{t("common.save")}</button>
                  </>
                ) : (
                  <button className="btn sm" onClick={() => setEditing(true)}><Pencil size={12} /> {t("common.edit")}</button>
                )}
              </div>
              {editing ? (
                <textarea ref={area} className="input mono note-editor" value={body} onChange={(e) => setBody(e.target.value)} placeholder={t("work.notes.placeholder")} />
              ) : (
                <div className="note-body">{body.trim() ? <Markdown text={body} /> : <span className="muted">{t("work.notes.emptyBody")}</span>}</div>
              )}
            </div>
          ) : null}
        </div>
      </div>
    </div>
  );
}
