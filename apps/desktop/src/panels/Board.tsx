import { Bot, Check, CheckCircle2, CircleHelp, KanbanSquare, Plus, User , Pencil, Trash2 } from "../ui/icons";
import { useState } from "react";
import { browseOf } from "../browse";
import { BrowseRequest } from "../ui/BrowseRequest";
import { type Entity, useApp, useOperation } from "../state";
import { Modal, toast } from "../ui/bits";
import { Markdown } from "../ui/Markdown";
import { asksOperator, questionOf } from "../tasks";
import { ClientQuestions } from "../ui/ClientQuestions";
import { t, tn } from "../i18n";
import { HelpHint } from "../ui/HelpHint";

/** The task board shared by humans and agents. Drag a card to another column to move it. */

const COLUMNS = ["todo", "in_progress", "blocked", "done"];
const PRIORITIES = ["urgent", "high", "normal", "low"];
const priorityLabel = (p: string) => t(`work.priority.${p}`);
const MAESTRO_ID = "01JA000000000000000000MSTR";

/** A question an agent left for the operator: answered right here, the agent hears it and goes on. */
function AnswerBox(props: { task: Entity }) {
  const { client } = useApp();
  const [text, setText] = useState("");
  const options = (props.task.attributes.options as string[] | undefined) ?? [];
  const send = (answer?: string) => {
    const a = (answer ?? text).trim();
    if (!a) return;
    void client.call("task.answer", { id: props.task.id, answer: a }).then(
      () => toast("ok", t("work.board.answer.sent"), t("work.board.answer.sentBody")),
      (e: Error) => toast("bad", t("work.board.answer.failed"), e.message),
    );
  };
  return (
    <div className="answer-box" onMouseDown={(e) => e.stopPropagation()} draggable={false} onDragStart={(e) => e.preventDefault()}>
      {props.task.attributes.question ? <div className="ab-q"><CircleHelp size={12} /> <span>{String(props.task.attributes.question)}</span></div> : null}
      {options.length ? <div className="ab-options">{options.map((o) => <button key={o} className="btn sm" onClick={() => send(o)}>{o}</button>)}</div> : null}
      <textarea className="input" rows={2} placeholder={options.length ? t("work.board.answer.orType") : t("work.board.answer.placeholder")} value={text} onChange={(e) => setText(e.target.value)} onKeyDown={(e) => e.key === "Enter" && !e.shiftKey && (e.preventDefault(), send())} />
      <button className="btn sm primary" disabled={!text.trim()} onClick={() => send()}>{t("common.reply")}</button>
    </div>
  );
}

const ASSIGNEE = ["keep", "me", "maestro", "nobody"];

/** Edit a card: title, detail, priority and who does it. */
function EditTask(props: { task: Entity; onClose: () => void }) {
  const { client } = useApp();
  const task = props.task;
  const [title, setTitle] = useState(String(task.attributes.title));
  const [description, setDescription] = useState(String(task.attributes.description ?? ""));
  const [priority, setPriority] = useState(String(task.attributes.priority ?? "normal"));
  const [assignee, setAssignee] = useState("keep");
  async function save() {
    try {
      await client.call("task.update", { id: task.id, title: title.trim(), description, priority, ...(assignee !== "keep" ? { assignee } : {}) });
      toast("ok", t("work.board.saved"));
      props.onClose();
    } catch (e) {
      toast("bad", t("common.notSaved"), (e as Error).message);
    }
  }
  return (
    <Modal
      title={t("work.board.edit.title")}
      icon={<Pencil size={16} />}
      onClose={props.onClose}
      footer={
        <>
          <button className="btn ghost" onClick={props.onClose}>{t("common.cancel")}</button>
          <button className="btn primary" disabled={!title.trim()} onClick={save}>{t("common.save")}</button>
        </>
      }
    >
      <label>{t("work.board.field.title")}<input className="input" autoFocus value={title} onChange={(e) => setTitle(e.target.value)} /></label>
      <label>{t("work.board.field.detail")}<textarea className="input" rows={5} value={description} onChange={(e) => setDescription(e.target.value)} /></label>
      <div className="row2">
        <label>{t("work.board.field.priority")}
          <select className="input" value={priority} onChange={(e) => setPriority(e.target.value)}>{PRIORITIES.map((k) => <option key={k} value={k}>{priorityLabel(k)}</option>)}</select>
        </label>
        <label>{t("work.board.field.assignee")}
          <select className="input" value={assignee} onChange={(e) => setAssignee(e.target.value)}>{ASSIGNEE.map((k) => <option key={k} value={k}>{t(`work.board.assignee.${k}`)}</option>)}</select>
        </label>
      </div>
    </Modal>
  );
}

export function BoardPanel() {
  const { client, me } = useApp();
  const tasks = useOperation<Entity[]>("entity.query", { kind: "task", limit: 2000 }, { refreshOn: (e) => e.kind === "task" });
  const [adding, setAdding] = useState(false);
  const [title, setTitle] = useState("");
  const [assignee, setAssignee] = useState("me");
  const [priority, setPriority] = useState("normal");
  const [drag, setDrag] = useState<string>();
  const list = (tasks.data ?? []).filter((task) => task.attributes.status !== "cancelled");
  // Assigned to a human: the operator (solo) or this operator (team).
  const mine = (task: Entity) => {
    const a = task.attributes.assignee as { type: string; id: string } | null | undefined;
    return a?.type === "human" && (a.id === me?.id || a.id === "01JA0000000000000000000HMN");
  };
  const waiting = list.filter((task) => mine(task) && task.attributes.status !== "done");

  const [editing, setEditing] = useState<Entity>();
  async function remove(task: Entity) {
    if (!window.confirm(t("work.board.delete.confirm", { title: String(task.attributes.title) }))) return;
    await client.call("task.delete", { id: task.id }).then(() => toast("ok", t("work.board.delete.done")), (e: Error) => toast("bad", t("work.board.delete.failed"), e.message));
  }
  const move = (id: string, status: string) => client.call("task.update", { id, status }).catch((e: Error) => toast("bad", t("work.board.moveFailed"), e.message));
  async function add() {
    await client.call("task.create", { title: title.trim(), priority, assignee }).catch((e: Error) => toast("bad", t("common.error"), e.message));
    setTitle("");
    setAdding(false);
  }
  const who = (task: Entity) => {
    const a = task.attributes.assignee as { type: string; id: string } | null | undefined;
    if (!a) return null;
    if (a.type === "agent") return <span className="who agent"><Bot size={11} /> {a.id === MAESTRO_ID ? t("common.maestro") : t("common.agent")}</span>;
    return <span className="who"><User size={11} /> {a.id === me?.id ? t("common.you") : t("common.operator")}</span>;
  };

  return (
    <div className="panel">
      <div className="panel-toolbar">
        <KanbanSquare size={14} />
        <h3>{t("work.board.title")}</h3>
        <span className="count">{list.length}</span>
        {waiting.length ? (
          <span className="hint waiting-hint">{tn("work.board.waiting", waiting.length)}</span>
        ) : (
          <HelpHint id="board" text={t("work.board.hint")} />
        )}
        <div className="grow" />
        <button className="btn sm" onClick={() => setAdding(true)}><Plus size={12} /> {t("work.board.new")}</button>
      </div>
      {adding ? (
        <div className="add-row" style={{ padding: "8px 12px", borderBottom: "1px solid var(--line)" }}>
          <input className="input" autoFocus style={{ flex: 1 }} placeholder={t("work.board.new.placeholder")} value={title} onChange={(e) => setTitle(e.target.value)} onKeyDown={(e) => e.key === "Enter" && title.trim() && add()} />
          <select className="input" value={assignee} onChange={(e) => setAssignee(e.target.value)}>
            <option value="me">{t("work.board.assignee.me")}</option>
            <option value="maestro">{t("work.board.assignee.maestro")}</option>
            <option value="nobody">{t("work.board.assignee.nobody")}</option>
          </select>
          <select className="input" value={priority} onChange={(e) => setPriority(e.target.value)}>
            {PRIORITIES.map((k) => <option key={k} value={k}>{priorityLabel(k)}</option>)}
          </select>
          <button className="btn primary" disabled={!title.trim()} onClick={add}>{t("common.create")}</button>
          <button className="btn ghost" onClick={() => setAdding(false)}>{t("common.cancel")}</button>
        </div>
      ) : null}
      <ClientQuestions />
      <div className="board">
        {COLUMNS.map((status) => {
          const cards = list.filter((task) => task.attributes.status === status || (status === "blocked" && task.attributes.status === "awaiting_approval"));
          return (
            <div
              key={status}
              className={`column ${drag ? "droppable" : ""}`}
              onDragOver={(e) => e.preventDefault()}
              onDrop={() => {
                if (drag) void move(drag, status);
                setDrag(undefined);
              }}
            >
              <div className="col-head">{t(`work.board.column.${status}`)} <span className="muted">{cards.length}</span></div>
              {cards.map((task) => (
                <div key={task.id} className={`card prio-${String(task.attributes.priority)} ${mine(task) && task.attributes.status !== "done" ? "mine" : ""} ${asksOperator(task) ? "asks" : ""}`} draggable onDragStart={() => setDrag(task.id)} onDragEnd={() => setDrag(undefined)}>
                  <div className="card-head">
                    <div className="t">{String(task.attributes.title)}</div>
                    <div className="card-actions" onMouseDown={(e) => e.stopPropagation()}>
                      <button className="icon-btn" aria-label={t("work.board.edit.aria")} title={t("common.edit")} onClick={() => setEditing(task)}><Pencil size={13} /></button>
                      <button className="icon-btn" aria-label={t("work.board.delete.aria")} title={t("common.delete")} onClick={() => void remove(task)}><Trash2 size={13} /></button>
                    </div>
                  </div>
                  {task.attributes.description ? <div className="d"><Markdown text={String(task.attributes.description)} /></div> : null}
                  {asksOperator(task) ? (browseOf(task) ? <BrowseRequest task={task} /> : <AnswerBox task={task} />) : null}
                  {task.attributes.answer ? (
                    <div className="task-answer">
                      <div className="ta-q"><CircleHelp size={11} /> <span>{questionOf(task).question}</span></div>
                      <div className="ta-a"><CheckCircle2 size={11} /> <span>{String((task.attributes.answer as { text: string }).text)}</span></div>
                    </div>
                  ) : null}
                  {mine(task) && !asksOperator(task) && task.attributes.status !== "done" ? (
                    <button className="btn sm ghost card-done" onClick={() => move(task.id, "done")}><Check size={11} /> {t("work.board.markDone")}</button>
                  ) : null}
                  <div className="meta">
                    {who(task)}
                    {task.attributes.priority !== "normal" ? <span className={`tag ${task.attributes.priority === "urgent" || task.attributes.priority === "high" ? "warn" : "muted"}`}>{priorityLabel(String(task.attributes.priority))}</span> : null}
                  </div>
                </div>
              ))}
            </div>
          );
        })}
      </div>
      {editing ? <EditTask task={editing} onClose={() => setEditing(undefined)} /> : null}
    </div>
  );
}
