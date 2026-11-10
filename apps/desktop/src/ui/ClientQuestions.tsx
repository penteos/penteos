import { Check, ChevronDown, Copy, MessageSquareQuote, Plus, X } from "./icons";
import { useState } from "react";
import { useApp, useOperation } from "../state";
import { toast } from "./bits";
import { t, tn } from "../i18n";

/**
 * What the team needs from the client (accounts, a window, what a service protects), gathered in
 * one list the operator copies into an email. The client's answer is recorded here and the Maestro
 * hears it.
 */

export interface ClientQuestion {
  id: string;
  text: string;
  options?: string[];
  path?: string;
  status: "open" | "answered" | "dropped";
  answer?: string;
}

export function useClientQuestions() {
  return useOperation<ClientQuestion[]>("client_question.list", {}, { refreshOn: (e) => e.type === "client_questions.changed" });
}

function Answer(props: { q: ClientQuestion }) {
  const { client } = useApp();
  const [text, setText] = useState("");
  const call = (input: Record<string, unknown>) =>
    client.call("client_question.answer", { id: props.q.id, ...input }).catch((e: Error) => toast("bad", t("work.clientQ.failed"), e.message));
  const options = props.q.options ?? [];
  return (
    <div className="cq-answer">
      {options.length ? <div className="ab-options">{options.map((o) => <button key={o} className="btn sm" onClick={() => void call({ answer: o })}>{o}</button>)}</div> : null}
      <div className="cq-answer-row">
        <input className="input" placeholder={options.length ? t("work.board.answer.orType") : t("work.clientQ.answer.placeholder")} value={text} onChange={(e) => setText(e.target.value)} onKeyDown={(e) => e.key === "Enter" && text.trim() && void call({ answer: text.trim() })} />
        <button className="btn sm" disabled={!text.trim()} onClick={() => void call({ answer: text.trim() })}><Check size={12} /> {t("work.clientQ.answer.save")}</button>
        <button className="icon-btn" title={t("work.clientQ.drop")} aria-label={t("work.clientQ.drop")} onClick={() => void call({ drop: true })}><X size={13} /></button>
      </div>
    </div>
  );
}

export function ClientQuestions() {
  const { client, engagement } = useApp();
  const { data } = useClientQuestions();
  const [toggled, setOpen] = useState<boolean>();
  const [adding, setAdding] = useState("");
  const list = (data ?? []).filter((q) => q.status !== "dropped");
  const pending = list.filter((q) => q.status === "open");
  // Open by itself while something is waiting for the client; a single line otherwise.
  const open = toggled ?? pending.length > 0;

  function copy() {
    const head = t("work.clientQ.copy.head", { project: engagement?.name ?? "" });
    const body = pending.map((q, i) => `${i + 1}. ${q.text}`).join("\n");
    void navigator.clipboard.writeText(`${head}\n\n${body}`).then(() => toast("ok", t("work.clientQ.copied"), tn("work.clientQ.copied.body", pending.length)));
  }
  const add = () =>
    adding.trim() &&
    client.call("client_question.add", { text: adding.trim() }).then(
      () => setAdding(""),
      (e: Error) => toast("bad", t("work.clientQ.failed"), e.message),
    );

  return (
    <section className="client-questions">
      <div className="cq-head">
        <button className="cq-toggle" onClick={() => setOpen(!open)}>
          <ChevronDown size={12} style={{ transform: open ? "none" : "rotate(-90deg)" }} />
          <MessageSquareQuote size={13} />
          <span className="cq-title">{t("work.clientQ.title")}</span>
          <span className="cq-count">{tn("work.clientQ.open", pending.length)}</span>
        </button>
        <div className="grow" />
        {pending.length ? <button className="btn sm" onClick={copy}><Copy size={12} /> {t("work.clientQ.copy")}</button> : null}
      </div>
      {open ? (
        <div className="cq-list">
          {list.map((q, i) => (
            <div key={q.id} className={`cq-item ${q.status}`}>
              <span className="cq-n mono">{String(i + 1).padStart(2, "0")}</span>
              <div className="cq-body">
                <div className="cq-q">{q.text}</div>
                {q.path ? <div className="cq-path">{t("work.clientQ.fromPath", { path: q.path })}</div> : null}
                {q.status === "answered" ? <div className="cq-a"><Check size={11} /> {q.answer}</div> : <Answer q={q} />}
              </div>
            </div>
          ))}
          <div className="cq-add">
            <input className="input" placeholder={t("work.clientQ.add.placeholder")} value={adding} onChange={(e) => setAdding(e.target.value)} onKeyDown={(e) => e.key === "Enter" && void add()} />
            <button className="btn sm" disabled={!adding.trim()} onClick={() => void add()}><Plus size={12} /> {t("work.clientQ.add")}</button>
          </div>
        </div>
      ) : null}
    </section>
  );
}
