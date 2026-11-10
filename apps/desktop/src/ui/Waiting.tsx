import { CheckCircle2, CircleHelp, Hand, Loader2, Play } from "./icons";
import { useState } from "react";
import { type Entity, useApp, useOperation } from "../state";
import { toast } from "./bits";
import { asksOperator, questionOf } from "../tasks";
import { t, tn } from "../i18n";
import { browseOf } from "../browse";
import { BrowseRequest } from "./BrowseRequest";

/**
 * "Waiting for you": what the agents need from the operator right now, always in the same place above
 * the composer. If it is empty and the Maestro is not working, nothing is waiting on the operator.
 */

export function openQuestions(tasks: Entity[] | undefined): Entity[] {
  return (tasks ?? []).filter(asksOperator);
}

function Question(props: { task: Entity }) {
  const { client } = useApp();
  const [text, setText] = useState("");
  const [busy, setBusy] = useState(false);
  async function answer() {
    if (!text.trim()) return;
    setBusy(true);
    try {
      await client.call("task.answer", { id: props.task.id, answer: text.trim() });
      toast("ok", t("team.waiting.answerSent.title"), t("team.waiting.answerSent.body"));
      setText("");
    } catch (e) {
      toast("bad", t("team.waiting.sendFailed"), (e as Error).message);
    } finally {
      setBusy(false);
    }
  }
  return (
    <div className="wq">
      <div className="wq-q"><CircleHelp size={12} /> <span>{questionOf(props.task).question}</span></div>
      {questionOf(props.task).detail ? <div className="wq-d">{questionOf(props.task).detail}</div> : null}
      <div className="wq-a">
        <input className="input sm" placeholder={t("team.waiting.answerPlaceholder")} value={text} onChange={(e) => setText(e.target.value)} onKeyDown={(e) => e.key === "Enter" && answer()} />
        <button className="btn sm primary" disabled={busy || !text.trim()} onClick={answer}>{t("common.reply")}</button>
      </div>
    </div>
  );
}

export function WaitingStrip(props: { running: boolean; parked: boolean; hasConversation: boolean; inlineApprovals: number; onResume: () => void }) {
  const { approvals } = useApp();
  const tasks = useOperation<Entity[]>("entity.query", { kind: "task", limit: 2000 }, { refreshOn: (e) => e.kind === "task" });
  const questions = openQuestions(tasks.data);
  // Approvals outside the conversation are already cards right above this strip: not repeated here.
  const pending = props.inlineApprovals ? approvals.length : 0;
  const waiting = questions.length > 0 || pending > 0 || props.parked;

  if (!waiting) {
    if (approvals.length) return null;
    if (!props.hasConversation) return null;
    return (
      <div className="waiting idle">
        {props.running ? <><Loader2 size={12} className="spin" /> {t("team.waiting.working")}</> : <><CheckCircle2 size={12} /> {t("team.waiting.idle")}</>}
      </div>
    );
  }
  return (
    <div className="waiting">
      <div className="w-head"><Hand size={12} /> <span className="head-t">{t("team.waiting.title")}</span><span className="kick mono">{String(pending + questions.length).padStart(2, "0")}</span></div>
      {pending ? (
        <div className="w-line">
          {tn("team.waiting.approvalsInline", pending)}
        </div>
      ) : null}
      {questions.map((q) => (browseOf(q) ? <div key={q.id} className="wq"><BrowseRequest task={q} /></div> : <Question key={q.id} task={q} />))} {/* i18n-ignore */}
      {props.parked && !props.running ? (
        <div className="w-line">
          {t("team.waiting.parked")}
          <button className="btn sm" onClick={props.onResume}><Play size={11} /> {t("team.waiting.continue")}</button>
        </div>
      ) : null}
    </div>
  );
}
