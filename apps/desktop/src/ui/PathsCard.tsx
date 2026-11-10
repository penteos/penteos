import { ArrowRight, Check, MessageSquareQuote, Route } from "./icons";
import { useState } from "react";
import { useApp } from "../state";
import { toast } from "./bits";
import { t } from "../i18n";

/**
 * How a round of work ends: where things stand and the paths worth
 * exploring. A pentest is never done in one pass; the operator picks where to go next, or turns
 * what depends on the client into a question for them.
 */

interface Path {
  title: string;
  why: string;
  payoff?: string;
  needs: "nothing" | "approval" | "browser" | "credentials" | "client";
  noise?: "low" | "medium" | "high";
  question?: string;
}

export function PathsCard(props: { input: unknown }) {
  const { client } = useApp();
  const input = (props.input ?? {}) as { status?: string; paths?: Path[] };
  const paths = Array.isArray(input.paths) ? input.paths : [];
  const [done, setDone] = useState<Record<number, "followed" | "asked">>({});
  if (!paths.length) return null;

  const follow = (i: number, p: Path) => {
    window.dispatchEvent(new CustomEvent("penteos:ask-maestro", { detail: t("agent.paths.followPrompt", { title: p.title }) }));
    setDone((d) => ({ ...d, [i]: "followed" }));
  };
  const ask = (i: number, p: Path) =>
    client.call("client_question.add", { text: p.question?.trim() || p.title, path: p.title }).then(
      () => {
        setDone((d) => ({ ...d, [i]: "asked" }));
        toast("ok", t("agent.paths.asked"), t("agent.paths.askedBody"));
      },
      (e: Error) => toast("bad", t("work.clientQ.failed"), e.message),
    );

  return (
    <div className="paths-card">
      <div className="pc-head">
        <Route size={13} /> <span className="pc-title">{t("agent.paths.title")}</span>
      </div>
      {input.status ? <div className="pc-status">{input.status}</div> : null}
      <div className="pc-list">
        {paths.map((p, i) => {
          const fromClient = p.needs === "credentials" || p.needs === "client";
          return (
            <div key={i} className={`pc-path ${done[i] ?? ""}`}>
              <div className="pc-t">{p.title}</div>
              <div className="pc-why">{p.why}</div>
              {p.payoff ? <div className="pc-payoff">{t("agent.paths.payoff", { payoff: p.payoff })}</div> : null}
              <div className="pc-foot">
                <span className={`pc-needs ${fromClient ? "client" : ""}`}>{t(`agent.paths.needs.${p.needs}`)}</span>
                {p.noise ? <span className={`pc-noise ${p.noise}`}>{t(`agent.paths.noise.${p.noise}`)}</span> : null}
                <span className="grow" />
                {done[i] === "followed" ? (
                  <span className="pc-done"><Check size={11} /> {t("agent.paths.followed")}</span>
                ) : done[i] === "asked" ? (
                  <span className="pc-done"><Check size={11} /> {t("agent.paths.inList")}</span>
                ) : fromClient ? (
                  <button className="btn sm" onClick={() => void ask(i, p)}><MessageSquareQuote size={12} /> {t("agent.paths.ask")}</button>
                ) : (
                  <button className="btn sm primary" onClick={() => follow(i, p)}>{t("agent.paths.follow")} <ArrowRight size={12} /></button>
                )}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
