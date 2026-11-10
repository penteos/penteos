import { ago, t as tr } from "../i18n";
import { Bot, Cpu, ShieldAlert, User } from "./icons";
import { type ReactNode, useEffect, useState } from "react";
import type { Actor } from "../state";

/** Relative time in the operator's language. */
export function relTime(iso: string | undefined, now = Date.now()): string {
  return ago(iso, now);
}

/** Re-renders periodically so relative times stay fresh. */
export function useTick(ms = 15000): number {
  const [t, setT] = useState(Date.now());
  useEffect(() => {
    const id = setInterval(() => setT(Date.now()), ms);
    return () => clearInterval(id);
  }, [ms]);
  return t;
}

export function Badge(props: { tone?: string; children: ReactNode; title?: string }) {
  return (
    <span className={`badge ${props.tone ?? ""}`} title={props.title}>
      {props.children}
    </span>
  );
}

export function ScopeBadge(props: { out: boolean }) {
  return props.out ? (
    <Badge tone="out" title={tr("data.scope.outTitle")}>
      <ShieldAlert size={11} /> {tr("data.scope.out")}
    </Badge>
  ) : (
    <Badge>{tr("data.scope.in")}</Badge>
  );
}

/** The built-in agents, by their fixed identity. */
const AGENT_NAMES: Record<string, string> = { "01JA000000000000000000MSTR": "common.maestro", "01JA0000000000000000VRFYR0": "common.verifier" };

export function ActorBadge(props: { actor: Actor }) {
  const { actor } = props;
  if (actor.type === "agent")
    return (
      <Badge tone="agent">
        <Bot size={11} /> {tr(AGENT_NAMES[actor.id] ?? "common.agent")}
      </Badge>
    );
  if (actor.type === "human")
    return (
      <Badge tone="info">
        <User size={11} /> {tr("common.operator")}
      </Badge>
    );
  return (
    <Badge>
      <Cpu size={11} /> {actor.id.replace(/@.*/, "")}
    </Badge>
  );
}

export function Empty(props: { icon: ReactNode; title: string; children?: ReactNode }) {
  return (
    <div className="empty">
      <div>
        <div className="icon">{props.icon}</div>
        <h4>{props.title}</h4>
        {props.children ? <div className="empty-text">{props.children}</div> : null}
      </div>
    </div>
  );
}

// ---------------------------------------------------------------------------------------------
// Toasts
// ---------------------------------------------------------------------------------------------

type Toast = { id: number; tone: "ok" | "bad" | "info"; title: string; body?: string };
let toastSeq = 0;
const toastListeners = new Set<(t: Toast[]) => void>();
let toasts: Toast[] = [];

function dismiss(id: number) {
  toasts = toasts.filter((x) => x.id !== id);
  for (const l of toastListeners) l(toasts);
}

export function toast(tone: Toast["tone"], title: string, body?: string) {
  const t = { id: ++toastSeq, tone, title, ...(body ? { body } : {}) };
  toasts = [...toasts, t];
  for (const l of toastListeners) l(toasts);
  setTimeout(() => dismiss(t.id), 5200);
}

export function Toasts() {
  const [list, setList] = useState<Toast[]>(toasts);
  useEffect(() => {
    toastListeners.add(setList);
    return () => {
      toastListeners.delete(setList);
    };
  }, []);
  return (
    <div className="toast-stack">
      {list.map((t) => (
        <div key={t.id} className={`toast ${t.tone}`}>
          <button className="toast-x" title={tr("common.close")} onClick={() => dismiss(t.id)}>×</button>
          <div className="t">{t.title}</div>
          {t.body ? <div className="s" title={t.body}>{t.body}</div> : null}
        </div>
      ))}
    </div>
  );
}

export function Modal(props: { title: ReactNode; icon?: ReactNode; children: ReactNode; footer: ReactNode; onClose: () => void }) {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && props.onClose();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [props]);
  return (
    <div className="overlay" onMouseDown={(e) => e.target === e.currentTarget && props.onClose()}>
      <div className="modal">
        <div className="modal-h">
          {props.icon}
          {props.title}
        </div>
        <div className="modal-b">{props.children}</div>
        <div className="modal-f">{props.footer}</div>
      </div>
    </div>
  );
}
