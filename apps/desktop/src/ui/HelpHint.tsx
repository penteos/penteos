import { CircleHelp } from "./icons";
import { useState } from "react";

/**
 * A panel's explanation: in full the first few times the operator opens the panel, then folded
 * into a "?" that shows it on hover. Useful while learning, out of the way once known.
 */
const SHOWN_TIMES = 3;

function seen(id: string): number {
  try {
    const key = `penteos.hint.${id}`;
    const n = Number(localStorage.getItem(key) ?? "0");
    localStorage.setItem(key, String(n + 1));
    return n;
  } catch {
    return 0;
  }
}

export function HelpHint(props: { id: string; text: string }) {
  // Counted once per mount: opening the panel is one view.
  const [learning] = useState(() => SHOWN_TIMES > seen(props.id));
  if (learning) return <span className="hint">{props.text}</span>;
  return (
    <span className="help-hint" tabIndex={0} aria-label={props.text}>
      <CircleHelp size={13} />
      <span className="help-hint-text" role="tooltip">{props.text}</span>
    </span>
  );
}
