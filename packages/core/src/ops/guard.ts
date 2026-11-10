/**
 * Repetition guard. A model stuck in a loop repeats the same action with
 * the same arguments, or alternates two of them (A-B-A-B). Within an agent's recent calls, the
 * third identical action is not executed again: it gets back the result it already had with a
 * note to change approach. The sixth is refused. Reads are never held back (waiting on a run or
 * re-reading the board is normal); only actions that write or touch a target are.
 */

const WINDOW = 12;
export const ECHO_AT = 3;
export const REFUSE_AT = 6;

interface Call {
  key: string;
  outcome?: { ok: true; result: unknown } | { ok: false; error: unknown };
}

const recent = new Map<string, Call[]>();

/** Same JSON for the same arguments, whatever the key order; the free-text intent does not count. */
export function callKey(op: string, input: unknown): string {
  const stable = (v: unknown): unknown => {
    if (Array.isArray(v)) return v.map(stable);
    if (v && typeof v === "object") {
      return Object.fromEntries(
        Object.keys(v as Record<string, unknown>)
          .filter((k) => k !== "intent")
          .sort()
          .map((k) => [k, stable((v as Record<string, unknown>)[k])]),
      );
    }
    return v;
  };
  return `${op} ${JSON.stringify(stable(input ?? {}))}`;
}

export type GuardDecision =
  | { action: "run"; record: (outcome: Call["outcome"]) => void }
  | { action: "echo"; times: number; previous: NonNullable<Call["outcome"]> }
  | { action: "refuse"; times: number };

/** What to do with this call from this agent: run it, echo the previous outcome, or refuse. */
export function guardCall(scope: string, op: string, input: unknown): GuardDecision {
  const key = callKey(op, input);
  const list = recent.get(scope) ?? [];
  const same = list.filter((c) => c.key === key);
  const times = same.length + 1;
  const call: Call = { key };
  list.push(call);
  if (list.length > WINDOW) list.splice(0, list.length - WINDOW);
  recent.set(scope, list);
  if (recent.size > 500) recent.delete(recent.keys().next().value!);
  const previous = [...same].reverse().find((c) => c.outcome)?.outcome;
  if (times >= REFUSE_AT) return { action: "refuse", times };
  if (times >= ECHO_AT && previous) {
    call.outcome = previous;
    return { action: "echo", times, previous };
  }
  return { action: "run", record: (outcome) => (call.outcome = outcome) };
}

/** A person spoke to the agent: what it repeats from now on may be on purpose. */
export function resetRepeatGuard(actorId: string): void {
  for (const k of [...recent.keys()]) if (k === actorId || k.startsWith(`${actorId}:`)) recent.delete(k);
}

export function repeatNote(times: number): string {
  return `You already made this exact call ${times - 1} times recently; Penteos did not run it again and this is the previous result. Repeating it will not change the outcome: change approach (other parameters, another technique or tool, another target in the plan) or close what you are doing with what you have.`;
}
