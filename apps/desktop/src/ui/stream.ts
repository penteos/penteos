/**
 * Where a streamed piece of the agent's text goes. A notice or a status line that arrives while
 * the agent is writing (an approval decided, a run that ended) must not cut its message in two:
 * the text keeps growing in place and the interruption stays after it.
 */
export function openTextIndex<E extends { kind: string }>(entries: E[], textKind: string): number {
  for (let i = entries.length - 1; i >= 0; i--) {
    const k = entries[i]!.kind;
    if (k === textKind) return i;
    if (k !== "notice" && k !== "status") return -1;
  }
  return -1;
}

/** Appends a streamed piece to the open text, or starts a new one. */
export function appendDelta<E extends { kind: string }>(entries: E[], textKind: string, text: string): E[] {
  const i = openTextIndex(entries, textKind);
  if (i < 0) return [...entries, { kind: textKind, text } as unknown as E];
  const open = entries[i] as E & { text: string };
  return [...entries.slice(0, i), { ...open, text: open.text + text }, ...entries.slice(i + 1)];
}
