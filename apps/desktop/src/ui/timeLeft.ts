/**
 * "45 min", "7 h 12 min", "8 h", "23 h": how long until something expires. Minutes are rounded
 * once, on the total, so 7 h 59.6 min reads "8 h" and never "7 h 60 min".
 */
export function timeLeft(ms: number): string {
  const minutes = Math.max(1, Math.round(ms / 60_000));
  if (minutes < 60) return `${minutes} min`;
  const h = Math.floor(minutes / 60);
  const m = minutes % 60;
  // Past ten hours the minutes are noise.
  return h >= 10 || m === 0 ? `${h} h` : `${h} h ${m} min`;
}
