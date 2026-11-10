const ENCODING = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/**
 * Generates a ULID. Works offline and in both Node and the browser, which matters because
 * entities are created locally in solo mode and synced later in team mode.
 */
export function ulid(now: number = Date.now()): string {
  let time = "";
  let t = now;
  for (let i = 0; i < 10; i++) {
    time = ENCODING[t % 32] + time;
    t = Math.floor(t / 32);
  }
  // 256 is a multiple of 32, so taking each byte modulo 32 has no bias.
  const bytes = globalThis.crypto.getRandomValues(new Uint8Array(16));
  let random = "";
  for (const byte of bytes) random += ENCODING[byte % 32];
  return time + random;
}
