import { randomBytes } from "node:crypto";

/**
 * WebSocket frames (RFC 6455) for the proxy: read what goes by, record each message, and
 * re-encode the ones the operator edits. Frames nobody touches are forwarded byte for byte.
 */

export interface Frame {
  fin: boolean;
  opcode: number;
  masked: boolean;
  /** Unmasked payload. */
  payload: Buffer;
  /** The frame exactly as it arrived. */
  raw: Buffer;
}

export const OP = { continuation: 0, text: 1, binary: 2, close: 8, ping: 9, pong: 10 } as const;

const MAX_FRAME = 64 * 1024 * 1024;

/** Incremental frame reader: feed bytes, take complete frames. */
export class FrameReader {
  private buf: Buffer = Buffer.alloc(0);

  push(chunk: Buffer): Frame[] {
    this.buf = this.buf.length ? Buffer.concat([this.buf, chunk]) : chunk;
    const out: Frame[] = [];
    for (;;) {
      const f = this.next();
      if (!f) break;
      out.push(f);
    }
    return out;
  }

  private next(): Frame | undefined {
    const b = this.buf;
    if (b.length < 2) return undefined;
    const fin = (b[0]! & 0x80) !== 0;
    const opcode = b[0]! & 0x0f;
    const masked = (b[1]! & 0x80) !== 0;
    let len = b[1]! & 0x7f;
    let off = 2;
    if (len === 126) {
      if (b.length < 4) return undefined;
      len = b.readUInt16BE(2);
      off = 4;
    } else if (len === 127) {
      if (b.length < 10) return undefined;
      const big = b.readBigUInt64BE(2);
      if (big > BigInt(MAX_FRAME)) throw new Error("frame demasiado grande");
      len = Number(big);
      off = 10;
    }
    const maskOff = off;
    if (masked) off += 4;
    if (b.length < off + len) return undefined;
    let payload = b.subarray(off, off + len);
    if (masked) {
      const key = b.subarray(maskOff, maskOff + 4);
      payload = Buffer.from(payload);
      for (let i = 0; i < payload.length; i++) payload[i]! ^= key[i % 4]!;
    }
    const raw = b.subarray(0, off + len);
    this.buf = b.subarray(off + len);
    return { fin, opcode, masked, payload: Buffer.from(payload), raw: Buffer.from(raw) };
  }
}

/** A frame for the wire. Client→server frames must be masked; server→client must not. */
export function encodeFrame(opcode: number, payload: Buffer, mask: boolean, fin = true): Buffer {
  const len = payload.length;
  const head: number[] = [(fin ? 0x80 : 0) | opcode];
  const maskBit = mask ? 0x80 : 0;
  if (len < 126) head.push(maskBit | len);
  else if (len < 65536) head.push(maskBit | 126, (len >> 8) & 0xff, len & 0xff);
  else {
    head.push(maskBit | 127);
    const big = Buffer.alloc(8);
    big.writeBigUInt64BE(BigInt(len));
    head.push(...big);
  }
  if (!mask) return Buffer.concat([Buffer.from(head), payload]);
  const key = randomBytes(4);
  const body = Buffer.from(payload);
  for (let i = 0; i < body.length; i++) body[i]! ^= key[i % 4]!;
  return Buffer.concat([Buffer.from(head), key, body]);
}

/** Whether a payload reads as UTF-8 text. */
export function isUtf8(b: Buffer): boolean {
  return Buffer.from(b.toString("utf8"), "utf8").equals(b);
}
