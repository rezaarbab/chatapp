export function bytesToB64(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}

export function b64ToBytes(b64: string): Uint8Array {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/**
 * Normalizes D1 BLOB reads. Real D1 and miniflare return BLOB columns in
 * different shapes (ArrayBuffer vs Uint8Array); this makes the Worker
 * environment-agnostic without touching the crypto layer.
 */
export function asBytes(v: unknown): Uint8Array {
  if (v instanceof Uint8Array) return v;
  if (v instanceof ArrayBuffer) return new Uint8Array(v);
  if (typeof v === "string") return b64ToBytes(v);
  if (v && typeof (v as ArrayBufferView).buffer === "object") {
    return new Uint8Array((v as ArrayBufferView).buffer);
  }
  if (Array.isArray(v)) return Uint8Array.from(v as number[]);
  if (v && typeof v === "object") {
    const o = v as Record<string, unknown>;
    if (Array.isArray(o.data)) return Uint8Array.from(o.data as number[]);
  }
  throw new Error("unsupported binary shape returned by D1");
}

export function bytesToHex(bytes: Uint8Array): string {
  return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
}

export async function sha256(bytes: Uint8Array): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", bytes as BufferSource);
  return bytesToHex(new Uint8Array(digest));
}

export function randomBytes(len: number): Uint8Array {
  const out = new Uint8Array(len);
  crypto.getRandomValues(out);
  return out;
}

export function randomHex(byteLen: number): string {
  return bytesToHex(randomBytes(byteLen));
}
