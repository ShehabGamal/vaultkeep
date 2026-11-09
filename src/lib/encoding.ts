export const enc = new TextEncoder();
export const dec = new TextDecoder();

export function b64(buf: ArrayBuffer | Uint8Array): string {
  const u = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  let s = '';
  for (const x of u) s += String.fromCharCode(x);
  return btoa(s);
}

export const ub64 = (s: string): Uint8Array<ArrayBuffer> => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

export const hex = (buf: ArrayBuffer | Uint8Array): string =>
  Array.from(buf instanceof Uint8Array ? buf : new Uint8Array(buf), (x) => x.toString(16).padStart(2, '0')).join('');

export const uid = (): string => hex(crypto.getRandomValues(new Uint8Array(8)));
