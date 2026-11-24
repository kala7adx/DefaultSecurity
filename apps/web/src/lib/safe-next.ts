const BASE = "https://skyline.invalid";
const CONTROL = /[\u0000-\u001f\u007f]/;

/**
 * The post-login redirect target from `?next=` (ADR-0008 deep links). Only a same-origin
 * relative path survives: it must start with a single `/`, never `//` or a backslash, hold
 * no control characters, and still be all of that after URL-decoding (up to three rounds,
 * for double-encoded tricks). Anything else becomes `/`.
 */
export function safeNext(raw: string | null | undefined): string {
  if (typeof raw !== "string" || raw.length === 0 || raw.length > 2048) return "/";
  let decoded = raw;
  for (let round = 0; round < 3; round += 1) {
    let next: string;
    try {
      next = decodeURIComponent(decoded);
    } catch {
      return "/";
    }
    if (next === decoded) break;
    decoded = next;
  }
  // "." and ".." segments are never needed in a deep link, and URL parsing would resolve
  // them, e.g. "/..//evil.example" -> "//evil.example" (a scheme-relative URL).
  if (DOT_SEGMENT.test(decoded.split(/[?#]/, 1)[0] ?? "")) return "/";
  for (const value of [raw, decoded]) {
    if (!isSafePath(value)) return "/";
  }
  let url: URL;
  try {
    url = new URL(raw, BASE);
  } catch {
    return "/";
  }
  if (url.origin !== BASE) return "/";
  const out = `${url.pathname}${url.search}${url.hash}`;
  // Check the final value too: whatever parsing did, it must still be a same-origin path.
  return isSafePath(out) ? out : "/";
}

const DOT_SEGMENT = /(^|\/)\.{1,2}(\/|$)/;

function isSafePath(value: string): boolean {
  return (
    value.startsWith("/") &&
    !value.startsWith("//") &&
    !value.includes("\\") &&
    !CONTROL.test(value)
  );
}
