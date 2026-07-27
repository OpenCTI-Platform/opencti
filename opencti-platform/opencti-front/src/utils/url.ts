// Matches any URI scheme (e.g. https:, http:, javascript:, data:, ftp:)
const ABSOLUTE_URL_SCHEME_PATTERN = /^[a-zA-Z][a-zA-Z0-9+\-.]*:/;

// Matches percent-encoded characters that, once decoded, could form a scheme (e.g. javas%63ript:)
const ENCODED_SCHEME_PATTERN = /^[a-zA-Z0-9+\-.]*%[0-9a-fA-F]{2}/;

/**
 * Returns true if the given string is a relative URL.
 * A relative URL has no scheme (e.g. https:) and no protocol-relative prefix (//).
 * Also guards against encoded schemes and backslash-based paths some browsers treat as absolute.
 */
export const isRelativeUrl = (value: string): boolean => {
  const trimmed = value.trim();
  return trimmed.length > 0
    && !trimmed.startsWith('//')
    && !trimmed.startsWith('\\')
    && !ABSOLUTE_URL_SCHEME_PATTERN.test(trimmed)
    && !ENCODED_SCHEME_PATTERN.test(trimmed);
};

/**
 * Only `http(s)` URLs are safe to render as a link or hand to `window.open`
 * as a top-level navigation. Use this on any server-provided absolute URL
 * (e.g. `xtm_one_url` from `/chatbot/config`) so that a misconfigured or
 * tampered value (`javascript:`, `data:`, ...) is never displayed or opened.
 * Returns the trimmed URL when valid, else null.
 */
export const toSafeHttpUrl = (rawUrl: string | null): string | null => {
  const trimmed = rawUrl?.trim();
  if (!trimmed) return null;
  try {
    const { protocol } = new URL(trimmed);
    return protocol === 'http:' || protocol === 'https:' ? trimmed : null;
  } catch {
    return null;
  }
};
