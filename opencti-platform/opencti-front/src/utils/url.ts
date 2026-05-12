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
