// node-saml validates PEM keys and certificates against a strict RFC 7468 pattern:
// a blank line before the BEGIN header or more than one newline after the END footer
// makes the value fail validation, and the provider then fails to start with no error in the UI.
// Copy-paste artifacts (leading/trailing blank lines, spaces, Windows line endings) are removed here.
export const normalizeSamlPemValue = <T extends string | null | undefined>(value: T): T => {
  if (typeof value !== 'string') {
    return value;
  }
  const normalized = value.replace(/\r\n?/g, '\n').trim();
  return (normalized.length > 0 ? normalized : undefined) as T;
};
