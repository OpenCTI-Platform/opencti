// A bare `new Error()` stringifies to just "Error", and thrown non-Error values need
// wrapping - both are normalized here into a readable { message, stack } pair before being logged.
export const normalizeFrontendError = (thrown: unknown): { message: string; stack?: string } => {
  const normalizedError = thrown instanceof Error ? thrown : new Error(describeThrownValue(thrown));
  const message = normalizedError.message
    ? safeString(normalizedError, `${normalizedError.name}: <unreadable error message>`)
    : `${normalizedError.name} (no message provided)`;
  return { message, stack: normalizedError.stack };
};

// Thrown objects may carry secrets (tokens, credentials, large payloads) as property values, so
// only their key names are surfaced here, never the values and never a full serialized dump.
const describeThrownValue = (thrown: unknown): string => {
  if (typeof thrown === 'string') {
    return thrown;
  }
  if (thrown && typeof thrown === 'object') {
    const keys = safeKeys(thrown);
    return keys.length > 0
      ? `Non-Error object thrown with keys: [${keys.join(', ')}]`
      : 'Non-Error object thrown with no enumerable keys';
  }
  return safeString(thrown, 'Unserializable value thrown');
};

// Object.keys can throw on exotic/proxy objects, and String()/toString() can throw on hostile
// objects with a broken custom conversion; both are guarded so the crash reporter itself can
// never throw and silently drop the log.
const safeKeys = (thrown: object): string[] => {
  try {
    return Object.keys(thrown).slice(0, 20);
  } catch {
    return [];
  }
};

const safeString = (value: unknown, fallback: string): string => {
  try {
    return String(value);
  } catch {
    return fallback;
  }
};
