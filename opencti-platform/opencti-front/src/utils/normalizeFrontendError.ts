// A bare `new Error()` stringifies to just "Error", and thrown non-Error values need
// wrapping - both are normalized here into a readable { message, stack } pair before being logged.
export const normalizeFrontendError = (thrown: unknown): { message: string; stack?: string } => {
  const normalizedError = thrown instanceof Error ? thrown : new Error(describeThrownValue(thrown));
  const message = normalizedError.message
    ? String(normalizedError)
    : `${normalizedError.name} (no message provided)`;
  return { message, stack: normalizedError.stack };
};

// String() never throws, unlike JSON.stringify on circular references, so it's the safe fallback.
const describeThrownValue = (thrown: unknown): string => {
  if (typeof thrown === 'string') {
    return thrown;
  }
  try {
    return JSON.stringify(thrown) ?? String(thrown);
  } catch {
    return String(thrown);
  }
};
