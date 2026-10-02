import { Kind, type OperationDefinitionNode } from 'graphql';
import { isNotEmptyField } from '../database/utils';

// Kept in code so that a deployment overriding app:app_logs:logs_redacted_inputs
// can add keys to the redaction but never remove these ones.
export const BASELINE_REDACTED_INPUTS = ['password', 'password_history', 'newPassword', 'otp', 'secret', 'token', 'api_tokens'];

// User attributes holding password hashes: never broadcast, never carried by a context user.
export const USER_SECRET_ATTRIBUTES = ['password', 'password_history'];

export const withoutUserSecrets = <T extends Record<string, any>>(user: T): T => {
  return Object.fromEntries(Object.entries(user).filter(([key]) => !USER_SECRET_ATTRIBUTES.includes(key))) as T;
};

// Root fields of the mutations whose query text can carry a credential as an inline literal.
export const CREDENTIAL_MUTATIONS = ['token', 'otpActivation', 'otpLogin', 'userAdd', 'userEdit', 'meEdit', 'changePassword', 'verifyOtp', 'verifyMfa'];

export const buildRedactedInputs = (configured: unknown): string[] => {
  const extra = Array.isArray(configured) ? configured.filter((key): key is string => typeof key === 'string') : [];
  return [...new Set([...BASELINE_REDACTED_INPUTS, ...extra])];
};

const isPlainObject = (value: unknown): value is Record<string, unknown> => {
  if (typeof value !== 'object' || value === null) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
};

// Returns a copy of `data` where every sensitive key, at any depth, and the `value`
// of every `{ key, value }` edit input whose key is sensitive, hold `marker` instead.
export const redactSensitiveData = (data: unknown, sensitiveKeys: string[], marker: string): unknown => {
  if (Array.isArray(data)) {
    return data.map((item) => redactSensitiveData(item, sensitiveKeys, marker));
  }
  if (!isPlainObject(data)) {
    return data;
  }
  const isSensitiveEditInput = typeof data.key === 'string' && sensitiveKeys.includes(data.key);
  return Object.fromEntries(Object.entries(data).map(([key, value]) => {
    const isSensitive = sensitiveKeys.includes(key) || (isSensitiveEditInput && key === 'value');
    if (isSensitive && isNotEmptyField(value)) {
      return [key, marker];
    }
    return [key, redactSensitiveData(value, sensitiveKeys, marker)];
  }));
};

// A root selection that is not a plain field (a fragment spread) can hide a credential mutation, so it counts as one.
export const isCredentialOperation = (operation: OperationDefinitionNode | null | undefined): boolean => {
  if (operation?.operation !== 'mutation') {
    return false;
  }
  return operation.selectionSet.selections.some((selection) => {
    return selection.kind !== Kind.FIELD || CREDENTIAL_MUTATIONS.includes(selection.name.value);
  });
};
