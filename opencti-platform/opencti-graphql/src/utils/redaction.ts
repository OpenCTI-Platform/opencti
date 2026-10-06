import { type DocumentNode, Kind, type OperationDefinitionNode, parse, type ValueNode, visit } from 'graphql';
import { isNotEmptyField } from '../database/utils';

export const REDACTED_VALUE = '** Redacted **';

// Kept in code so that a deployment overriding app:app_logs:logs_redacted_inputs
// can add keys to the redaction but never remove these ones.
export const BASELINE_REDACTED_INPUTS = [
  'password',
  'password_history',
  'newPassword',
  'otp',
  'code', // MFA code
  'secret',
  'token',
  'api_tokens',
  'oauth_client_secret', // SMTP
  'oauth_access_token',
  'oauth_refresh_token',
  'new_value_cleartext', // authentication provider secrets
];

// User attributes holding password hashes: never broadcast, never carried by a context user.
export const USER_SECRET_ATTRIBUTES = ['password', 'password_history'];

export const withoutUserSecrets = <T extends Record<string, any>>(user: T): T => {
  return Object.fromEntries(Object.entries(user).filter(([key]) => !USER_SECRET_ATTRIBUTES.includes(key))) as T;
};

// Root fields of the mutations whose query text can carry a credential as an inline literal.
export const CREDENTIAL_MUTATIONS = [
  'token',
  'otpActivation',
  'otpLogin',
  'userAdd',
  'userEdit',
  'meEdit',
  'changePassword',
  'verifyOtp',
  'verifyMfa',
  'smtpConfigurationEdit',
  'oidcProviderAdd',
  'oidcProviderEdit',
  'samlProviderAdd',
  'samlProviderEdit',
  'ldapProviderAdd',
  'ldapProviderEdit',
];

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

// The parsed request, or undefined when it cannot be parsed: such a request cannot be classified.
export const resolveRequestDocument = (document: DocumentNode | null | undefined, query: string | null | undefined): DocumentNode | undefined => {
  if (document) {
    return document;
  }
  if (!query) {
    return undefined;
  }
  try {
    return parse(query);
  } catch {
    return undefined;
  }
};

// The whole request text is logged, not only the operation that runs: any credential operation
// in it, or a request that cannot be classified, keeps the text out of the logs.
export const mayCarryCredential = (document: DocumentNode | null | undefined): boolean => {
  if (!document) {
    return true;
  }
  return document.definitions.some((definition) => definition.kind === Kind.OPERATION_DEFINITION && isCredentialOperation(definition));
};

// Variable names are chosen by the caller, so a variable is sensitive by where it is used: an argument
// or an input field with a sensitive name, or the `value` of an inline `{ key, value }` edit input whose key is sensitive.
const sensitiveVariableNames = (document: DocumentNode, sensitiveKeys: string[]): Set<string> => {
  const names = new Set<string>();
  const visitValue = (value: ValueNode, isSensitive: boolean) => {
    if (value.kind === Kind.VARIABLE) {
      if (isSensitive) names.add(value.name.value);
    } else if (value.kind === Kind.LIST) {
      value.values.forEach((item) => visitValue(item, isSensitive));
    } else if (value.kind === Kind.OBJECT) {
      const keyField = value.fields.find((field) => field.name.value === 'key');
      const isSensitiveEditInput = keyField?.value.kind === Kind.STRING && sensitiveKeys.includes(keyField.value.value);
      value.fields.forEach((field) => {
        visitValue(field.value, sensitiveKeys.includes(field.name.value) || (isSensitiveEditInput && field.name.value === 'value'));
      });
    }
  };
  visit(document, {
    Argument: (node) => {
      visitValue(node.value, sensitiveKeys.includes(node.name.value));
      return false;
    },
  });
  return names;
};

// The request variables as they can be logged or audited. Inside a variable, keys are schema names and
// are redacted by name. A request that cannot be classified has all its variables redacted.
export const redactRequestVariables = (
  variables: unknown,
  document: DocumentNode | null | undefined,
  sensitiveKeys: string[],
  marker: string,
): unknown => {
  if (!isPlainObject(variables) || Object.keys(variables).length === 0) {
    return variables;
  }
  if (!document) {
    return marker;
  }
  const sensitiveVariables = sensitiveVariableNames(document, sensitiveKeys);
  return Object.fromEntries(Object.entries(variables).map(([name, value]) => {
    if ((sensitiveVariables.has(name) || sensitiveKeys.includes(name)) && isNotEmptyField(value)) {
      return [name, marker];
    }
    return [name, redactSensitiveData(value, sensitiveKeys, marker)];
  }));
};
