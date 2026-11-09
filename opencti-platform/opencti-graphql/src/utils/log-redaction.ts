import { type ASTNode, type DocumentNode, Kind, type ObjectValueNode, type SelectionSetNode, stripIgnoredCharacters, type ValueNode, visit } from 'graphql';
import conf from '../config/conf';
import { isNotEmptyField, REDACTED_INFORMATION } from '../database/utils';

// Names that always hold a secret. They are redacted at any depth, whatever the configuration:
// app:app_logs:logs_redacted_inputs can only add names to this list, never remove them.
const BASELINE_SENSITIVE_KEYS = [
  'password',
  'newPassword',
  'otp',
  'secret',
  'token',
  'api_tokens',
  'authentication_value',
  'enterprise_license',
  'oauth_client_secret',
  'oauth_access_token',
  'oauth_refresh_token',
  'new_value_cleartext',
  'platform_token',
  'xtm_hub_token',
];
const CONFIGURED_SENSITIVE_KEYS: string[] = conf.get('app:app_logs:logs_redacted_inputs') ?? [];
export const SENSITIVE_KEYS: ReadonlySet<string> = new Set([...BASELINE_SENSITIVE_KEYS, ...CONFIGURED_SENSITIVE_KEYS]);

// Mutations used to log in, to verify a one-time code or to reset a password.
// In them `code` is a secret (OTP / MFA code), elsewhere it is a plain value (connector error codes...).
const AUTHENTICATION_MUTATIONS = ['token', 'otpLogin', 'otpActivation', 'askSendOtp', 'verifyOtp', 'verifyMfa', 'changePassword'];
const AUTHENTICATION_SENSITIVE_KEYS = ['code'];
// Mutations that carry credentials: the query text of a request holding one of them is never logged.
const CREDENTIAL_MUTATIONS = [...AUTHENTICATION_MUTATIONS, 'meEdit'];

export interface RequestSensitivity {
  // The query text must not be logged
  hideQuery: boolean;
  // No variable value can be logged: without a parsed document, nobody knows which argument a variable feeds
  hideVariables: boolean;
  // Keys redacted at any depth of the variables
  sensitiveKeys: ReadonlySet<string>;
  // Variables feeding a sensitive argument or input field, whatever name the caller gave them
  sensitiveVariables: ReadonlySet<string>;
}

const isPlainObject = (value: unknown): value is Record<string, unknown> => {
  if (value === null || typeof value !== 'object') {
    return false;
  }
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
};

// Is this object an edit input ({ key, value }) whose key is sensitive?
const isSensitiveEditInput = (value: Record<string, unknown>, sensitiveKeys: ReadonlySet<string>) => {
  const { key } = value;
  return 'value' in value && (Array.isArray(key) ? key : [key]).some((k) => typeof k === 'string' && sensitiveKeys.has(k));
};

// Copy the data, replacing every sensitive value by a redaction marker, at any depth:
// - the value of a sensitive key: { password: 'xxx' }
// - the value of an edit input whose key is sensitive: { key: 'password', value: 'xxx' }
// The data given is never modified.
// - The copy is built with a loop over a stack, not a recursion: a JSON variable can be nested at will by the caller.
// - Data nested deeper than MAX_REDACTION_DEPTH is replaced by the redaction marker: the copy is then always small
//   enough in depth to be serialized (JSON.stringify, used to store and log events, overflows near 10 000 levels).
export const MAX_REDACTION_DEPTH = 100;
type Container = unknown[] | Record<string, unknown>;
export const redactSensitiveData = <T>(data: T, sensitiveKeys: ReadonlySet<string> = SENSITIVE_KEYS): T => {
  const seen = new WeakMap<object, Container>();
  const pending: Array<{ source: Container; copy: Container; depth: number }> = [];
  // Values are returned as they are, containers get an empty copy filled later from the pending stack
  const prepare = (value: unknown, depth: number): unknown => {
    if (!Array.isArray(value) && !isPlainObject(value)) {
      return value;
    }
    const known = seen.get(value);
    if (known) return known;
    if (depth > MAX_REDACTION_DEPTH) {
      return REDACTED_INFORMATION;
    }
    const copy: Container = Array.isArray(value) ? [] : {};
    seen.set(value, copy);
    pending.push({ source: value, copy, depth });
    return copy;
  };
  const result = prepare(data, 0);
  while (pending.length > 0) {
    const { source, copy, depth } = pending.pop() as { source: Container; copy: Container; depth: number };
    if (Array.isArray(source)) {
      source.forEach((element, index) => {
        (copy as unknown[])[index] = prepare(element, depth + 1);
      });
    } else {
      const isEditInput = isSensitiveEditInput(source, sensitiveKeys);
      Object.entries(source).forEach(([key, element]) => {
        const isSensitive = sensitiveKeys.has(key) || (isEditInput && key === 'value');
        (copy as Record<string, unknown>)[key] = isSensitive && isNotEmptyField(element) ? REDACTED_INFORMATION : prepare(element, depth + 1);
      });
    }
  }
  return result as T;
};

const collectVariables = (node: ASTNode, into: Set<string>) => {
  visit(node, {
    Variable: (variable) => {
      into.add(variable.name.value);
    },
  });
};

const STRUCTURAL_KINDS: string[] = [Kind.VARIABLE, Kind.LIST, Kind.OBJECT, Kind.OBJECT_FIELD, Kind.NAME, Kind.NULL];
// Does the value hold a literal (a value written in the query text itself)?
const hasLiteral = (node: ValueNode) => {
  let literal = false;
  visit(node, {
    enter: (inner) => {
      if (!STRUCTURAL_KINDS.includes(inner.kind)) {
        literal = true;
      }
    },
  });
  return literal;
};

// Names of the root fields of all the operations of the document, through inline fragments and fragment spreads.
// All operation types are read: an invalid request such as { otpLogin(...) } can put a mutation field in a query.
// A loop over a stack, not a recursion: the caller can chain as many fragments as wanted.
const listRootFields = (document: DocumentNode): string[] => {
  const fragments = new Map(document.definitions.filter((d) => d.kind === Kind.FRAGMENT_DEFINITION).map((d) => [d.name.value, d]));
  const names: string[] = [];
  const visitedFragments = new Set<string>();
  const pending: SelectionSetNode[] = document.definitions
    .filter((definition) => definition.kind === Kind.OPERATION_DEFINITION)
    .map((definition) => definition.selectionSet);
  while (pending.length > 0) {
    const selectionSet = pending.pop() as SelectionSetNode;
    selectionSet.selections.forEach((selection) => {
      if (selection.kind === Kind.FIELD) {
        names.push(selection.name.value);
      } else if (selection.kind === Kind.INLINE_FRAGMENT) {
        pending.push(selection.selectionSet);
      } else if (!visitedFragments.has(selection.name.value)) {
        visitedFragments.add(selection.name.value);
        const fragment = fragments.get(selection.name.value);
        if (fragment) pending.push(fragment.selectionSet);
      }
    });
  }
  return names;
};

// Find what must be redacted to log a GraphQL request, from its parsed document.
// Without a document (the request could not be parsed), neither the query text nor the variable values are logged.
export const analyzeRequestSensitivity = (document: DocumentNode | undefined | null): RequestSensitivity => {
  if (!document) {
    return { hideQuery: true, hideVariables: true, sensitiveKeys: SENSITIVE_KEYS, sensitiveVariables: new Set() };
  }
  const rootFields = listRootFields(document);
  const isAuthentication = rootFields.some((name) => AUTHENTICATION_MUTATIONS.includes(name));
  const sensitiveKeys = isAuthentication ? new Set([...SENSITIVE_KEYS, ...AUTHENTICATION_SENSITIVE_KEYS]) : SENSITIVE_KEYS;
  let hideQuery = rootFields.some((name) => CREDENTIAL_MUTATIONS.includes(name));
  const sensitiveVariables = new Set<string>();
  const variablesWithDefaultLiteral = new Set<string>();
  const markSensitiveValue = (value: ValueNode) => {
    collectVariables(value, sensitiveVariables);
    if (hasLiteral(value)) {
      hideQuery = true;
    }
  };
  visit(document, {
    // meEdit(password: $anyName), userAdd(input: { password: "xxx" })
    Argument: (argument) => {
      if (sensitiveKeys.has(argument.name.value)) markSensitiveValue(argument.value);
    },
    ObjectField: (field) => {
      if (sensitiveKeys.has(field.name.value)) markSensitiveValue(field.value);
    },
    // fieldPatch(input: { key: "password", value: $anyName })
    ObjectValue: (object: ObjectValueNode) => {
      const keyField = object.fields.find((f) => f.name.value === 'key');
      const valueField = object.fields.find((f) => f.name.value === 'value');
      if (!keyField || !valueField) {
        return;
      }
      const keyValues = keyField.value.kind === Kind.LIST ? keyField.value.values : [keyField.value];
      // A key given by a variable cannot be checked here, the value is then handled as sensitive
      const isSensitive = keyValues.some((k) => k.kind !== Kind.STRING || sensitiveKeys.has(k.value));
      if (isSensitive) markSensitiveValue(valueField.value);
    },
    // query($anyName: String = "xxx"): the default value is written in the query text
    VariableDefinition: (definition) => {
      if (definition.defaultValue && hasLiteral(definition.defaultValue)) {
        variablesWithDefaultLiteral.add(definition.variable.name.value);
      }
    },
  });
  if ([...sensitiveVariables].some((name) => variablesWithDefaultLiteral.has(name))) {
    hideQuery = true;
  }
  return { hideQuery, hideVariables: false, sensitiveKeys, sensitiveVariables };
};

// Request variables ready to be logged or stored in an activity event
export const redactRequestVariables = <T extends Record<string, unknown>>(variables: T | undefined | null, sensitivity: RequestSensitivity): T => {
  if (sensitivity.hideVariables) {
    // The variable names are kept to help debugging, never their values
    return Object.fromEntries(Object.keys(variables ?? {}).map((name) => [name, REDACTED_INFORMATION])) as T;
  }
  const redacted = redactSensitiveData(variables ?? {}, sensitivity.sensitiveKeys) as Record<string, unknown>;
  sensitivity.sensitiveVariables.forEach((name) => {
    if (isNotEmptyField(redacted[name])) {
      redacted[name] = REDACTED_INFORMATION;
    }
  });
  return redacted as T;
};

// Query text ready to be logged
export const redactRequestQuery = (query: string | undefined | null, sensitivity: RequestSensitivity): string => {
  if (sensitivity.hideQuery) {
    return REDACTED_INFORMATION;
  }
  return stripIgnoredCharacters(query ?? 'undefined');
};
