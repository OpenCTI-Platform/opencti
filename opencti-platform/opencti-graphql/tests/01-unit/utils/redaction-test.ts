import { describe, expect, it } from 'vitest';
import { parse, type OperationDefinitionNode } from 'graphql';
import {
  BASELINE_REDACTED_INPUTS,
  buildRedactedInputs,
  isCredentialOperation,
  mayCarryCredential,
  redactRequestVariables,
  redactSensitiveData,
  resolveRequestDocument,
} from '../../../src/utils/redaction';

const KEYS = buildRedactedInputs([]);
const MARK = '** Redacted **';

const operationOf = (query: string) => parse(query).definitions[0] as OperationDefinitionNode;

describe('buildRedactedInputs', () => {
  it('keeps the baseline when the configuration overrides the list', () => {
    const keys = buildRedactedInputs(['token']);
    BASELINE_REDACTED_INPUTS.forEach((key) => expect(keys).toContain(key));
  });

  it('adds the configured keys and ignores anything that is not a string', () => {
    const keys = buildRedactedInputs(['enterprise_license', 42, null]);
    expect(keys).toContain('enterprise_license');
    expect(keys).not.toContain(42);
    expect(keys).not.toContain(null);
  });

  it('falls back to the baseline when the configuration is missing', () => {
    expect(buildRedactedInputs(undefined)).toEqual(BASELINE_REDACTED_INPUTS);
  });

  it('covers the MFA code, the SMTP credentials and the authentication provider secrets', () => {
    ['code', 'oauth_client_secret', 'oauth_access_token', 'oauth_refresh_token', 'new_value_cleartext'].forEach((key) => {
      expect(BASELINE_REDACTED_INPUTS).toContain(key);
    });
  });
});

describe('redactSensitiveData', () => {
  it('redacts the value of a single edit input whose key is sensitive', () => {
    const variables = { id: 'user-1', input: { key: 'password', value: 'Clear-text-1!' } };
    expect(redactSensitiveData(variables, KEYS, MARK)).toEqual({ id: 'user-1', input: { key: 'password', value: MARK } });
  });

  it('redacts the value of every sensitive edit input in an array', () => {
    const variables = { input: [{ key: 'password', value: ['Clear-text-1!'] }, { key: 'language', value: ['fr-fr'] }] };
    expect(redactSensitiveData(variables, KEYS, MARK)).toEqual({
      input: [{ key: 'password', value: MARK }, { key: 'language', value: ['fr-fr'] }],
    });
  });

  it('redacts sensitive keys at any depth, including the current password argument', () => {
    const variables = { password: 'Current-1!', input: { transactionId: 'tx-1', otp: '12345678', newPassword: 'Clear-text-1!' } };
    expect(redactSensitiveData(variables, KEYS, MARK)).toEqual({
      password: MARK,
      input: { transactionId: 'tx-1', otp: MARK, newPassword: MARK },
    });
  });

  it('leaves empty values and non-sensitive data as they are', () => {
    const variables = { password: '', input: { key: 'password', value: [] }, name: 'report' };
    expect(redactSensitiveData(variables, KEYS, MARK)).toEqual(variables);
  });

  it('does not mutate the data it is given', () => {
    const variables = { input: { key: 'password', value: 'Clear-text-1!' } };
    redactSensitiveData(variables, KEYS, MARK);
    expect(variables.input.value).toBe('Clear-text-1!');
  });

  it('leaves non-plain objects untouched', () => {
    const date = new Date('2026-10-01T00:00:00Z');
    expect(redactSensitiveData({ created: date }, KEYS, MARK)).toEqual({ created: date });
  });
});

describe('isCredentialOperation', () => {
  it('is true for a mutation on a credential root field', () => {
    expect(isCredentialOperation(operationOf('mutation { meEdit(input: [{ key: "password", value: ["x"] }]) { id } }'))).toBe(true);
    expect(isCredentialOperation(operationOf('mutation { userEdit(id: "1") { fieldPatch(input: []) { id } } }'))).toBe(true);
    expect(isCredentialOperation(operationOf('mutation { changePassword(input: { transactionId: "1", otp: "1", newPassword: "x" }) }'))).toBe(true);
  });

  it('is false for other mutations and for queries', () => {
    expect(isCredentialOperation(operationOf('mutation { reportAdd(input: { name: "x" }) { id } }'))).toBe(false);
    expect(isCredentialOperation(operationOf('query { me { id } }'))).toBe(false);
    expect(isCredentialOperation(undefined)).toBe(false);
  });

  it('is true when a root selection is not a plain field', () => {
    expect(isCredentialOperation(operationOf('mutation { ...Change }'))).toBe(true);
  });
});

describe('isCredentialOperation, configuration mutations', () => {
  it('is true for the SMTP and authentication provider mutations, which carry secrets', () => {
    expect(isCredentialOperation(operationOf('mutation { smtpConfigurationEdit(input: { password: "x" }) { id } }'))).toBe(true);
    ['oidcProviderAdd', 'oidcProviderEdit', 'samlProviderAdd', 'samlProviderEdit', 'ldapProviderAdd', 'ldapProviderEdit'].forEach((root) => {
      expect(isCredentialOperation(operationOf(`mutation { ${root}(input: {}) { id } }`))).toBe(true);
    });
  });
});

describe('resolveRequestDocument', () => {
  it('uses the parsed document when there is one, and parses the query otherwise', () => {
    const document = parse('query { me { id } }');
    expect(resolveRequestDocument(document, 'mutation { meEdit { id } }')).toBe(document);
    expect(resolveRequestDocument(undefined, 'query { me { id } }')?.definitions).toHaveLength(1);
  });

  it('gives nothing for a request that cannot be parsed', () => {
    expect(resolveRequestDocument(undefined, 'mutation { meEdit(')).toBeUndefined();
    expect(resolveRequestDocument(undefined, undefined)).toBeUndefined();
  });
});

describe('mayCarryCredential', () => {
  it('looks at every operation of the request, not only the one that runs', () => {
    const document = parse('query Harmless { me { id } } mutation Change { meEdit(input: [{ key: "password", value: ["x"] }]) { id } }');
    expect(mayCarryCredential(document)).toBe(true);
  });

  it('is true for a request that cannot be classified', () => {
    expect(mayCarryCredential(undefined)).toBe(true);
  });

  it('is false for a request without any credential operation', () => {
    expect(mayCarryCredential(parse('query A { me { id } } mutation B { reportAdd(input: { name: "x" }) { id } }'))).toBe(false);
  });
});

describe('redactRequestVariables', () => {
  it('redacts a variable by the argument it feeds, whatever the caller named it', () => {
    const document = parse('mutation ($currentPass: String, $input: [EditInput]!) { meEdit(password: $currentPass, input: $input) { id } }');
    const variables = { currentPass: 'Current-1!', input: [{ key: 'password', value: ['Clear-text-1!'] }] };
    expect(redactRequestVariables(variables, document, KEYS, MARK)).toEqual({ currentPass: MARK, input: [{ key: 'password', value: MARK }] });
  });

  it('redacts a variable fed into a sensitive input field or into the value of a sensitive edit input', () => {
    const document = parse(`mutation ($a: String!, $b: [Any]) {
      changePassword(input: { transactionId: "1", otp: "1", newPassword: $a })
      userEdit(id: "1") { fieldPatch(input: [{ key: "password", value: $b }]) { id } }
    }`);
    expect(redactRequestVariables({ a: 'Clear-text-1!', b: ['Clear-text-2!'] }, document, KEYS, MARK)).toEqual({ a: MARK, b: MARK });
  });

  it('keeps the variables that feed nothing sensitive', () => {
    const document = parse('mutation ($id: ID!, $input: [EditInput]!) { userEdit(id: $id) { fieldPatch(input: $input) { id } } }');
    const variables = { id: 'user-1', input: [{ key: 'language', value: ['fr-fr'] }] };
    expect(redactRequestVariables(variables, document, KEYS, MARK)).toEqual(variables);
  });

  it('redacts every variable of a request that cannot be classified', () => {
    expect(redactRequestVariables({ anything: 'Clear-text-1!' }, undefined, KEYS, MARK)).toBe(MARK);
    expect(redactRequestVariables({}, undefined, KEYS, MARK)).toEqual({});
  });
});
