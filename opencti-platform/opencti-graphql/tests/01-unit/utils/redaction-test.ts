import { describe, expect, it } from 'vitest';
import { parse, type OperationDefinitionNode } from 'graphql';
import { BASELINE_REDACTED_INPUTS, buildRedactedInputs, isCredentialOperation, redactSensitiveData } from '../../../src/utils/redaction';

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
