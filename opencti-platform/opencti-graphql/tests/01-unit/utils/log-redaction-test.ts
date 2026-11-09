import { describe, expect, it } from 'vitest';
import { parse, stripIgnoredCharacters } from 'graphql';
import { analyzeRequestSensitivity, redactRequestQuery, redactRequestVariables, redactSensitiveData } from '../../../src/utils/log-redaction';
import { REDACTED_INFORMATION } from '../../../src/database/utils';

const R = REDACTED_INFORMATION;

describe('log-redaction - redactSensitiveData', () => {
  it('should redact sensitive keys at any depth', () => {
    const data = { name: 'n', secret: 'v', nested: { list: [{ token: 'v', other: 'o' }] } };
    expect(redactSensitiveData(data)).toEqual({ name: 'n', secret: R, nested: { list: [{ token: R, other: 'o' }] } });
  });

  it('should redact the value of an edit input whose key is sensitive', () => {
    expect(redactSensitiveData({ key: 'password', value: ['v'] })).toEqual({ key: 'password', value: R });
    expect(redactSensitiveData([{ key: 'name', value: ['v'] }])).toEqual([{ key: 'name', value: ['v'] }]);
    expect(redactSensitiveData({ key: ['name', 'secret'], value: ['v'] })).toEqual({ key: ['name', 'secret'], value: R });
  });

  it('should keep empty values and non plain objects as they are', () => {
    const date = new Date();
    expect(redactSensitiveData({ password: null, token: '', date })).toEqual({ password: null, token: '', date });
  });

  it('should support objects without prototype', () => {
    const data = Object.assign(Object.create(null), { secret: 'v' });
    expect(redactSensitiveData(data)).toEqual({ secret: R });
  });

  it('should support cycles', () => {
    const data: Record<string, unknown> = { secret: 'v' };
    data.self = data;
    const list: unknown[] = [];
    list.push(list);
    const redacted = redactSensitiveData(data);
    expect(redacted.secret).toBe(R);
    expect(redacted.self).toBe(redacted);
    expect(redactSensitiveData(list)[0]).toBeInstanceOf(Array);
  });

  it('should return a copy, without modifying the data', () => {
    const data = { secret: 'v' };
    expect(redactSensitiveData(data)).not.toBe(data);
    expect(data.secret).toBe('v');
  });

  it('should keep deeply nested data complete, without overflowing the stack', () => {
    const depth = 100_000;
    let data: unknown = { secret: 'v', name: 'n' };
    for (let i = 0; i < depth; i += 1) data = i % 2 ? [data] : { a: data };
    let current: unknown = redactSensitiveData(data);
    for (let i = 0; i < depth; i += 1) current = Array.isArray(current) ? current[0] : (current as { a: unknown }).a;
    expect(current).toEqual({ secret: R, name: 'n' });
  });

  it('should redact the platform registration tokens', () => {
    expect(redactSensitiveData({ platform_token: 'v' })).toEqual({ platform_token: R });
    expect(redactSensitiveData({ key: 'xtm_hub_token', value: ['v'] })).toEqual({ key: 'xtm_hub_token', value: R });
  });

  it('should use the given keys', () => {
    expect(redactSensitiveData({ code: 'v', secret: 'v' }, new Set(['code']))).toEqual({ code: R, secret: 'v' });
  });
});

describe('log-redaction - analyzeRequestSensitivity', () => {
  it('should hide the query text and every variable value when the request has no document', () => {
    const sensitivity = analyzeRequestSensitivity(undefined);
    expect(sensitivity.hideQuery).toBe(true);
    expect(sensitivity.hideVariables).toBe(true);
    expect(redactRequestQuery('{ about { version } }', sensitivity)).toBe(R);
    expect(redactRequestVariables({ a: 'v', input: { name: 'n' } }, sensitivity)).toEqual({ a: R, input: R });
    expect(redactRequestVariables(undefined, sensitivity)).toEqual({});
  });

  it('should keep a regular request visible', () => {
    const query = 'query Q($first: Int, $filters: FilterGroup) { reports(first: $first, filters: $filters) { edges { node { id } } } }';
    const sensitivity = analyzeRequestSensitivity(parse(query));
    expect(sensitivity.hideQuery).toBe(false);
    expect(sensitivity.sensitiveVariables.size).toBe(0);
    expect(redactRequestQuery(query, sensitivity)).toBe(stripIgnoredCharacters(query));
    expect(redactRequestVariables({ first: 10 }, sensitivity)).toEqual({ first: 10 });
  });

  it('should hide the query text of an authentication mutation, through fragments', () => {
    expect(analyzeRequestSensitivity(parse('mutation M { token(input: $input) }')).hideQuery).toBe(true);
    expect(analyzeRequestSensitivity(parse('mutation M { ... on Mutation { logout } }')).hideQuery).toBe(false);
    const withFragments = 'mutation M { ...A ...A } fragment A on Mutation { ...B } fragment B on Mutation { otpLogin(input: $input) }';
    expect(analyzeRequestSensitivity(parse(withFragments)).hideQuery).toBe(true);
    expect(analyzeRequestSensitivity(parse('mutation M { ...Unknown }')).hideQuery).toBe(false);
  });

  it('should follow a long chain of fragments, without overflowing the stack', () => {
    const length = 20_000;
    let query = 'mutation M { ...F0 }';
    for (let i = 0; i < length; i += 1) query += ` fragment F${i} on Mutation { ${i === length - 1 ? 'otpLogin(input: $input)' : `...F${i + 1}`} }`;
    expect(analyzeRequestSensitivity(parse(query)).hideQuery).toBe(true);
  });

  it('should read the root fields of every operation type', () => {
    const shorthand = analyzeRequestSensitivity(parse('{ otpLogin(input: { code: "v" }) }'));
    expect(shorthand.hideQuery).toBe(true);
    const query = analyzeRequestSensitivity(parse('query Q($input: AnyInput) { verifyMfa(input: $input) }'));
    expect(redactRequestVariables({ input: { code: 'v' } }, query)).toEqual({ input: { code: R } });
  });

  it('should redact code only in authentication mutations', () => {
    const authentication = analyzeRequestSensitivity(parse('mutation M($input: VerifyMfaInput!) { verifyMfa(input: $input) }'));
    expect(redactRequestVariables({ input: { code: 'v', transactionId: 't' } }, authentication)).toEqual({ input: { code: R, transactionId: 't' } });
    const other = analyzeRequestSensitivity(parse('mutation M($input: AnyInput) { anyMutation(input: $input) { id } }'));
    expect(redactRequestVariables({ input: { code: 'v' } }, other)).toEqual({ input: { code: 'v' } });
  });

  it('should redact a variable feeding a sensitive argument, whatever its name', () => {
    const sensitivity = analyzeRequestSensitivity(parse('mutation M($a: String, $b: String) { anyMutation(secret: $a, name: $b) { id } }'));
    expect(sensitivity.hideQuery).toBe(false);
    expect(redactRequestVariables({ a: 'v', b: 'n' }, sensitivity)).toEqual({ a: R, b: 'n' });
  });

  it('should redact a variable feeding a sensitive input field or edit input value', () => {
    const query = 'mutation M($a: String, $b: [Any]) { m1(input: { secret: [$a] }) { id } m2(input: { key: "secret", value: $b }) { id } }';
    const sensitivity = analyzeRequestSensitivity(parse(query));
    expect(sensitivity.hideQuery).toBe(false);
    expect(redactRequestVariables({ a: 'v', b: ['v'] }, sensitivity)).toEqual({ a: R, b: R });
  });

  it('should handle the value of an edit input with a variable key as sensitive', () => {
    const query = 'mutation M($k: String!, $v: [Any]) { m(input: { key: $k, value: $v }) { id } }';
    expect(redactRequestVariables({ k: 'name', v: ['v'] }, analyzeRequestSensitivity(parse(query)))).toEqual({ k: 'name', v: R });
  });

  it('should keep the value of an edit input whose key is not sensitive', () => {
    const query = 'mutation M($v: [Any]) { m(input: { key: "name", value: $v }) { id } n(input: { key: "name" }) { id } }';
    const sensitivity = analyzeRequestSensitivity(parse(query));
    expect(sensitivity.hideQuery).toBe(false);
    expect(redactRequestVariables({ v: ['v'] }, sensitivity)).toEqual({ v: ['v'] });
  });

  it('should hide the query text holding a sensitive literal, but not a null one', () => {
    expect(analyzeRequestSensitivity(parse('mutation M { m(input: { secret: "v" }) { id } }')).hideQuery).toBe(true);
    expect(analyzeRequestSensitivity(parse('mutation M { m(input: { key: ["secret"], value: ["v"] }) { id } }')).hideQuery).toBe(true);
    expect(analyzeRequestSensitivity(parse('mutation M { m(input: { secret: null }) { id } }')).hideQuery).toBe(false);
  });

  it('should hide the query text when a sensitive variable has a default value', () => {
    expect(analyzeRequestSensitivity(parse('mutation M($a: String = "v") { m(input: { secret: $a }) { id } }')).hideQuery).toBe(true);
    expect(analyzeRequestSensitivity(parse('mutation M($a: String = null) { m(input: { secret: $a }) { id } }')).hideQuery).toBe(false);
    expect(analyzeRequestSensitivity(parse('query Q($first: Int = 10) { reports(first: $first) { edges { node { id } } } }')).hideQuery).toBe(false);
  });
});

describe('log-redaction - redactRequestVariables and redactRequestQuery', () => {
  it('should support missing variables and query', () => {
    const sensitivity = analyzeRequestSensitivity(parse('query Q { about { version } }'));
    expect(redactRequestVariables(undefined, sensitivity)).toEqual({});
    expect(redactRequestVariables(null, sensitivity)).toEqual({});
    expect(redactRequestQuery(undefined, sensitivity)).toBe('undefined');
  });

  it('should keep an empty sensitive variable', () => {
    const sensitivity = analyzeRequestSensitivity(parse('mutation M($a: String) { anyMutation(secret: $a) { id } }'));
    expect(redactRequestVariables({ a: null }, sensitivity)).toEqual({ a: null });
  });
});
