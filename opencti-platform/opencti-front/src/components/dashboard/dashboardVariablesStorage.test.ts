import { describe, expect, it } from 'vitest';
import { parseVariablesParam, serializeVariablesParam } from './dashboardVariablesStorage';

describe('variables URL param', () => {
  it('round-trips values containing commas, colons and spaces', () => {
    const values = { 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa': 'a,b:c d', 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb': 'x' };
    expect(parseVariablesParam(`?variables=${encodeURIComponent(serializeVariablesParam(values))}`)).toEqual(values);
  });
  it('returns an empty object for a malformed param', () => {
    expect(parseVariablesParam('?variables=%%%')).toEqual({});
    expect(parseVariablesParam('?variables=nocolon')).toEqual({});
  });
});
