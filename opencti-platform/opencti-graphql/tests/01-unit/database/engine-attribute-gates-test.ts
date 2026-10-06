import { describe, expect, it } from 'vitest';
import { attributeGateClauses, registerAttributeQueryGate } from '../../../src/database/engine-attribute-gates';
import type { FilterGroup } from '../../../src/generated/graphql';
import { SYSTEM_USER } from '../../../src/utils/access';
import { testContext } from '../../utils/testQuery';

const group = (keys: string[], filterGroups: FilterGroup[] = []) => ({
  mode: 'and',
  filters: keys.map((key) => ({ key: [key], values: ['value'] })),
  filterGroups,
}) as unknown as FilterGroup;

describe('Attribute query gates', () => {
  let calls = 0;
  registerAttributeQueryGate(['test_gated_level', 'test_gated_date'], async () => {
    calls += 1;
    return { match_none: {} };
  });

  it('applies the gate of an attribute read by a filter of a nested group, by a date histogram or by an aggregation, once', async () => {
    calls = 0;
    const filters = group(['name'], [group(['test_gated_level'])]);
    expect(await attributeGateClauses(testContext, SYSTEM_USER, { filters, attributes: ['test_gated_date'] })).toEqual([{ match_none: {} }]);
    expect(calls).toBe(1);
    expect(await attributeGateClauses(testContext, SYSTEM_USER, { filters: null, attributes: ['test_gated_level'] })).toEqual([{ match_none: {} }]);
  });

  it('adds nothing to a query that reads no gated attribute', async () => {
    calls = 0;
    expect(await attributeGateClauses(testContext, SYSTEM_USER, { filters: group(['name', 'created_at']), attributes: [null, undefined, 'created_at'] })).toEqual([]);
    expect(calls).toBe(0);
  });
});
