import { describe, expect, it } from 'vitest';
import { countSerializedFilters, playbookNodeSummary } from './playbookNodeSummary';

const filterGroup = (filters: number, nested: number[] = []) => ({
  mode: 'and',
  filters: Array.from({ length: filters }, (_, i) => ({ key: [`k${i}`], values: ['v'], operator: 'eq', mode: 'or' })),
  filterGroups: nested.map((n) => ({ mode: 'and', filters: Array.from({ length: n }, () => ({ key: ['x'], values: [] })), filterGroups: [] })),
});

describe('countSerializedFilters', () => {
  it('counts the filters of a group and of its nested groups', () => {
    expect(countSerializedFilters(JSON.stringify(filterGroup(2, [1, 3])))).toBe(6);
  });

  it('answers 0 for nothing, an empty string or an unreadable value', () => {
    expect(countSerializedFilters(undefined)).toBe(0);
    expect(countSerializedFilters('')).toBe(0);
    expect(countSerializedFilters('{not json')).toBe(0);
    expect(countSerializedFilters(JSON.stringify(filterGroup(0)))).toBe(0);
  });
});

describe('playbookNodeSummary', () => {
  const schema = JSON.stringify({ type: 'object', required: ['filters'], properties: { filters: { type: 'string' } } });

  it('says a required setting is missing before anything else', () => {
    expect(playbookNodeSummary(undefined, schema)).toEqual({ kind: 'missing' });
    expect(playbookNodeSummary({ filters: '' }, schema)).toEqual({ kind: 'missing' });
    expect(playbookNodeSummary({ actions: [] }, JSON.stringify({ required: ['actions'] }))).toEqual({ kind: 'missing' });
  });

  it('summarises the filters and the actions a step is set with', () => {
    const filters = JSON.stringify(filterGroup(2));
    expect(playbookNodeSummary({ filters }, schema)).toEqual({ kind: 'filters', count: 2 });
    expect(playbookNodeSummary({ actions: [{}, {}, {}] }, null)).toEqual({ kind: 'actions', count: 3 });
    expect(playbookNodeSummary({ filters, actions: [{}] }, schema)).toEqual({ kind: 'filters_and_actions', filters: 2, actions: 1 });
  });

  it('shows nothing for a step without filters, actions or required settings', () => {
    expect(playbookNodeSummary({}, null)).toBeNull();
    expect(playbookNodeSummary(undefined, '{broken')).toBeNull();
    expect(playbookNodeSummary({ applyToElements: 'all-elements' }, JSON.stringify({ required: [] }))).toBeNull();
  });
});
