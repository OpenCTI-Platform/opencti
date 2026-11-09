import { describe, expect, it } from 'vitest';
import { cleanInputData } from '../../../src/manager/activityListener';
import { REDACTED_INFORMATION } from '../../../src/database/utils';

describe('Activity listener - cleanInputData', () => {
  it('should serialize filters object inside input to a JSON string', () => {
    const filterGroup = {
      mode: 'and',
      filters: [{ key: ['entity_type'], values: ['Stix-Core-Object'], operator: 'eq' }],
      filterGroups: [],
    };
    const contextData = {
      operation: 'StixCoreObjectsLinesQuery',
      input: {
        filters: filterGroup,
        first: 20,
      },
    };

    const cleaned = cleanInputData(contextData);
    expect(typeof cleaned.input.filters).toBe('string');
    expect(JSON.parse(cleaned.input.filters)).toEqual(filterGroup);
    expect(cleaned.input.first).toBe(20);
  });

  it('should serialize filters object at root of context_data to a JSON string', () => {
    const filterGroup = {
      mode: 'and',
      filters: [{ key: ['entity_type'], values: ['Malware'], operator: 'eq' }],
      filterGroups: [],
    };
    const contextData = {
      filters: filterGroup,
      message: 'test filter event',
    };

    const cleaned = cleanInputData(contextData);
    expect(typeof cleaned.filters).toBe('string');
    expect(JSON.parse(cleaned.filters)).toEqual(filterGroup);
    expect(cleaned.message).toBe('test filter event');
  });

  it('should serialize dynamicFrom and dynamicTo objects to JSON strings', () => {
    const dynamicFilter = {
      mode: 'and',
      filters: [{ key: ['relationship_type'], values: ['indicates'] }],
      filterGroups: [],
    };
    const contextData = {
      input: {
        dynamicFrom: dynamicFilter,
        dynamicTo: dynamicFilter,
      },
    };

    const cleaned = cleanInputData(contextData);
    expect(typeof cleaned.input.dynamicFrom).toBe('string');
    expect(typeof cleaned.input.dynamicTo).toBe('string');
    expect(JSON.parse(cleaned.input.dynamicFrom)).toEqual(dynamicFilter);
    expect(JSON.parse(cleaned.input.dynamicTo)).toEqual(dynamicFilter);
  });

  it('should leave filters untouched when it is already a string', () => {
    const filtersString = '{"mode":"and","filters":[]}';
    const contextData = {
      input: {
        filters: filtersString,
      },
    };

    const cleaned = cleanInputData(contextData);
    expect(cleaned.input.filters).toBe(filtersString);
  });

  it('should remove unsupported props like sort and _id from input', () => {
    const contextData = {
      input: {
        _id: 'internal-id',
        sort: 1722530083665,
        i_attributes: {},
        i_relation: {},
        valid_field: 'valid',
      },
    };

    const cleaned = cleanInputData(contextData);
    expect(cleaned.input._id).toBeUndefined();
    expect(cleaned.input.sort).toBeUndefined();
    expect(cleaned.input.i_attributes).toBeUndefined();
    expect(cleaned.input.i_relation).toBeUndefined();
    expect(cleaned.input.valid_field).toBe('valid');
  });

  it('should redact sensitive fields in input array', () => {
    const contextData = {
      input: [
        { key: 'password', value: ['supersecret'] },
        { key: 'name', value: ['normal'] },
      ],
    };

    const cleaned = cleanInputData(contextData);
    expect(cleaned.input[0]).toEqual({ password: REDACTED_INFORMATION });
    expect(cleaned.input[1]).toEqual({ key: 'name', value: ['normal'] });
  });

  it('should not mutate the original data', () => {
    const filterGroup = {
      mode: 'and',
      filters: [{ key: ['entity_type'], values: ['Malware'], operator: 'eq' }],
      filterGroups: [],
    };
    const args = { search: 'test', filters: filterGroup, sort: 1722530083665, password: 'supersecret' };
    const patches = [{ key: 'password', value: ['supersecret'] }];
    const contextData = { input: args, search: args.search, nested: { input: patches } };

    const cleaned = cleanInputData(contextData);
    expect(typeof cleaned.input.filters).toBe('string');
    expect(cleaned.input.sort).toBeUndefined();
    expect(cleaned.input.password).toBe(REDACTED_INFORMATION);
    expect(cleaned.nested.input[0]).toEqual({ password: REDACTED_INFORMATION });
    // Original data, like resolver args reused after the activity is published, must be left untouched
    expect(contextData.input).toBe(args);
    expect(args.filters).toBe(filterGroup);
    expect(filterGroup.filters).toEqual([{ key: ['entity_type'], values: ['Malware'], operator: 'eq' }]);
    expect(args.sort).toBe(1722530083665);
    expect(args.password).toBe('supersecret');
    expect(contextData.nested.input).toBe(patches);
    expect(patches[0]).toEqual({ key: 'password', value: ['supersecret'] });
  });

  it('should redact sensitive fields before serializing filters', () => {
    const contextData = {
      operation: 'UserAdd',
      input: {
        filters: { name: 'user', password: 'supersecret', nested: { token: 'my-token' } },
        dynamicFrom: { mode: 'and', filters: [], filterGroups: [], secret: 'my-secret' },
        dynamicTo: { mode: 'and', filters: [], filterGroups: [] },
      },
    };

    const cleaned = cleanInputData(contextData);
    expect(JSON.parse(cleaned.input.filters)).toEqual({ name: 'user', password: REDACTED_INFORMATION, nested: { token: REDACTED_INFORMATION } });
    expect(JSON.parse(cleaned.input.dynamicFrom)).toEqual({ mode: 'and', filters: [], filterGroups: [], secret: REDACTED_INFORMATION });
    expect(cleaned.input.filters).not.toContain('supersecret');
    expect(cleaned.input.filters).not.toContain('my-token');
    expect(cleaned.input.dynamicFrom).not.toContain('my-secret');
  });

  it('should serialize nested filter groups only once', () => {
    const filterGroup = {
      mode: 'and',
      filters: [{ key: ['entity_type'], values: ['Malware'], operator: 'eq' }],
      filterGroups: [{
        mode: 'or',
        filters: [{ key: ['name'], values: ['a', 'b'], operator: 'eq' }],
        filterGroups: [],
      }],
    };
    const cleaned = cleanInputData({ input: { filters: filterGroup } });
    const parsed = JSON.parse(cleaned.input.filters);
    expect(parsed).toEqual(filterGroup);
    expect(Array.isArray(parsed.filters)).toBe(true);
    expect(Array.isArray(parsed.filterGroups[0].filters)).toBe(true);
  });

  it('should drop filters that cannot be serialized', () => {
    const cleaned = cleanInputData({ input: { filters: { mode: 'and', count: BigInt(1) }, first: 20 } });
    expect(cleaned.input.filters).toBeUndefined();
    expect(cleaned.input.first).toBe(20);
  });

  it('should handle null, undefined, and non-object inputs gracefully', () => {
    expect(cleanInputData(null)).toBeNull();
    expect(cleanInputData(undefined)).toBeUndefined();
    expect(cleanInputData('string')).toBe('string');
    expect(cleanInputData(123)).toBe(123);
  });
});
