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

  it('should handle null, undefined, and non-object inputs gracefully', () => {
    expect(cleanInputData(null)).toBeNull();
    expect(cleanInputData(undefined)).toBeUndefined();
    expect(cleanInputData('string')).toBe('string');
    expect(cleanInputData(123)).toBe(123);
  });
});
