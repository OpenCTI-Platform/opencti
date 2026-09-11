import { describe, expect, it } from 'vitest';
import { idsValuesRemap } from '../../../src/database/stix-2-1-converter';
import type { BasicStoreObject } from '../../../src/types/store';
import { convertToStixDate } from '../../../src/database/stix-converter-utils';
import { FROM_START, FROM_START_STR, UNTIL_END, UNTIL_END_STR } from '../../../src/utils/format';

describe('Stix converter utils: idsValuesRemap', () => {
  const standardId1 = 'identity--8c641a55-16b5-503d-9cc3-bf68ef0c40cc';
  const internalId1 = '22669f93-d08e-4348-a92f-7424f9bdc1c8';
  const standardId2 = 'report--bb628481-d13c-59cb-b4d1-a1e7c9c9a1fb';
  const internalId2 = '0532a2e5-9d30-4adc-ab8c-32c0b65bb541';
  const deletedStandardId = 'malware--21c45dbe-54ec-5bb7-b8cd-9f27cc518714';
  const fakeId = 'A fake Id';
  const resolvedMap = {
    [standardId1]: {
      internal_id: internalId1,
      standard_id: standardId1,
    },
    [internalId1]: {
      internal_id: internalId1,
      standard_id: standardId1,
    },
    [fakeId]: {
      internal_id: fakeId,
      standard_id: fakeId,
    },
    [standardId2]: {
      internal_id: internalId2,
      standard_id: standardId2,
      entity_type: 'Report',
      name: 'My report',
    },
    [internalId2]: {
      internal_id: internalId2,
      standard_id: standardId2,
      entity_type: 'Report',
      name: 'My report',
    },
  } as unknown as { [p: string]: BasicStoreObject };
  it('should replace internal ids by standard ids', async () => {
    const ids = ['100', internalId1];
    const remappedIds = idsValuesRemap(ids, resolvedMap, 'internal');
    expect(remappedIds.length).toEqual(2);
    expect(remappedIds[0]).toEqual('100');
    expect(remappedIds[1]).toEqual(standardId1);
  });
  it('should replace standard ids by internal ids', async () => {
    const ids = ['100', internalId1, standardId2];
    const remappedIds = idsValuesRemap(ids, resolvedMap, 'stix');
    expect(remappedIds.length).toEqual(3);
    expect(remappedIds[0]).toEqual('100');
    expect(remappedIds[1]).toEqual(internalId1);
    expect(remappedIds[2]).toEqual(internalId2);
  });
  it('should replace all the ids, and only the ids of correct format', async () => {
    const ids = ['100', internalId1, 'name', internalId2, standardId1, fakeId, deletedStandardId];
    const remappedIds = idsValuesRemap(ids, resolvedMap, 'internal');
    expect(remappedIds.length).toEqual(7);
    expect(remappedIds[0]).toEqual('100');
    expect(remappedIds[1]).toEqual(standardId1);
    expect(remappedIds[2]).toEqual('name');
    expect(remappedIds[3]).toEqual(standardId2);
    expect(remappedIds[4]).toEqual(standardId1);
    expect(remappedIds[5]).toEqual(fakeId);
    expect(remappedIds[6]).toEqual(deletedStandardId);
  });
  it('should remove not found ids if removeNotFoundStixIds = true', async () => {
    const ids = [internalId1, 'name', standardId1, fakeId, deletedStandardId];
    const remappedIds = idsValuesRemap(ids, resolvedMap, 'stix', true);
    expect(remappedIds.length).toEqual(4);
    expect(remappedIds[0]).toEqual(internalId1);
    expect(remappedIds[1]).toEqual('name');
    expect(remappedIds[2]).toEqual(internalId1);
    expect(remappedIds[3]).toEqual(fakeId);
  });
});

describe('Stix converter utils: convertToStixDate', () => {
  it('should return undefined when date is undefined', () => {
    expect(convertToStixDate(undefined)).toBeUndefined();
    expect(convertToStixDate(undefined, { allowEpoch: true })).toBeUndefined();
  });

  it('should format valid date strings and Date objects as ISO strings', () => {
    const dateStr = '2025-06-26T14:32:10.000Z';
    const dateObj = new Date(dateStr);
    expect(convertToStixDate(dateStr)).toBe(dateStr);
    expect(convertToStixDate(dateObj)).toBe(dateStr);
  });

  it('should convert FROM_START / epoch date to undefined by default', () => {
    expect(convertToStixDate(FROM_START_STR)).toBeUndefined();
    expect(convertToStixDate(new Date(FROM_START))).toBeUndefined();
    expect(convertToStixDate('1970-01-01T00:00:00.000Z')).toBeUndefined();
    expect(convertToStixDate(new Date(0))).toBeUndefined();
  });

  it('should convert UNTIL_END date to undefined by default and with allowEpoch', () => {
    expect(convertToStixDate(UNTIL_END_STR)).toBeUndefined();
    expect(convertToStixDate(new Date(UNTIL_END))).toBeUndefined();
    expect(convertToStixDate(UNTIL_END_STR, { allowEpoch: true })).toBeUndefined();
    expect(convertToStixDate(new Date(UNTIL_END), { allowEpoch: true })).toBeUndefined();
  });

  it('should preserve epoch date when allowEpoch is true', () => {
    expect(convertToStixDate(FROM_START_STR, { allowEpoch: true })).toBe(FROM_START_STR);
    expect(convertToStixDate(new Date(FROM_START), { allowEpoch: true })).toBe('1970-01-01T00:00:00.000Z');
    expect(convertToStixDate('1970-01-01T00:00:00.000Z', { allowEpoch: true })).toBe('1970-01-01T00:00:00.000Z');
    expect(convertToStixDate(new Date(0), { allowEpoch: true })).toBe('1970-01-01T00:00:00.000Z');
  });
});
