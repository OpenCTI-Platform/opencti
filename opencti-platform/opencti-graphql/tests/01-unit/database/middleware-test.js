import { describe, expect, it } from 'vitest';
import { hashMergeValidation, normalizeUpdateInputs } from '../../../src/database/middleware';
import {
  ENTITY_TYPE_CAMPAIGN,
  ENTITY_TYPE_INCIDENT
} from '../../../src/schema/stixDomainObject';
import '../../../src/modules/index';
import { FROM_START_STR, UNTIL_END_STR } from '../../../src/utils/format';
import { ENTITY_TYPE_LABEL } from '../../../src/schema/stixMetaObject';

describe('middleware hashes', () => {
  it('should hashes allowed to merge', () => {
    const instanceOne = { hashes: { MD5: 'md5', 'SHA-1': 'SHA' } };
    const instanceTwo = { hashes: { MD5: 'md5' } };
    hashMergeValidation([instanceOne, instanceTwo]);
  });
  it('should hashes have collisions', () => {
    const instanceOne = { hashes: { MD5: 'md5instanceOne' } };
    const instanceTwo = { hashes: { MD5: 'md5instanceTwo' } };
    const merge = () => hashMergeValidation([instanceOne, instanceTwo]);
    expect(merge).toThrow();
  });
  it('should hashes have complex collisions', () => {
    const instanceOne = { hashes: { MD5: 'md5', 'SHA-1': 'SHA' } };
    const instanceTwo = { hashes: { MD5: 'md5', 'SHA-1': 'SHA2' } };
    const merge = () => hashMergeValidation([instanceOne, instanceTwo]);
    expect(merge).toThrow();
  });
});

describe('middleware update normalizer', () => {
  it('should dates correctly setup', () => {
    const inputs = [{ key: 'first_seen', value: [] }, { key: 'last_seen', value: [] }];
    const normalizedInputs = normalizeUpdateInputs({ entity_type: ENTITY_TYPE_CAMPAIGN }, inputs);
    expect(normalizedInputs[0].key).toBe('first_seen');
    expect(normalizedInputs[0].value).toEqual([FROM_START_STR]);
    expect(normalizedInputs[1].key).toBe('last_seen');
    expect(normalizedInputs[1].value).toEqual([UNTIL_END_STR]);
  });
  it('should label name correctly lowered', () => {
    const inputs = [{ key: 'value', value: ['COUCOU'] }];
    const normalizedInputs = normalizeUpdateInputs({ entity_type: ENTITY_TYPE_LABEL }, inputs);
    expect(normalizedInputs[0].key).toBe('value');
    expect(normalizedInputs[0].value).toEqual(['coucou']);
  });
  it('should aliases object prevent name changing', () => {
    const inputs = [{ key: 'name', value: ['NAME_01'] }];
    const normalizedInputs = normalizeUpdateInputs({ entity_type: ENTITY_TYPE_INCIDENT, aliases: ['name_01'] }, inputs);
    expect(normalizedInputs.length).toBe(0);
  });
});
