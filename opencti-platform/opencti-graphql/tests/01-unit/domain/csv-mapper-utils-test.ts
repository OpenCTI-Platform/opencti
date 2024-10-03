import { assert, describe, expect, it } from 'vitest';
import { csvMapperMockSimpleDifferentEntities, csvMapperMockWithDynamicColumn } from '../../02-integration/05-parser/dynamic-simple-test/csv-mapper-mock-simple-different-entities';
import { validateCsvMapper } from '../../../src/modules/internal/csvMapper/csvMapper-utils';
import { ADMIN_USER, testContext } from '../../utils/testQuery';
import type { CsvMapperParsed } from '../../../src/modules/internal/csvMapper/csvMapper-types';

describe('CSV Mapper - without dynamic entity', () => {
  it('validate a valid mapper', async () => {
    await validateCsvMapper(testContext, ADMIN_USER, {
      ...csvMapperMockSimpleDifferentEntities as CsvMapperParsed,
      name: 'Valid Mapper'
    });
    assert(true);
  });
  it('invalidate a invalid mapper', async () => {
    const mapper = csvMapperMockSimpleDifferentEntities as CsvMapperParsed;
    await expect(() => validateCsvMapper(testContext, ADMIN_USER, {
      ...mapper,
      name: 'Invalid Mapper',
      representations: [], // cannot have 0 representations
    })).rejects.toThrowError('CSV Mapper has no representation');

    await expect(() => validateCsvMapper(testContext, ADMIN_USER, {
      ...mapper,
      name: 'Invalid Mapper',
      representations: [
        {
          ...mapper.representations[0],
          attributes: [], // missing attribute
        },
        mapper.representations[1],
      ]
    })).rejects.toThrowError('Missing values for required attribute');
  });
});

describe('CSV Mapper with dynamic entity - parsing of mapper configuration', () => {
  it('should a valid csv mapper with dynamic entity be valid', async () => {
    await validateCsvMapper(testContext, ADMIN_USER, {
      ...csvMapperMockWithDynamicColumn as CsvMapperParsed,
      name: 'Valid dynamic Mapper'
    });
    assert(true);
  });
});
