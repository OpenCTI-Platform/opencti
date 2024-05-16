import { assert, describe, expect, it } from 'vitest';
import { csvMapperMockSimpleDifferentEntities } from '../../data/csv-mapper-mock-simple-different-entities';
import { validateCsvMapper } from '../../../src/modules/internal/csvMapper/csvMapper-utils';
import { ADMIN_USER, testContext } from '../../utils/testQuery';
import type { CsvMapperParsed } from '../../../src/modules/internal/csvMapper/csvMapper-types';

describe('CSV Mapper', () => {
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
    })).rejects.toThrowError('CSV Mapper \'Invalid Mapper\' has no representation');

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

    // TODO: cover more validation tests
  });
});
