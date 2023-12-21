import { assert, describe, expect, it } from 'vitest';
import { csvMapperMockSimpleDifferentEntities } from '../../data/csv-mapper-mock-simple-different-entities';
import { validate } from '../../../src/modules/internal/csvMapper/csvMapper-utils';
import { testContext } from '../../utils/testQuery';
import type { BasicStoreEntityCsvMapper } from '../../../src/modules/internal/csvMapper/csvMapper-types';

describe('CSV Mapper', () => {
  it('validate a valid mapper', async () => {
    await validate(testContext, {
      ...csvMapperMockSimpleDifferentEntities as BasicStoreEntityCsvMapper,
      name: 'Valid Mapper'
    });
    assert(true);
  });
  it('invalidate a invalid mapper', async () => {
    const mapper = csvMapperMockSimpleDifferentEntities as BasicStoreEntityCsvMapper;
    await expect(() => validate(testContext, {
      ...mapper,
      name: 'Invalid Mapper',
      representations: [], // cannot have 0 representations
    })).rejects.toThrowError('CSV Mapper \'Invalid Mapper\' has no representation');

    await expect(() => validate(testContext, {
      ...mapper,
      name: 'Invalid Mapper',
      representations: [
        {
          ...mapper.representations[0],
          attributes: [], // missing attribute
        },
        mapper.representations[1],
      ]
    })).rejects.toThrowError(/missing values for required attribute/);

    // TODO: cover more validation tests
  });
});
