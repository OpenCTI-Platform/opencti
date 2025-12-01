import { describe, expect, it } from 'vitest';
import { buildElasticSortingForAttributeCriteria } from '../../../src/utils/sorting';
import { SYSTEM_USER } from '../../../src/utils/access';
import { testContext } from '../../utils/testQuery';

describe('Sorting utilities', () => {
  let sorting;
  it('buildElasticSortingForAttributeCriteria properly construct elastic sorting options', async () => {
    sorting = await buildElasticSortingForAttributeCriteria(testContext, SYSTEM_USER, 'name', 'asc');
    expect(sorting).toEqual({
      'name.keyword': {
        missing: '_last',
        order: 'asc',
      },
    });

    sorting = await buildElasticSortingForAttributeCriteria(testContext, SYSTEM_USER, 'confidence', 'desc');
    expect(sorting).toEqual({
      confidence: {
        missing: '_last',
        order: 'desc',
      },
    });

    sorting = await buildElasticSortingForAttributeCriteria(testContext, SYSTEM_USER, 'created_at', 'desc');
    expect(sorting).toEqual({
      created_at: {
        missing: 0,
        order: 'desc',
      },
    });

    // complex object with sortBy
    sorting = await buildElasticSortingForAttributeCriteria(testContext, SYSTEM_USER, 'group_confidence_level', 'asc');
    expect(sorting).toEqual({
      'group_confidence_level.max_confidence': {
        missing: '_last',
        order: 'asc',
      },
    });

    // fallback
    sorting = await buildElasticSortingForAttributeCriteria(testContext, SYSTEM_USER, 'some_attribute', 'asc');
    expect(sorting).toEqual({
      'some_attribute.keyword': {
        missing: '_last',
        order: 'asc',
      },
    });
  });

  it('buildElasticSortingForAttributeCriteria throws on error if sorting criteria not in schema', async () => {
    sorting = async () => buildElasticSortingForAttributeCriteria(testContext, SYSTEM_USER, 'context_data', 'asc');
    await expect(sorting).rejects.toThrowError('Sorting on [context_data] is not supported: this criteria does not have a sortBy definition in schema');
  });
});
