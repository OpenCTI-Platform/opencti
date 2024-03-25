import { describe, expect, it } from 'vitest';
import { buildElasticSortingForAttributeCriteria } from '../../../src/utils/sorting';

describe('Sorting utilities', () => {
  let sorting;
  it('buildElasticSortingForAttributeCriteria properly construct elastic sorting options', () => {
    sorting = buildElasticSortingForAttributeCriteria('name', 'asc');
    expect(sorting).toEqual({
      'name.keyword': {
        missing: '_last',
        order: 'asc',
      },
    });

    sorting = buildElasticSortingForAttributeCriteria('confidence', 'desc');
    expect(sorting).toEqual({
      confidence: {
        missing: '_last',
        order: 'desc',
      },
    });

    sorting = buildElasticSortingForAttributeCriteria('created_at', 'desc');
    expect(sorting).toEqual({
      created_at: {
        missing: 0,
        order: 'desc',
      },
    });

    // complex object with sortBy
    sorting = buildElasticSortingForAttributeCriteria('group_confidence_level', 'asc');
    expect(sorting).toEqual({
      'group_confidence_level.max_confidence': {
        missing: '_last',
        order: 'asc',
      },
    });

    // fallback
    sorting = buildElasticSortingForAttributeCriteria('some_attribute', 'asc');
    expect(sorting).toEqual({
      'some_attribute.keyword': {
        missing: '_last',
        order: 'asc',
      },
    });
  });

  it('buildElasticSortingForAttributeCriteria throws on error', () => {
    sorting = () => buildElasticSortingForAttributeCriteria('context_data', 'asc');
    expect(sorting).toThrowError('Sorting on [context_data] is not supported: this criteria does not have a sortBy definition in schema');
  });
});
