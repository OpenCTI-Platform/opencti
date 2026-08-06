import { describe, expect, it, vi } from 'vitest';
import { buildLocalMustFilter, prepareElementForIndexing } from '../../../src/database/engine';
import * as engineConfig from '../../../src/database/engine-config';

describe('prepareElementForIndexing testing', () => {
  it('should base trim applied', async () => {
    const element = await prepareElementForIndexing({ name: '  test' });
    expect(element.name).toBe('test');
  });
  it('should inner trim applied', async () => {
    const element = await prepareElementForIndexing({ num: 10, data: { test: '  spacing   ' } });
    expect(element.num).toBe(10);
    expect(element.data.test).toBe('spacing');
  });
  it('should array trim applied', async () => {
    const element = await prepareElementForIndexing({ test: [20, '  trim01  ', '  trim 02    '] });
    expect(element.test).toEqual([20, 'trim01', 'trim 02']);
  });
  it('should inner array trim applied', async () => {
    const element = await prepareElementForIndexing({ test: { values: [20, '  trim01  ', '  trim 02    '] } });
    expect(element.test.values).toEqual([20, 'trim01', 'trim 02']);
  });
  it('should do nothing with date value', async () => {
    const now = new Date();
    const element = await prepareElementForIndexing({ date: now });
    expect(element.date).toEqual(now);
  });
});

describe('buildLocalMustFilter testing', () => {
  it('should buildLocalMustFilter with script be refused by default', () => {
    const scriptFilter = {
      key: ['name'],
      values: [
        'doc.containsKey(\'name.keyword\')',
      ],
      operator: 'script',
    };

    expect(() => buildLocalMustFilter(scriptFilter)).toThrow(/Filter script is not allowed/);
  });

  it('unknown filter operators must be rejected by buildLocalMustFilter', () => {
    const scriptFilter = {
      key: ['name'],
      values: [
        'doc.containsKey(\'name.keyword\')',
      ],
      operator: 'internal_script',
    };

    expect(() => buildLocalMustFilter(scriptFilter)).toThrow(/Not supported filter operator/);
  });

  it('buildLocalMustFilter with script should work when enabled', () => {
    vi.spyOn(engineConfig, 'isEsScriptFilterEnabled').mockResolvedValue(true);
    const scriptFilter = {
      key: ['name'],
      values: [
        'doc.containsKey(\'name.keyword\')',
      ],
      operator: 'script',
    };

    const result = buildLocalMustFilter(scriptFilter);

    expect(result).toStrictEqual({
      bool: {
        minimum_should_match: 1,
        should: [
          {
            script: {
              script: "doc.containsKey('name.keyword')",
            },
          },
        ],
      },
    });
  });

  const sampleKeys = [
    "name']; ctx._source.value = true; //",
    "name.foo']; ctx._source.value = true; //",
    "name'].isEmpty(); return true; //",
    'name" + ctx._source.value + "',
  ];

  it('should buildLocalMustFilter with only_eq_to build the same script source for any key value', () => {
    const sources = sampleKeys.map((key) => {
      const result = buildLocalMustFilter({ key: [key], values: ['a'], operator: 'only_eq_to' });
      return result.bool.should[0].script.script;
    });

    sources.forEach((scriptClause) => {
      expect(scriptClause.source).toBe(sources[0].source);
      sampleKeys.forEach((key) => expect(scriptClause.source).not.toContain(key));
    });
    sources.forEach((scriptClause, i) => {
      expect(scriptClause.params.field).toBe(`${sampleKeys[i]}.keyword`);
    });
  });

  it('should buildLocalMustFilter with not_only_eq_to build the same script source for any key value', () => {
    const sources = sampleKeys.map((key) => {
      const result = buildLocalMustFilter({ key: [key], values: ['a'], operator: 'not_only_eq_to' });
      return result.bool.should[0].bool.must_not[0].script.script;
    });

    sources.forEach((scriptClause) => {
      expect(scriptClause.source).toBe(sources[0].source);
      sampleKeys.forEach((key) => expect(scriptClause.source).not.toContain(key));
    });
    sources.forEach((scriptClause, i) => {
      expect(scriptClause.params.field).toBe(`${sampleKeys[i]}.keyword`);
    });
  });

  it('only_eq_to script params must be correctly built when the search-engine script filter is disabled', () => {
    vi.spyOn(engineConfig, 'isEsScriptFilterEnabled').mockResolvedValue(false);
    const filter = {
      key: ['name'],
      values: ['a', 'b'],
      operator: 'only_eq_to',
      mode: 'or',
    };

    expect(() => buildLocalMustFilter(filter)).not.toThrow();
    const result = buildLocalMustFilter(filter);
    const scriptClause = result.bool.should[0].script.script;
    expect(scriptClause.params.field).toBe('name.keyword');
    expect(scriptClause.params.values).toStrictEqual(['a', 'b']);
    expect(scriptClause.params.mode).toBe('or');
  });

  it('should buildLocalMustFilter with wildcard build a well formed query_string clause', () => {
    const value = '*" OR internal_id:* OR field:"';
    const filter = {
      key: ['name'],
      values: [value],
      operator: 'wildcard',
    };

    const result = buildLocalMustFilter(filter);
    const query = result.bool.should[0].query_string.query;

    expect(query).not.toBe(`"${value}"`);
  });

  it('should buildLocalMustFilter with not_wildcard build a well formed query_string clause', () => {
    const value = '*" OR secret_field:*';
    const filter = {
      key: ['name'],
      values: [value],
      operator: 'not_wildcard',
    };

    const result = buildLocalMustFilter(filter);
    const query = result.bool.should[0].bool.must_not[0].query_string.query;

    expect(query).not.toBe(`"${value}"`);
  });

  it('buildLocalMustFilter with script should work when enabled', () => {
    vi.spyOn(engineConfig, 'isEsScriptFilterEnabled').mockResolvedValue(true);
    const scriptFilter = {
      key: ['name'],
      values: [
        'doc.containsKey(\'name.keyword\')',
      ],
      operator: 'script',
    };

    const result = buildLocalMustFilter(scriptFilter);
    expect(result).toStrictEqual({
      bool: {
        minimum_should_match: 1,
        should: [
          {
            script: {
              script: "doc.containsKey('name.keyword')",
            },
          },
        ],
      },
    });
  });
});
