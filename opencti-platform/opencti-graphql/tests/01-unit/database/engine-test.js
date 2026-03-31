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

  it('should buildLocalMustFilter with internal_script should work', () => {
    const scriptFilter = {
      key: ['name'],
      values: [
        'doc.containsKey(\'name.keyword\')',
      ],
      operator: 'internal_script',
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
