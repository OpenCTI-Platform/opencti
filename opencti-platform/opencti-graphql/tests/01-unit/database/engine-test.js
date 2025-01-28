import { describe, expect, it } from 'vitest';
import { prepareElementForIndexing } from '../../../src/database/engine';

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
