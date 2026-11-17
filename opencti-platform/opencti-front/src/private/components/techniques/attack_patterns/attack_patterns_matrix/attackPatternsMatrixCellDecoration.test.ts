import { describe, expect, it } from 'vitest';
import { formatNameList } from './attackPatternsMatrixCellDecoration';

describe('formatNameList', () => {
  const t = (message: string, options?: { values?: Record<string, string | number> }) => (
    message.replace('{count}', String(options?.values?.count))
  );

  it('lists at most max names, then "and N more"', () => {
    const names = Array.from({ length: 12 }, (_, i) => `Name ${i + 1}`);
    const result = formatNameList(names, 10, t);
    expect(result).toBe('Name 1, Name 2, Name 3, Name 4, Name 5, Name 6, Name 7, Name 8, Name 9, Name 10 and 2 more');
  });

  it('lists every name when within max', () => {
    expect(formatNameList(['A', 'B'], 10, t)).toBe('A, B');
  });
});
