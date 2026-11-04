import { describe, expect, it } from 'vitest';
import { mergeSx } from './sx';

describe('Utils: mergeSx', () => {
  it('keeps the parts in order, the last one winning', () => {
    expect(mergeSx({ flex: 1 }, { flex: 2 })).toEqual([{ flex: 1 }, { flex: 2 }]);
  });

  it('flattens the parts given as arrays', () => {
    const fn = () => ({ gap: 1 });
    expect(mergeSx({ flex: 1 }, [{ gap: 2 }, fn, false])).toEqual([{ flex: 1 }, { gap: 2 }, fn, false]);
  });

  it('drops the parts left undefined', () => {
    expect(mergeSx({ flex: 1 }, undefined)).toEqual([{ flex: 1 }]);
  });
});
