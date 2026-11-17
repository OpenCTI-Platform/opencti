import { describe, expect, it } from 'vitest';
import { applyCellDecoration } from './AttackPatternsMatrixColumns';

describe('applyCellDecoration', () => {
  it('lets the decoration fill and border win over the base styles', () => {
    const styles = { border: '1px solid red', backgroundColor: 'pink' };
    expect(applyCellDecoration(styles, { fill: 'F', border: 'B', textTone: 'dark', linkedEntities: [], accessibleName: 'x' }))
      .toEqual({ border: '1px solid red', borderColor: 'B', backgroundColor: 'F', labelColor: 'var(--black-1000)' });
  });
  it('keeps the base styles without a decoration', () => {
    expect(applyCellDecoration({ border: 'b', backgroundColor: 'c' })).toEqual({ border: 'b', borderColor: undefined, backgroundColor: 'c', labelColor: undefined });
  });
});
