import { describe, expect, it } from 'vitest';
import { dataTableToolbarLeftGroupStyle, dataTableToolbarRightGroupStyle, dataTableToolbarRowStyle } from './dataTableToolbarLayout';

describe('DataTable toolbar layout', () => {
  it('lets the row wrap and shrink instead of overflowing the page', () => {
    const row = dataTableToolbarRowStyle('8px');
    expect(row.flexWrap).toBe('wrap');
    expect(row.minWidth).toBe(0);
    expect(row.alignItems).toBe('center');
    expect(row.gap).toBe('8px');
  });

  it('lets the filters group shrink', () => {
    expect(dataTableToolbarLeftGroupStyle('8px').minWidth).toBe(0);
  });

  it('keeps the right-hand group whole and right-aligned when it wraps', () => {
    const right = dataTableToolbarRightGroupStyle('8px');
    expect(right.flexShrink).toBe(0);
    expect(right.marginLeft).toBe('auto');
  });
});
