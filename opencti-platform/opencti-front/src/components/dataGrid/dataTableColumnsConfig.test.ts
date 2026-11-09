import { describe, expect, it } from 'vitest';
import { computeVisibleWidthRatio, isSameListColumnConfig, legacyListColumnConfig, parseListColumnsConfig, toListColumnConfig } from './dataTableColumnsConfig';
import type { DataTableColumns } from './dataTableTypes';

const columns = [
  { id: 'select', visible: true },
  { id: 'name', visible: true, percentWidth: 40, order: 0 },
  { id: 'objectLabel', visible: false, percentWidth: 30, order: 1 },
  { id: 'objectAssignee', visible: true, percentWidth: 10.123, order: 2 },
  { id: 'navigate', visible: true },
] as DataTableColumns;

describe('dataTableColumnsConfig', () => {
  it('keeps the data columns in their order, with their visibility and width', () => {
    expect(toListColumnConfig(columns)).toEqual([
      { id: 'name', visible: true, percentWidth: 40 },
      { id: 'objectLabel', visible: false, percentWidth: 30 },
      { id: 'objectAssignee', visible: true, percentWidth: 10.12 },
    ]);
  });

  it('enlarges the visible columns to fill the table when some are hidden', () => {
    // About 50% visible: each visible column is about twice as wide
    expect(computeVisibleWidthRatio(columns)).toBeCloseTo(100 / 50.123);
    // More than 100%: the table scrolls horizontally instead
    expect(computeVisibleWidthRatio(columns.map((c) => ({ ...c, visible: true, percentWidth: c.percentWidth && 40 })))).toBe(1);
  });

  it('reads a saved configuration and ignores an invalid one', () => {
    expect(parseListColumnsConfig('{"reports":[{"id":"name","visible":true,"percentWidth":25}]}'))
      .toEqual({ reports: [{ id: 'name', visible: true, percentWidth: 25 }] });
    expect(parseListColumnsConfig('not json')).toEqual({});
    expect(parseListColumnsConfig('[]')).toEqual({});
    expect(parseListColumnsConfig(null)).toEqual({});
  });

  it('keeps a browser configuration only while the default columns are the same', () => {
    const stored = {
      select: { percentWidth: 0 },
      name: { percentWidth: 30, visible: true, index: 1 },
      objectLabel: { percentWidth: 20, visible: false, index: 0 },
    };
    expect(legacyListColumnConfig(stored, ['name', 'objectLabel'])).toEqual([
      { id: 'objectLabel', visible: false, percentWidth: 20 },
      { id: 'name', visible: true, percentWidth: 30 },
    ]);
    expect(legacyListColumnConfig(stored, ['name', 'objectLabel', 'published'])).toBeUndefined();
  });

  it('compares configurations', () => {
    const config = toListColumnConfig(columns);
    expect(isSameListColumnConfig(config, toListColumnConfig(columns))).toBe(true);
    expect(isSameListColumnConfig(config, config.slice(1))).toBe(false);
  });
});
