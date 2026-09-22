import { describe, expect, it } from 'vitest';
import type { FilterGroup } from 'src/utils/filters/filtersHelpers-types';
import type { WidgetColumn } from 'src/utils/widget/widget';
import { getEntityTypeFromFilters, mergeAvailableAndSelectedColumns } from './WidgetCreationParameters.utils';

describe('WidgetCreationParameters.utils', () => {
  it('returns undefined when filterGroup is undefined', () => {
    expect(getEntityTypeFromFilters(undefined)).toBeUndefined();
  });

  it('returns entity type for AND mode with a single entity_type filter', () => {
    const filterGroup: FilterGroup = {
      mode: 'and',
      filters: [{ key: 'entity_type', values: ['Indicator'], operator: 'eq', mode: 'or' }],
      filterGroups: [],
    };
    expect(getEntityTypeFromFilters(filterGroup)).toBe('Indicator');
  });

  it('returns entity type for OR mode only when entity_type is the only filter', () => {
    const filterGroup: FilterGroup = {
      mode: 'or',
      filters: [{ key: 'entity_type', values: ['Report'], operator: 'eq', mode: 'or' }],
      filterGroups: [],
    };
    expect(getEntityTypeFromFilters(filterGroup)).toBe('Report');
  });

  it('returns undefined for OR mode when another filter is present', () => {
    const filterGroup: FilterGroup = {
      mode: 'or',
      filters: [
        { key: 'entity_type', values: ['Report'], operator: 'eq', mode: 'or' },
        { key: 'name', values: ['foo'], operator: 'search', mode: 'or' },
      ],
      filterGroups: [],
    };
    expect(getEntityTypeFromFilters(filterGroup)).toBeUndefined();
  });

  it('keeps selected columns when they are missing from available columns', () => {
    const availableColumns: WidgetColumn[] = [
      { attribute: 'entity_type', label: 'Type' },
      { attribute: 'name', label: 'Name' },
    ];
    const selectedColumns: WidgetColumn[] = [
      { attribute: 'entity_type', label: 'Entity type' },
      { attribute: 'indicator_types', label: 'Indicator types' },
    ];

    const merged = mergeAvailableAndSelectedColumns(availableColumns, selectedColumns);
    const mergedAttributes = merged.map((c) => c.attribute);

    expect(mergedAttributes).toContain('indicator_types');
  });

  it('does not duplicate columns already present in available columns', () => {
    const availableColumns: WidgetColumn[] = [
      { attribute: 'entity_type', label: 'Type' },
      { attribute: 'name', label: 'Name' },
    ];
    const selectedColumns: WidgetColumn[] = [
      { attribute: 'entity_type', label: 'Entity type' },
      { attribute: 'name', label: 'Entity name' },
    ];

    const merged = mergeAvailableAndSelectedColumns(availableColumns, selectedColumns);
    expect(merged).toHaveLength(2);
  });
});
