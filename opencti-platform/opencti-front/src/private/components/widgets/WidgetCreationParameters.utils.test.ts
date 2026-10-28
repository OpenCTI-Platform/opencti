import { describe, expect, it } from 'vitest';
import type { FilterGroup } from 'src/utils/filters/filtersHelpers-types';
import type { WidgetColumn, WidgetDataSelection, WidgetHost } from 'src/utils/widget/widget';
import { applyBreakdownCompatibility, getEntityTypeFromFilters, getWidgetColumnsEntityType, mergeAvailableAndSelectedColumns } from './WidgetCreationParameters.utils';

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

  it('returns relationship type with and global mode', () => {
    const filterGroup: FilterGroup = {
      mode: 'and',
      filters: [{ key: 'relationship_type', values: ['stix-sighting-relationship'], operator: 'eq', mode: 'or' }],
      filterGroups: [],
    };
    expect(getEntityTypeFromFilters(filterGroup)).toBe('stix-sighting-relationship');
  });

  it('returns relationship type with or global mode', () => {
    const filterGroup: FilterGroup = {
      mode: 'or',
      filters: [{ key: 'relationship_type', values: ['stix-sighting-relationship'], operator: 'eq', mode: 'or' }],
      filterGroups: [],
    };
    expect(getEntityTypeFromFilters(filterGroup)).toBe('stix-sighting-relationship');
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

  it('falls back to fintel entity type for entities perspective when no entity_type filter is present', () => {
    const host: WidgetHost = {
      kind: 'fintelTemplate',
      fintelWidgets: [],
      fintelEntityType: 'Vulnerability',
      fintelEditorValue: '',
    };
    expect(getWidgetColumnsEntityType(undefined, 'entities', host)).toBe('Vulnerability');
  });

  it('returns undefined for non-entities perspective when no entity_type filter is present', () => {
    const host: WidgetHost = {
      kind: 'fintelTemplate',
      fintelWidgets: [],
      fintelEntityType: 'Vulnerability',
      fintelEditorValue: '',
    };
    expect(getWidgetColumnsEntityType(undefined, 'relationships', host)).toBeUndefined();
  });

  it('keeps entity_type filter value over host fallback when present', () => {
    const filterGroup: FilterGroup = {
      mode: 'and',
      filters: [{ key: 'entity_type', values: ['Indicator'], operator: 'eq', mode: 'or' }],
      filterGroups: [],
    };
    const host: WidgetHost = {
      kind: 'fintelTemplate',
      fintelWidgets: [],
      fintelEntityType: 'Vulnerability',
      fintelEditorValue: '',
    };
    expect(getWidgetColumnsEntityType(filterGroup, 'entities', host)).toBe('Indicator');
  });

  it('does not fallback to host type when entity_type filter is ambiguous', () => {
    const filterGroup: FilterGroup = {
      mode: 'or',
      filters: [
        { key: 'entity_type', values: ['Vulnerability'], operator: 'eq', mode: 'or' },
        { key: 'name', values: ['CVE'], operator: 'search', mode: 'or' },
      ],
      filterGroups: [],
    };
    const host: WidgetHost = {
      kind: 'fintelTemplate',
      fintelWidgets: [],
      fintelEntityType: 'Malware',
      fintelEditorValue: '',
    };
    expect(getWidgetColumnsEntityType(filterGroup, 'entities', host)).toBeUndefined();
  });
});

describe('applyBreakdownCompatibility', () => {
  const workspace = { kind: 'workspace' } as const;
  const selection = { filters: { mode: 'and', filters: [], filterGroups: [] } } as unknown as WidgetDataSelection;
  const brokenDownLine = {
    type: 'line',
    perspective: 'entities' as const,
    dataSelection: [selection],
    parameters: { breakdownBy: 'entity_type' as const, breakdownLimit: 20, breakdownOrder: 'asc' as const, breakdownOther: true },
  };

  it('keeps the breakdown of every entities time series visualization', () => {
    ['line', 'area', 'vertical-bar', 'heatmap'].forEach((type) => {
      const { parameters } = applyBreakdownCompatibility({ ...brokenDownLine, type }, workspace);
      expect(parameters).toEqual(brokenDownLine.parameters);
    });
  });

  it('drops the breakdown and its settings for a non time series visualization', () => {
    const widget = applyBreakdownCompatibility({ ...brokenDownLine, type: 'donut' }, workspace);
    expect(widget.parameters).toEqual({ breakdownBy: null, breakdownLimit: null, breakdownOrder: null, breakdownOther: null });
  });

  it('keeps the breakdown of every relationships time series visualization', () => {
    const relationships = { ...brokenDownLine, perspective: 'relationships' as const, parameters: { ...brokenDownLine.parameters, breakdownBy: 'toTypes' } };
    ['line', 'area', 'vertical-bar', 'heatmap'].forEach((type) => {
      expect(applyBreakdownCompatibility({ ...relationships, type }, workspace).parameters).toEqual(relationships.parameters);
    });
    // A relationships widget left with an entities dataset cannot be broken down as relationships
    const entitiesDataset = { ...selection, perspective: 'entities' as const };
    expect(applyBreakdownCompatibility({ ...relationships, dataSelection: [entitiesDataset] }, workspace).parameters.breakdownBy).toBeNull();
  });

  it('drops the breakdown without perspective, with several datasets or another host', () => {
    expect(applyBreakdownCompatibility({ ...brokenDownLine, perspective: null }, workspace).parameters.breakdownBy).toBeNull();
    expect(applyBreakdownCompatibility({ ...brokenDownLine, dataSelection: [selection, selection] }, workspace).parameters.breakdownBy).toBeNull();
    const customView = { kind: 'custom-view' as const, customViewTargetEntityType: 'Report' };
    expect(applyBreakdownCompatibility(brokenDownLine, customView).parameters.breakdownBy).toBeNull();
    const severalDatasets = applyBreakdownCompatibility({ ...brokenDownLine, dataSelection: [selection, selection] }, workspace);
    expect(severalDatasets.parameters).toEqual({ breakdownBy: null, breakdownLimit: null, breakdownOrder: null, breakdownOther: null });
  });

  it('keeps the breakdown of every audits time series visualization', () => {
    ['line', 'area', 'vertical-bar', 'heatmap'].forEach((type) => {
      const { parameters } = applyBreakdownCompatibility({ ...brokenDownLine, perspective: 'audits' as const, type }, workspace);
      expect(parameters).toEqual(brokenDownLine.parameters);
    });
  });

  it('drops the breakdown of audits lines and areas counting distinct values', () => {
    const distinct = { ...brokenDownLine, perspective: 'audits' as const, dataSelection: [{ ...selection, unique: true }] };
    expect(applyBreakdownCompatibility(distinct, workspace).parameters).toEqual({ breakdownBy: null, breakdownLimit: null, breakdownOrder: null, breakdownOther: null });
    expect(applyBreakdownCompatibility({ ...distinct, type: 'vertical-bar' }, workspace).parameters).toEqual(brokenDownLine.parameters);
  });

  it('returns the widget untouched without breakdown', () => {
    const widget = { ...brokenDownLine, type: 'donut', parameters: { title: 'Donut' } };
    expect(applyBreakdownCompatibility(widget, workspace)).toBe(widget);
  });
});
