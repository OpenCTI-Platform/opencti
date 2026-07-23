import { describe, it, expect, vi } from 'vitest';
import type { WidgetDataSelection } from '../../utils/widget/widget';
import { removeIdAndIncorrectKeysFromFilterGroupObject, getAvailableFilterKeysForEntityTypes, buildFiltersForCustomView } from '../../utils/filters/filtersUtils';
import type { SchemaType } from '../../utils/hooks/useAuth';
import type { FilterGroup } from '../../utils/filters/filtersHelpers-types';
import {
  resolveDataSelection,
  computeStartEndDates,
  computeWidgetFiltersForSelection,
  computeWidgetFiltersForMultiSelection,
  buildRelationshipMultiWidgetBaseQueryVariables,
  buildRelationshipSingleWidgetBaseQueryVariables,
} from './dashboardVizUtils';

vi.mock('src/relay/environment', () => ({
  fetchQuery: vi.fn(),
}));

import { fetchQuery } from 'src/relay/environment';

describe('resolvedDataSelection', () => {
  const stixCoreObjectAvailableFilterKey = 'regardingOf';
  const stixCoreObjectFilterKeysSchema = new Map([
    [stixCoreObjectAvailableFilterKey, {
      filterKey: stixCoreObjectAvailableFilterKey,
      label: 'In regards of',
      type: 'nested',
      multiple: true,
      subEntityTypes: ['IMSI'],
      elementsForFilterValuesSearch: [],
    }],
  ]);
  const relationshipsAvailableFilterKey = 'fromOrToId';
  const relationshipsFilterKeysSchema = new Map([
    [relationshipsAvailableFilterKey, {
      filterKey: relationshipsAvailableFilterKey,
      label: 'Related entity',
      type: 'id',
      multiple: false,
      subEntityTypes: ['delivers', 'targets'],
      elementsForFilterValuesSearch: ['Stix-Core-Object'],
    }],
  ]);
  const historyAvailableFilterKey = 'contextEntityId';
  const historyFilterKeysSchema = new Map([
    [historyAvailableFilterKey, {
      filterKey: historyAvailableFilterKey,
      label: 'Related entity',
      type: 'id',
      multiple: false,
      subEntityTypes: ['History'],
      elementsForFilterValuesSearch: ['Stix-Core-Object'],
    }],
  ]);
  const filterKeysSchema: SchemaType['filterKeysSchema'] = new Map([
    ['Stix-Core-Object', stixCoreObjectFilterKeysSchema],
    ['stix-core-relationship', relationshipsFilterKeysSchema],
    ['stix-sighting-relationship', relationshipsFilterKeysSchema],
    ['History', historyFilterKeysSchema],
  ]);

  const randomObjectIdValue = 'b36dc180-021e-44c3-9ff1-87309fb9ba30';

  const regardingOfNestedValueRandom = {
    key: 'id',
    values: [randomObjectIdValue],
  };

  const selfIdValue = 'SELF_ID';

  const regardingOfNestedValueSELF_ID = {
    key: 'id',
    values: [selfIdValue],
  };

  const makeFilterGroup = (availableKey: string, value: unknown): FilterGroup => ({
    mode: 'and',
    filters: [{
      key: availableKey,
      values: [value],
      operator: 'eq',
      mode: 'or',
      id: '0d135be3-2878-441a-a222-0499108e7f7f',
    }, {
      key: 'wrongKey', // Case: unavailable key
      values: [true],
    }, {
      key: availableKey, // Available key
      values: [], // Case: no values
    }, {
      id: 'shouldBeRemoved',
      key: 'dynamicRegardingOf',
      values: [{
        key: 'dynamic',
        values: [{
          id: 'shouldBeRemovedToo',
          mode: 'and',
          filters: [{
            key: 'entity_type',
            values: ['Malware'],
          }],
        }],
      }, {
        key: 'relationship_type',
        values: [{
          mode: 'and',
          filters: [{
            key: 'entity_type',
            values: ['Malware'],
          }],
        }],
      }, {
        key: 'incorrectKey', // Case: incorrect dynamicRegardingOf subkey
        values: [{
          mode: 'and',
          filters: [{
            key: 'entity_type',
            values: ['Malware'],
          }],
        }],
      }],
    }],
    filterGroups: [],
  });
  const secondary = ['Stix-Core-Object'];

  it('removes id and incorrect keys from FilterGroup entries when a Entities perspective widget', async () => {
    const dataSelection: WidgetDataSelection[] = [{
      filters: makeFilterGroup(stixCoreObjectAvailableFilterKey, regardingOfNestedValueRandom),
      dynamicFrom: makeFilterGroup(stixCoreObjectAvailableFilterKey, regardingOfNestedValueRandom),
      dynamicTo: makeFilterGroup(stixCoreObjectAvailableFilterKey, regardingOfNestedValueRandom),
    }];
    const { resolvedDataSelection } = await resolveDataSelection({
      filterKeysSchema,
      dataSelection,
      perspective: 'entities',
    });
    const main = ['Stix-Core-Object', 'DraftWorkspace'];
    expect(resolvedDataSelection[0].filters).toStrictEqual(
      removeIdAndIncorrectKeysFromFilterGroupObject(
        dataSelection[0].filters,
        getAvailableFilterKeysForEntityTypes(filterKeysSchema, main, true),
      ),
    );
    expect(resolvedDataSelection[0].dynamicFrom).toStrictEqual(
      removeIdAndIncorrectKeysFromFilterGroupObject(
        dataSelection[0].dynamicFrom,
        getAvailableFilterKeysForEntityTypes(filterKeysSchema, secondary, true),
      ),
    );
    expect(resolvedDataSelection[0].dynamicTo).toStrictEqual(
      removeIdAndIncorrectKeysFromFilterGroupObject(
        dataSelection[0].dynamicTo,
        getAvailableFilterKeysForEntityTypes(filterKeysSchema, secondary, true),
      ),
    );
  });

  it('removes id and incorrect keys from FilterGroup entries when a Relationships perspective widget', async () => {
    const dataSelection: WidgetDataSelection[] = [{
      filters: makeFilterGroup(relationshipsAvailableFilterKey, randomObjectIdValue),
      dynamicFrom: makeFilterGroup(relationshipsAvailableFilterKey, randomObjectIdValue),
      dynamicTo: makeFilterGroup(relationshipsAvailableFilterKey, randomObjectIdValue),
    }];
    const { resolvedDataSelection } = await resolveDataSelection({
      filterKeysSchema,
      dataSelection,
      perspective: 'relationships',
    });
    const main = ['stix-core-relationship', 'stix-sighting-relationship'];
    expect(resolvedDataSelection[0].filters).toStrictEqual(
      removeIdAndIncorrectKeysFromFilterGroupObject(
        dataSelection[0].filters,
        getAvailableFilterKeysForEntityTypes(filterKeysSchema, main, true),
      ),
    );
    expect(resolvedDataSelection[0].dynamicFrom).toStrictEqual(
      removeIdAndIncorrectKeysFromFilterGroupObject(
        dataSelection[0].dynamicFrom,
        getAvailableFilterKeysForEntityTypes(filterKeysSchema, secondary, true),
      ),
    );
    expect(resolvedDataSelection[0].dynamicTo).toStrictEqual(
      removeIdAndIncorrectKeysFromFilterGroupObject(
        dataSelection[0].dynamicTo,
        getAvailableFilterKeysForEntityTypes(filterKeysSchema, secondary, true),
      ),
    );
  });

  it('removes id and incorrect keys from FilterGroup entries when a Audits perspective widget', async () => {
    const dataSelection: WidgetDataSelection[] = [{
      filters: makeFilterGroup(historyAvailableFilterKey, randomObjectIdValue),
      dynamicFrom: makeFilterGroup(historyAvailableFilterKey, randomObjectIdValue),
      dynamicTo: makeFilterGroup(historyAvailableFilterKey, randomObjectIdValue),
    }];
    const { resolvedDataSelection } = await resolveDataSelection({
      filterKeysSchema,
      dataSelection,
      perspective: 'audits',
    });
    const main = ['History'];
    expect(resolvedDataSelection[0].filters).toStrictEqual(
      removeIdAndIncorrectKeysFromFilterGroupObject(
        dataSelection[0].filters,
        getAvailableFilterKeysForEntityTypes(filterKeysSchema, main, true),
      ),
    );
    expect(resolvedDataSelection[0].dynamicFrom).toStrictEqual(
      removeIdAndIncorrectKeysFromFilterGroupObject(
        dataSelection[0].dynamicFrom,
        getAvailableFilterKeysForEntityTypes(filterKeysSchema, secondary, true),
      ),
    );
    expect(resolvedDataSelection[0].dynamicTo).toStrictEqual(
      removeIdAndIncorrectKeysFromFilterGroupObject(
        dataSelection[0].dynamicTo,
        getAvailableFilterKeysForEntityTypes(filterKeysSchema, secondary, true),
      ),
    );
  });

  it('does not return isMissingHostEntity if not hosted by a Custom View', async () => {
    const dataSelection: WidgetDataSelection[] = [{
      filters: makeFilterGroup(stixCoreObjectAvailableFilterKey, regardingOfNestedValueRandom),
      dynamicFrom: makeFilterGroup(stixCoreObjectAvailableFilterKey, regardingOfNestedValueRandom),
      dynamicTo: makeFilterGroup(stixCoreObjectAvailableFilterKey, regardingOfNestedValueRandom),
    }];
    const { isMissingHostEntity } = await resolveDataSelection({
      filterKeysSchema,
      dataSelection,
      perspective: 'entities',
      host: undefined,
    });
    expect(isMissingHostEntity).toBe(false);
  });

  describe('when hosted by a Custom View', () => {
    it('resolves SELF_ID filter values', async () => {
      const dataSelection: WidgetDataSelection[] = [{
        filters: makeFilterGroup(stixCoreObjectAvailableFilterKey, regardingOfNestedValueSELF_ID),
        dynamicFrom: makeFilterGroup(stixCoreObjectAvailableFilterKey, regardingOfNestedValueSELF_ID),
        dynamicTo: makeFilterGroup(stixCoreObjectAvailableFilterKey, regardingOfNestedValueSELF_ID),
      }];
      const customViewTargetEntityId = 'ebe9a2a0-787d-4417-950e-39bfc8cc2381';
      const { resolvedDataSelection, isMissingHostEntity } = await resolveDataSelection({
        filterKeysSchema,
        dataSelection,
        perspective: 'entities',
        host: {
          kind: 'custom-view',
          customViewTargetEntityType: 'Campaign',
          customViewTargetEntityId,
        },
      });
      const main = ['Stix-Core-Object', 'DraftWorkspace'];
      expect(resolvedDataSelection[0].filters).toStrictEqual(
        removeIdAndIncorrectKeysFromFilterGroupObject(
          buildFiltersForCustomView(dataSelection[0].filters, customViewTargetEntityId),
          getAvailableFilterKeysForEntityTypes(filterKeysSchema, main, true),
        ),
      );
      expect(resolvedDataSelection[0].dynamicFrom).toStrictEqual(
        removeIdAndIncorrectKeysFromFilterGroupObject(
          buildFiltersForCustomView(dataSelection[0].dynamicFrom, customViewTargetEntityId),
          getAvailableFilterKeysForEntityTypes(filterKeysSchema, secondary, true),
        ),
      );
      expect(resolvedDataSelection[0].dynamicTo).toStrictEqual(
        removeIdAndIncorrectKeysFromFilterGroupObject(
          buildFiltersForCustomView(dataSelection[0].dynamicTo, customViewTargetEntityId),
          getAvailableFilterKeysForEntityTypes(filterKeysSchema, secondary, true),
        ),
      );
      expect(isMissingHostEntity).toBe(false);
    });

    it('returns isMissingHostEntity if SELF_ID is used in filters but there is not host entity injected', async () => {
      const dataSelection: WidgetDataSelection[] = [{
        filters: makeFilterGroup(stixCoreObjectAvailableFilterKey, regardingOfNestedValueSELF_ID),
        dynamicFrom: makeFilterGroup(stixCoreObjectAvailableFilterKey, regardingOfNestedValueSELF_ID),
        dynamicTo: makeFilterGroup(stixCoreObjectAvailableFilterKey, regardingOfNestedValueSELF_ID),
      }];
      const { isMissingHostEntity } = await resolveDataSelection({
        filterKeysSchema,
        dataSelection,
        perspective: 'entities',
        host: {
          kind: 'custom-view',
          customViewTargetEntityType: 'Campaign',
          customViewTargetEntityId: undefined,
        },
      });
      expect(isMissingHostEntity).toBe(true);
    });

    it('returns isMissingHostEntity when custom view requires host entity even if preview mode is false', async () => {
      const dataSelection: WidgetDataSelection[] = [{
        filters: makeFilterGroup(stixCoreObjectAvailableFilterKey, regardingOfNestedValueSELF_ID),
        dynamicFrom: makeFilterGroup(stixCoreObjectAvailableFilterKey, regardingOfNestedValueSELF_ID),
        dynamicTo: makeFilterGroup(stixCoreObjectAvailableFilterKey, regardingOfNestedValueSELF_ID),
      }];
      const { isMissingHostEntity } = await resolveDataSelection({
        filterKeysSchema,
        dataSelection,
        perspective: 'entities',
        host: {
          kind: 'custom-view',
          customViewTargetEntityType: 'Campaign',
          customViewTargetEntityId: undefined,
          previewMode: false,
        },
      });
      expect(isMissingHostEntity).toBe(true);
    });

    it('does not return isMissingHostEntity if there is no host entity injected but SELF_ID is not used', async () => {
      const dataSelection: WidgetDataSelection[] = [{
        filters: makeFilterGroup(stixCoreObjectAvailableFilterKey, regardingOfNestedValueRandom),
        dynamicFrom: makeFilterGroup(stixCoreObjectAvailableFilterKey, regardingOfNestedValueRandom),
        dynamicTo: makeFilterGroup(stixCoreObjectAvailableFilterKey, regardingOfNestedValueRandom),
      }];
      const { isMissingHostEntity } = await resolveDataSelection({
        filterKeysSchema,
        dataSelection,
        perspective: 'entities',
        host: {
          kind: 'custom-view',
          customViewTargetEntityType: 'Campaign',
          customViewTargetEntityId: undefined,
        },
      });
      expect(isMissingHostEntity).toBe(false);
    });

    it('returns isPreviewMode if SELF_ID is used in filters, there is a host entity injected and input host config indicates previewMode===true', async () => {
      const dataSelection: WidgetDataSelection[] = [{
        filters: makeFilterGroup(stixCoreObjectAvailableFilterKey, regardingOfNestedValueSELF_ID),
        dynamicFrom: makeFilterGroup(stixCoreObjectAvailableFilterKey, regardingOfNestedValueSELF_ID),
        dynamicTo: makeFilterGroup(stixCoreObjectAvailableFilterKey, regardingOfNestedValueSELF_ID),
      }];
      const { isPreviewMode } = await resolveDataSelection({
        filterKeysSchema,
        dataSelection,
        perspective: 'entities',
        host: {
          kind: 'custom-view',
          customViewTargetEntityType: 'Campaign',
          customViewTargetEntityId: 'some-entity-type',
          previewMode: true,
        },
      });
      expect(isPreviewMode).toBe(true);
    });

    it('does not return isPreviewMode if SELF_ID is used in filters and input host config indicates previewMode===true but no injected entity host', async () => {
      const dataSelection: WidgetDataSelection[] = [{
        filters: makeFilterGroup(stixCoreObjectAvailableFilterKey, regardingOfNestedValueSELF_ID),
        dynamicFrom: makeFilterGroup(stixCoreObjectAvailableFilterKey, regardingOfNestedValueSELF_ID),
        dynamicTo: makeFilterGroup(stixCoreObjectAvailableFilterKey, regardingOfNestedValueSELF_ID),
      }];
      const { isPreviewMode } = await resolveDataSelection({
        filterKeysSchema,
        dataSelection,
        perspective: 'entities',
        host: {
          kind: 'custom-view',
          customViewTargetEntityType: 'Campaign',
          customViewTargetEntityId: undefined,
        },
      });
      expect(isPreviewMode).toBe(false);
    });

    it('does not return isPreviewMode if input host config indicates previewMode===true and there is injected entity host but SELF_ID is not used in filters ', async () => {
      const dataSelection: WidgetDataSelection[] = [{
        filters: makeFilterGroup(stixCoreObjectAvailableFilterKey, regardingOfNestedValueRandom),
        dynamicFrom: makeFilterGroup(stixCoreObjectAvailableFilterKey, regardingOfNestedValueRandom),
        dynamicTo: makeFilterGroup(stixCoreObjectAvailableFilterKey, regardingOfNestedValueRandom),
      }];
      const { isPreviewMode } = await resolveDataSelection({
        filterKeysSchema,
        dataSelection,
        perspective: 'entities',
        host: {
          kind: 'custom-view',
          customViewTargetEntityType: 'Campaign',
          customViewTargetEntityId: 'some-entity-type',
          previewMode: true,
        },
      });
      expect(isPreviewMode).toBe(false);
    });
  });

  describe('when saved filters are used', () => {
    const savedFilterContent: FilterGroup = {
      mode: 'and',
      filters: [{ key: 'regardingOf', values: [{ key: 'id', values: ['saved-entity-id'] }], operator: 'eq', mode: 'or' }],
      filterGroups: [],
    };

    const mockFetchQuerySuccess = () => {
      (fetchQuery as ReturnType<typeof vi.fn>).mockReturnValue({
        toPromise: () => Promise.resolve({
          savedFilter: {
            id: 'saved-filter-id',
            name: 'My Saved Filter',
            filters: JSON.stringify(savedFilterContent),
            scope: 'Stix-Core-Object',
          },
        }),
      });
    };

    const mockFetchQueryNotFound = () => {
      (fetchQuery as ReturnType<typeof vi.fn>).mockReturnValue({
        toPromise: () => Promise.resolve({ savedFilter: null }),
      });
    };

    it('resolves filters from a saved filter when filters_id is provided', async () => {
      mockFetchQuerySuccess();
      const dataSelection: WidgetDataSelection[] = [{
        filters_id: 'saved-filter-id',
        dynamicFrom: makeFilterGroup(stixCoreObjectAvailableFilterKey, regardingOfNestedValueRandom),
        dynamicTo: makeFilterGroup(stixCoreObjectAvailableFilterKey, regardingOfNestedValueRandom),
      }];
      const { resolvedDataSelection, isMissingSavedFilters } = await resolveDataSelection({
        filterKeysSchema,
        dataSelection,
        perspective: 'entities',
      });
      const main = ['Stix-Core-Object', 'DraftWorkspace'];
      expect(resolvedDataSelection[0].filters).toStrictEqual(
        removeIdAndIncorrectKeysFromFilterGroupObject(
          savedFilterContent,
          getAvailableFilterKeysForEntityTypes(filterKeysSchema, main, true),
        ),
      );
      expect(isMissingSavedFilters).toBe(false);
    });

    it('resolves dynamicFrom from a saved filter when dynamicFrom_id is provided', async () => {
      mockFetchQuerySuccess();
      const dataSelection: WidgetDataSelection[] = [{
        filters: makeFilterGroup(stixCoreObjectAvailableFilterKey, regardingOfNestedValueRandom),
        dynamicFrom_id: 'saved-filter-id',
        dynamicTo: makeFilterGroup(stixCoreObjectAvailableFilterKey, regardingOfNestedValueRandom),
      }];
      const { resolvedDataSelection, isMissingSavedFilters } = await resolveDataSelection({
        filterKeysSchema,
        dataSelection,
        perspective: 'entities',
      });
      expect(resolvedDataSelection[0].dynamicFrom).toStrictEqual(
        removeIdAndIncorrectKeysFromFilterGroupObject(
          savedFilterContent,
          getAvailableFilterKeysForEntityTypes(filterKeysSchema, ['Stix-Core-Object'], true),
        ),
      );
      expect(isMissingSavedFilters).toBe(false);
    });

    it('resolves dynamicTo from a saved filter when dynamicTo_id is provided', async () => {
      mockFetchQuerySuccess();
      const dataSelection: WidgetDataSelection[] = [{
        filters: makeFilterGroup(stixCoreObjectAvailableFilterKey, regardingOfNestedValueRandom),
        dynamicFrom: makeFilterGroup(stixCoreObjectAvailableFilterKey, regardingOfNestedValueRandom),
        dynamicTo_id: 'saved-filter-id',
      }];
      const { resolvedDataSelection, isMissingSavedFilters } = await resolveDataSelection({
        filterKeysSchema,
        dataSelection,
        perspective: 'entities',
      });
      expect(resolvedDataSelection[0].dynamicTo).toStrictEqual(
        removeIdAndIncorrectKeysFromFilterGroupObject(
          savedFilterContent,
          getAvailableFilterKeysForEntityTypes(filterKeysSchema, ['Stix-Core-Object'], true),
        ),
      );
      expect(isMissingSavedFilters).toBe(false);
    });

    it('sets isMissingSavedFilters to true when saved filter is not found for filters_id', async () => {
      mockFetchQueryNotFound();
      const dataSelection: WidgetDataSelection[] = [{
        filters_id: 'non-existent-filter-id',
        dynamicFrom: makeFilterGroup(stixCoreObjectAvailableFilterKey, regardingOfNestedValueRandom),
        dynamicTo: makeFilterGroup(stixCoreObjectAvailableFilterKey, regardingOfNestedValueRandom),
      }];
      const { isMissingSavedFilters } = await resolveDataSelection({
        filterKeysSchema,
        dataSelection,
        perspective: 'entities',
      });
      expect(isMissingSavedFilters).toBe(true);
    });

    it('sets isMissingSavedFilters to true when saved filter is not found for dynamicFrom_id', async () => {
      mockFetchQueryNotFound();
      const dataSelection: WidgetDataSelection[] = [{
        filters: makeFilterGroup(stixCoreObjectAvailableFilterKey, regardingOfNestedValueRandom),
        dynamicFrom_id: 'non-existent-filter-id',
        dynamicTo: makeFilterGroup(stixCoreObjectAvailableFilterKey, regardingOfNestedValueRandom),
      }];
      const { isMissingSavedFilters } = await resolveDataSelection({
        filterKeysSchema,
        dataSelection,
        perspective: 'entities',
      });
      expect(isMissingSavedFilters).toBe(true);
    });

    it('does not set isMissingSavedFilters when no saved filter ids are provided', async () => {
      const dataSelection: WidgetDataSelection[] = [{
        filters: makeFilterGroup(stixCoreObjectAvailableFilterKey, regardingOfNestedValueRandom),
        dynamicFrom: makeFilterGroup(stixCoreObjectAvailableFilterKey, regardingOfNestedValueRandom),
        dynamicTo: makeFilterGroup(stixCoreObjectAvailableFilterKey, regardingOfNestedValueRandom),
      }];
      const { isMissingSavedFilters } = await resolveDataSelection({
        filterKeysSchema,
        dataSelection,
        perspective: 'entities',
      });
      expect(isMissingSavedFilters).toBe(false);
    });
  });
});

describe('computeStartEndDates', () => {
  it('returns undefined dates when no config is provided', () => {
    const { startDate, endDate } = computeStartEndDates();
    expect(startDate).toBeUndefined();
    expect(endDate).toBeUndefined();
  });

  it('returns undefined dates when config has no date fields', () => {
    const { startDate, endDate } = computeStartEndDates({});
    expect(startDate).toBeUndefined();
    expect(endDate).toBeUndefined();
  });

  it('returns absolute dates from config', () => {
    const config = { startDate: '2025-01-01T00:00:00Z', endDate: '2025-06-01T00:00:00Z' };
    const { startDate, endDate } = computeStartEndDates(config);
    expect(startDate).toBe('2025-01-01T00:00:00Z');
    expect(endDate).toBe('2025-06-01T00:00:00Z');
  });

  it('computes relative dates when relativeDate is set, ignoring absolute dates', () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date('2025-03-15T10:30:00.000Z'));
    try {
      const config = {
        relativeDate: 'days-7',
        startDate: '2025-01-01T00:00:00Z',
        endDate: '2025-06-01T00:00:00Z',
      };
      const { startDate, endDate } = computeStartEndDates(config);
      // relativeDate should override absolute dates
      expect(startDate).toBe('2025-03-08T10:30:00.000Z');
      expect(endDate).toBe('2025-03-15T10:30:00.000Z');
    } finally {
      vi.useRealTimers();
    }
  });

  it('falls back to default date range when fallbackToDefaultDates is true and no dates configured', () => {
    const { startDate, endDate } = computeStartEndDates({}, true);
    expect(startDate).toBeDefined();
    expect(endDate).toBeDefined();
  });

  it('uses config dates over fallback defaults when both are available', () => {
    const config = { startDate: '2025-01-01T00:00:00Z', endDate: '2025-06-01T00:00:00Z' };
    const { startDate, endDate } = computeStartEndDates(config, true);
    expect(startDate).toBe('2025-01-01T00:00:00Z');
    expect(endDate).toBe('2025-06-01T00:00:00Z');
  });
});

describe('computeWidgetFiltersForSelection', () => {
  it('returns default dateAttribute "created_at" when selection has no date_attribute', () => {
    const result = computeWidgetFiltersForSelection({}, {});
    expect(result.dateAttribute).toBe('created_at');
  });

  it('uses selection date_attribute when provided', () => {
    const selection: WidgetDataSelection = { date_attribute: 'updated_at' };
    const result = computeWidgetFiltersForSelection(selection, {});
    expect(result.dateAttribute).toBe('updated_at');
  });

  it('falls back to "created_at" when date_attribute is empty string', () => {
    const selection: WidgetDataSelection = { date_attribute: '' };
    const result = computeWidgetFiltersForSelection(selection, {});
    expect(result.dateAttribute).toBe('created_at');
  });

  it('passes config dates through to startDate/endDate', () => {
    const config = { startDate: '2025-01-01T00:00:00Z', endDate: '2025-06-01T00:00:00Z' };
    const result = computeWidgetFiltersForSelection({}, config);
    expect(result.startDate).toBe(config.startDate);
    expect(result.endDate).toBe(config.endDate);
  });

  it('returns undefined dates when no config is provided', () => {
    const result = computeWidgetFiltersForSelection({});
    expect(result.startDate).toBeUndefined();
    expect(result.endDate).toBeUndefined();
  });

  it('includes date filters in the result when config has dates', () => {
    const config = { startDate: '2025-01-01T00:00:00Z', endDate: '2025-06-01T00:00:00Z' };
    const result = computeWidgetFiltersForSelection({}, config);
    const allFilterKeys = result.filters?.filters.map((f) => f.key).flat();
    expect(allFilterKeys).toContain('created_at');
  });

  it('uses custom date_attribute in date filters', () => {
    const selectionFilters: FilterGroup = {
      mode: 'and',
      filters: [{
        key: 'entity_type',
        values: ['Malware'],
        operator: 'eq',
        mode: 'or',
      }],
      filterGroups: [],
    };
    const selection: WidgetDataSelection = { date_attribute: 'start_time', filters: selectionFilters };
    const config = { startDate: '2025-03-01T00:00:00Z' };
    const result = computeWidgetFiltersForSelection(selection, config);
    expect(result.filters).toStrictEqual({
      mode: 'and',
      filters: [
        {
          key: ['entity_type'],
          values: ['Malware'],
          operator: 'eq',
          mode: 'or',
        },
        {
          key: ['start_time'],
          values: ['2025-03-01T00:00:00Z'],
          operator: 'gt',
          mode: 'or',
        },
      ],
      filterGroups: [],
    });
  });

  it('passes selection filters through to the result', () => {
    const selectionFilters: FilterGroup = {
      mode: 'and',
      filters: [{
        key: 'entity_type',
        values: ['Malware'],
        operator: 'eq',
        mode: 'or',
      }],
      filterGroups: [],
    };
    const result = computeWidgetFiltersForSelection({ filters: selectionFilters }, {});
    expect(result.filters).toStrictEqual({
      mode: 'and',
      filters: [{ key: ['entity_type'], values: ['Malware'], operator: 'eq', mode: 'or' }],
      filterGroups: [],
    });
  });

  it('does not apply fallback dates by default', () => {
    const result = computeWidgetFiltersForSelection({}, {});
    expect(result.startDate).toBeUndefined();
    expect(result.endDate).toBeUndefined();
  });
});

describe('computeWidgetFiltersForMultiSelection', () => {
  it('returns timeSeriesParameters for each selection with correct filters and dates', () => {
    const selectionA: WidgetDataSelection = {
      date_attribute: 'created_at',
      filters: {
        mode: 'and',
        filters: [{
          key: 'entity_type',
          values: ['Malware'],
          operator: 'eq',
          mode: 'or',
        }],
        filterGroups: [],
      },
    };
    const selectionB: WidgetDataSelection = {
      date_attribute: 'updated_at',
      filters: {
        mode: 'and',
        filters: [{
          key: 'entity_type',
          values: ['Report'],
          operator: 'eq',
          mode: 'or',
        }],
        filterGroups: [],
      },
    };
    const config = { startDate: '2025-01-01T00:00:00Z', endDate: '2025-06-01T00:00:00Z' };

    const result = computeWidgetFiltersForMultiSelection([selectionA, selectionB], config, ['Stix-Core-Object']);

    expect(result.startDate).toBe(config.startDate);
    expect(result.endDate).toBe(config.endDate);
    expect(result.timeSeriesParameters).toHaveLength(2);

    // First selection: created_at + Malware filter + date filters
    expect(result.timeSeriesParameters[0].field).toBe('created_at');
    expect(result.timeSeriesParameters[0].types).toStrictEqual(['Stix-Core-Object']);
    const firstFilterKeys = result.timeSeriesParameters[0].filters?.filters.map((f) => f.key).flat();
    expect(firstFilterKeys).toContain('entity_type');
    expect(firstFilterKeys).toContain('created_at');

    // Second selection: updated_at + Report filter + date filters
    expect(result.timeSeriesParameters[1].field).toBe('updated_at');
    expect(result.timeSeriesParameters[1].types).toStrictEqual(['Stix-Core-Object']);
    const secondFilterKeys = result.timeSeriesParameters[1].filters?.filters.map((f) => f.key).flat();
    expect(secondFilterKeys).toContain('entity_type');
    expect(secondFilterKeys).toContain('updated_at');
  });
});

describe('buildRelationshipMultiWidgetBaseQueryVariables', () => {
  it('returns correct structure with operation, dates, interval, and timeSeriesParameters', () => {
    const selectionA: WidgetDataSelection = {
      date_attribute: 'created_at',
      filters: {
        mode: 'and',
        filters: [{
          key: 'entity_type',
          values: ['Malware'],
          operator: 'eq',
          mode: 'or',
        }],
        filterGroups: [],
      },
      dynamicFrom: {
        mode: 'and',
        filters: [{
          key: 'entity_type',
          values: ['Indicator'],
          operator: 'eq',
          mode: 'or',
        }],
        filterGroups: [],
      },
    };
    const selectionB: WidgetDataSelection = {
      date_attribute: 'updated_at',
      filters: {
        mode: 'and',
        filters: [{
          key: 'entity_type',
          values: ['Report'],
          operator: 'eq',
          mode: 'or',
        }],
        filterGroups: [],
      },
      dynamicTo: {
        mode: 'and',
        filters: [{
          key: 'entity_type',
          values: ['Campaign'],
          operator: 'eq',
          mode: 'or',
        }],
        filterGroups: [],
      },
    };
    const config = { startDate: '2025-01-01T00:00:00Z', endDate: '2025-06-01T00:00:00Z' };

    const result = buildRelationshipMultiWidgetBaseQueryVariables([selectionA, selectionB], config);

    expect(result.operation).toBe('count');
    expect(result.startDate).toBe(config.startDate);
    expect(result.endDate).toBe(config.endDate);
    expect(result.interval).toBe('day');
    expect(result.timeSeriesParameters).toHaveLength(2);

    // First selection
    expect(result.timeSeriesParameters[0]).toStrictEqual({
      field: 'created_at',
      filters: {
        mode: 'and',
        filters: [
          { key: ['entity_type'], values: ['Malware'], operator: 'eq', mode: 'or' },
          { key: ['created_at'], values: ['2025-01-01T00:00:00Z'], operator: 'gt', mode: 'or' },
          { key: ['created_at'], values: ['2025-06-01T00:00:00Z'], operator: 'lt', mode: 'or' },
        ],
        filterGroups: [],
      },
      dynamicFrom: {
        mode: 'and',
        filters: [{ key: ['entity_type'], values: ['Indicator'], operator: 'eq', mode: 'or' }],
        filterGroups: [],
      },
      dynamicTo: undefined,
    });

    // Second selection
    expect(result.timeSeriesParameters[1]).toStrictEqual({
      field: 'updated_at',
      filters: {
        mode: 'and',
        filters: [
          { key: ['entity_type'], values: ['Report'], operator: 'eq', mode: 'or' },
          { key: ['updated_at'], values: ['2025-01-01T00:00:00Z'], operator: 'gt', mode: 'or' },
          { key: ['updated_at'], values: ['2025-06-01T00:00:00Z'], operator: 'lt', mode: 'or' },
        ],
        filterGroups: [],
      },
      dynamicFrom: undefined,
      dynamicTo: {
        mode: 'and',
        filters: [{ key: ['entity_type'], values: ['Campaign'], operator: 'eq', mode: 'or' }],
        filterGroups: [],
      },
    });
  });

  it('uses custom interval from parameters', () => {
    const selection: WidgetDataSelection = { date_attribute: 'created_at' };
    const config = { startDate: '2025-01-01T00:00:00Z', endDate: '2025-06-01T00:00:00Z' };
    const parameters = { interval: 'month' };

    const result = buildRelationshipMultiWidgetBaseQueryVariables([selection], config, parameters);

    expect(result.interval).toBe('month');
  });
});

describe('buildRelationshipSingleWidgetBaseQueryVariables', () => {
  it('returns correct structure with dates, filters, dynamicFrom and dynamicTo', () => {
    const selection: WidgetDataSelection = {
      date_attribute: 'created_at',
      filters: {
        mode: 'and',
        filters: [{
          key: 'entity_type',
          values: ['Malware'],
          operator: 'eq',
          mode: 'or',
        }],
        filterGroups: [],
      },
      dynamicFrom: {
        mode: 'and',
        filters: [{
          key: 'entity_type',
          values: ['Indicator'],
          operator: 'eq',
          mode: 'or',
        }],
        filterGroups: [],
      },
      dynamicTo: {
        mode: 'and',
        filters: [{
          key: 'entity_type',
          values: ['Campaign'],
          operator: 'eq',
          mode: 'or',
        }],
        filterGroups: [],
      },
    };
    const config = { startDate: '2025-01-01T00:00:00Z', endDate: '2025-06-01T00:00:00Z' };

    const result = buildRelationshipSingleWidgetBaseQueryVariables(selection, config);

    expect(result).toStrictEqual({
      startDate: '2025-01-01T00:00:00Z',
      endDate: '2025-06-01T00:00:00Z',
      dateAttribute: 'created_at',
      filters: {
        mode: 'and',
        filters: [
          { key: ['entity_type'], values: ['Malware'], operator: 'eq', mode: 'or' },
          { key: ['created_at'], values: ['2025-01-01T00:00:00Z'], operator: 'gt', mode: 'or' },
          { key: ['created_at'], values: ['2025-06-01T00:00:00Z'], operator: 'lt', mode: 'or' },
        ],
        filterGroups: [],
      },
      dynamicFrom: {
        mode: 'and',
        filters: [{ key: ['entity_type'], values: ['Indicator'], operator: 'eq', mode: 'or' }],
        filterGroups: [],
      },
      dynamicTo: {
        mode: 'and',
        filters: [{ key: ['entity_type'], values: ['Campaign'], operator: 'eq', mode: 'or' }],
        filterGroups: [],
      },
    });
  });

  it('returns undefined dynamicFrom and dynamicTo when not provided', () => {
    const selection: WidgetDataSelection = { date_attribute: 'created_at' };
    const config = { startDate: '2025-01-01T00:00:00Z', endDate: '2025-06-01T00:00:00Z' };

    const result = buildRelationshipSingleWidgetBaseQueryVariables(selection, config);

    expect(result.dynamicFrom).toBeUndefined();
    expect(result.dynamicTo).toBeUndefined();
  });

  it('defaults dateAttribute to created_at when not specified', () => {
    const selection: WidgetDataSelection = {};
    const config = {};

    const result = buildRelationshipSingleWidgetBaseQueryVariables(selection, config);

    expect(result.dateAttribute).toBe('created_at');
  });
});
