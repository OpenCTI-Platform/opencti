import { describe, it, expect, vi } from 'vitest';
import type { WidgetDataSelection } from '../../utils/widget/widget';
import { removeIdAndIncorrectKeysFromFilterGroupObject, getAvailableFilterKeysForEntityTypes, buildFiltersForCustomView } from '../../utils/filters/filtersUtils';
import type { SchemaType } from '../../utils/hooks/useAuth';
import type { FilterGroup } from '../../utils/filters/filtersHelpers-types';
import { resolveDataSelection } from './dashboardVizUtils';

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
    const main = ['Stix-Core-Object'];
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
    expect(resolvedDataSelection[0].dynamicFrom).toStrictEqual(
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
    expect(resolvedDataSelection[0].dynamicFrom).toStrictEqual(
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
    expect(resolvedDataSelection[0].dynamicFrom).toStrictEqual(
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
      const main = ['Stix-Core-Object'];
      expect(resolvedDataSelection[0].filters).toStrictEqual(
        removeIdAndIncorrectKeysFromFilterGroupObject(
          buildFiltersForCustomView(dataSelection[0].filters, customViewTargetEntityId),
          getAvailableFilterKeysForEntityTypes(filterKeysSchema, main, true),
        ),
      );
      expect(resolvedDataSelection[0].dynamicFrom).toStrictEqual(
        removeIdAndIncorrectKeysFromFilterGroupObject(
          buildFiltersForCustomView(dataSelection[0].dynamicFrom, customViewTargetEntityId),
          getAvailableFilterKeysForEntityTypes(filterKeysSchema, main, true),
        ),
      );
      expect(resolvedDataSelection[0].dynamicTo).toStrictEqual(
        removeIdAndIncorrectKeysFromFilterGroupObject(
          buildFiltersForCustomView(dataSelection[0].dynamicTo, customViewTargetEntityId),
          getAvailableFilterKeysForEntityTypes(filterKeysSchema, main, true),
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
