import { describe, it, expect } from 'vitest';
import type { WidgetDataSelection } from '../../utils/widget/widget';
import { removeIdAndIncorrectKeysFromFilterGroupObject, getAvailableFilterKeysForEntityTypes, buildFiltersForCustomView } from '../../utils/filters/filtersUtils';
import type { SchemaType } from '../../utils/hooks/useAuth';
import type { FilterGroup } from '../../utils/filters/filtersHelpers-types';
import { resolveDataSelection } from './dashboard-viz-utils';

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

  it('removes id and incorrect keys from FilterGroup entries when a Entities perspective widget', () => {
    const dataSelection: WidgetDataSelection[] = [{
      filters: makeFilterGroup(stixCoreObjectAvailableFilterKey, regardingOfNestedValueRandom),
      dynamicFrom: makeFilterGroup(stixCoreObjectAvailableFilterKey, regardingOfNestedValueRandom),
      dynamicTo: makeFilterGroup(stixCoreObjectAvailableFilterKey, regardingOfNestedValueRandom),
    }];
    const { resolvedDataSelection } = resolveDataSelection({
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

  it('removes id and incorrect keys from FilterGroup entries when a Relationships perspective widget', () => {
    const dataSelection: WidgetDataSelection[] = [{
      filters: makeFilterGroup(relationshipsAvailableFilterKey, randomObjectIdValue),
      dynamicFrom: makeFilterGroup(relationshipsAvailableFilterKey, randomObjectIdValue),
      dynamicTo: makeFilterGroup(relationshipsAvailableFilterKey, randomObjectIdValue),
    }];
    const { resolvedDataSelection } = resolveDataSelection({
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

  it('removes id and incorrect keys from FilterGroup entries when a Audits perspective widget', () => {
    const dataSelection: WidgetDataSelection[] = [{
      filters: makeFilterGroup(historyAvailableFilterKey, randomObjectIdValue),
      dynamicFrom: makeFilterGroup(historyAvailableFilterKey, randomObjectIdValue),
      dynamicTo: makeFilterGroup(historyAvailableFilterKey, randomObjectIdValue),
    }];
    const { resolvedDataSelection } = resolveDataSelection({
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

  it('does not return isMissingHostEntity if not hosted by a Custom View', () => {
    const dataSelection: WidgetDataSelection[] = [{
      filters: makeFilterGroup(stixCoreObjectAvailableFilterKey, regardingOfNestedValueRandom),
      dynamicFrom: makeFilterGroup(stixCoreObjectAvailableFilterKey, regardingOfNestedValueRandom),
      dynamicTo: makeFilterGroup(stixCoreObjectAvailableFilterKey, regardingOfNestedValueRandom),
    }];
    const { isMissingHostEntity } = resolveDataSelection({
      filterKeysSchema,
      dataSelection,
      perspective: 'entities',
      host: undefined,
    });
    expect(isMissingHostEntity).toBe(false);
  });

  describe('when hosted by a Custom View', () => {
    it('resolves SELF_ID filter values', () => {
      const dataSelection: WidgetDataSelection[] = [{
        filters: makeFilterGroup(stixCoreObjectAvailableFilterKey, regardingOfNestedValueSELF_ID),
        dynamicFrom: makeFilterGroup(stixCoreObjectAvailableFilterKey, regardingOfNestedValueSELF_ID),
        dynamicTo: makeFilterGroup(stixCoreObjectAvailableFilterKey, regardingOfNestedValueSELF_ID),
      }];
      const customViewTargetEntityId = 'ebe9a2a0-787d-4417-950e-39bfc8cc2381';
      const { resolvedDataSelection, isMissingHostEntity } = resolveDataSelection({
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

    it('returns isMissingHostEntity if SELF_ID is used in filters but there is not host entity injected', () => {
      const dataSelection: WidgetDataSelection[] = [{
        filters: makeFilterGroup(stixCoreObjectAvailableFilterKey, regardingOfNestedValueSELF_ID),
        dynamicFrom: makeFilterGroup(stixCoreObjectAvailableFilterKey, regardingOfNestedValueSELF_ID),
        dynamicTo: makeFilterGroup(stixCoreObjectAvailableFilterKey, regardingOfNestedValueSELF_ID),
      }];
      const { isMissingHostEntity } = resolveDataSelection({
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

    it('does not return isMissingHostEntity if there is no host entity injected but SELF_ID is not used', () => {
      const dataSelection: WidgetDataSelection[] = [{
        filters: makeFilterGroup(stixCoreObjectAvailableFilterKey, regardingOfNestedValueRandom),
        dynamicFrom: makeFilterGroup(stixCoreObjectAvailableFilterKey, regardingOfNestedValueRandom),
        dynamicTo: makeFilterGroup(stixCoreObjectAvailableFilterKey, regardingOfNestedValueRandom),
      }];
      const { isMissingHostEntity } = resolveDataSelection({
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
  });
});
