import { describe, expect, it } from 'vitest';
import { buildProvenanceWidgetVariables, PROVENANCE_ENTITY_TYPES, PROVENANCE_RELATIONSHIP_TYPES } from './provenanceWidgetUtils';
import {
  getCurrentCategory,
  getCurrentDataSelectionLimit,
  getCurrentIsRelationships,
  indexedVisualizationTypes,
  workspacesWidgetVisualizationTypes,
} from '../../../../utils/widget/widgetUtils';
import type { WidgetDataSelection } from '../../../../utils/widget/widget';
import type { FilterGroup } from '../../../../utils/filters/filtersHelpers-types';

const singleSourcedFilters: FilterGroup = {
  mode: 'and',
  filters: [{ key: 'single_sourced', values: ['true'], operator: 'eq', mode: 'or' }],
  filterGroups: [],
};

const selection = (filters: FilterGroup | null = null): WidgetDataSelection[] => [{ filters, date_attribute: 'created_at' } as WidgetDataSelection];

interface KeyedFilterGroup {
  readonly filters: ReadonlyArray<{ readonly key: string | ReadonlyArray<string> }>;
  readonly filterGroups: ReadonlyArray<KeyedFilterGroup>;
}

const flattenKeys = (group: KeyedFilterGroup | null | undefined): string[] => {
  if (!group) return [];
  return [
    ...group.filters.flatMap((filter) => (Array.isArray(filter.key) ? filter.key : [filter.key])),
    ...group.filterGroups.flatMap(flattenKeys),
  ];
};

describe('provenance widgets', () => {
  it('are registered in the widget catalog for entities and relationships', () => {
    const keys = workspacesWidgetVisualizationTypes.map((type) => type.key);
    expect(keys).toContain('provenance-freshness');
    expect(keys).toContain('provenance-single-sourced');
    expect(indexedVisualizationTypes['provenance-freshness'].isEntities).toBe(true);
    expect(getCurrentIsRelationships('provenance-freshness')).toBe(true);
    expect(getCurrentIsRelationships('provenance-single-sourced')).toBe(true);
    expect(getCurrentDataSelectionLimit('provenance-freshness')).toBe(1);
    expect(getCurrentDataSelectionLimit('provenance-single-sourced')).toBe(1);
  });

  it('let the single sourced share pick its number of types, not the freshness distribution', () => {
    expect(getCurrentCategory('provenance-single-sourced')).toBe('distribution');
    expect(getCurrentCategory('provenance-freshness')).toBe('provenance');
  });

  it('query the knowledge of the widget perspective', () => {
    expect(buildProvenanceWidgetVariables('entities', selection(), {}).types).toEqual(PROVENANCE_ENTITY_TYPES);
    expect(buildProvenanceWidgetVariables('relationships', selection(), {}).types).toEqual(PROVENANCE_RELATIONSHIP_TYPES);
  });

  it('keep the filters of the data selection', () => {
    const { filters } = buildProvenanceWidgetVariables('relationships', selection(singleSourcedFilters), {});
    expect(flattenKeys(filters)).toContain('single_sourced');
  });
});
