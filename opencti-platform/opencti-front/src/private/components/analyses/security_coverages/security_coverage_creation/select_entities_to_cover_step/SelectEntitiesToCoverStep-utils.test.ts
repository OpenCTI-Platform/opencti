import { describe, expect, it } from 'vitest';
import { FilterGroup } from 'src/utils/filters/filtersHelpers-types';
import { buildCoveredEntitiesFilters, buildEntitiesSelection } from './SelectEntitiesToCoverStep-utils';
import { HAS_COVERED_TARGETS_TYPES, StixCoreObjectNode } from '../SecurityCoverageCreation-types';

const containerEntity: StixCoreObjectNode = {
  id: 'report-1',
  entity_type: 'Report',
  parent_types: ['Basic-Object', 'Stix-Object', 'Stix-Core-Object', 'Stix-Domain-Object', 'Container'],
  created_at: '2026-01-01T00:00:00.000Z',
};

const nonContainerEntity: StixCoreObjectNode = {
  id: 'intrusion-set-1',
  entity_type: 'Intrusion-Set',
  parent_types: ['Basic-Object', 'Stix-Object', 'Stix-Core-Object', 'Stix-Domain-Object'],
  created_at: '2026-01-01T00:00:00.000Z',
};

const defaultFilters: FilterGroup = { mode: 'and', filters: [], filterGroups: [] };

const customFilters: FilterGroup = {
  mode: 'and',
  filters: [],
  filterGroups: [{
    mode: 'and',
    filters: [{ id: 'f1', key: 'objectLabel', values: ['label-1'], operator: 'eq', mode: 'or' }],
    filterGroups: [],
  }],
};

describe('SelectEntitiesToCoverStep-utils', () => {
  describe('buildCoveredEntitiesFilters', () => {
    it('should target the contained objects when the covered entity is a container', () => {
      const [containsFilter] = buildCoveredEntitiesFilters(containerEntity);
      expect(containsFilter).toEqual({
        key: 'objects',
        values: ['report-1'],
        operator: 'eq',
        mode: 'or',
      });
    });

    it('should target the targets and uses relationships when the covered entity is not a container', () => {
      const [regardingOfFilter] = buildCoveredEntitiesFilters(nonContainerEntity);
      expect(regardingOfFilter.key).toEqual('regardingOf');
      expect(regardingOfFilter.values).toEqual(expect.arrayContaining([
        { key: 'id', values: ['intrusion-set-1'] },
        { key: 'relationship_type', values: ['targets', 'uses'] },
      ]));
    });

    it('should force the relationship direction from the covered entity to the target', () => {
      const [regardingOfFilter] = buildCoveredEntitiesFilters(nonContainerEntity);
      expect(regardingOfFilter.values).toEqual(expect.arrayContaining([
        { key: 'direction_forced', values: [true] },
        { key: 'direction_reverse', values: [false] },
      ]));
    });

    it.each([
      ['container', containerEntity],
      ['non container', nonContainerEntity],
    ])('should restrict types to the has-covered compatible ones for a %s', (_label, entity) => {
      const filters = buildCoveredEntitiesFilters(entity);
      expect(filters).toContainEqual({
        key: 'entity_type',
        values: HAS_COVERED_TARGETS_TYPES,
        operator: 'eq',
        mode: 'or',
      });
    });
  });

  describe('buildEntitiesSelection', () => {
    const baseArgs = {
      selectAll: false,
      selectedIds: [],
      excludedIds: [],
      filters: defaultFilters,
    };

    it('should return null when nothing is selected', () => {
      expect(buildEntitiesSelection(baseArgs)).toBeNull();
    });

    it('should send the filters alone on an untouched select all', () => {
      const selection = buildEntitiesSelection({ ...baseArgs, selectAll: true });
      expect(selection).toEqual({ filters: defaultFilters });
    });

    it('should send the excluded ids when some rows are unchecked under select all', () => {
      const selection = buildEntitiesSelection({
        ...baseArgs,
        selectAll: true,
        excludedIds: ['id1'],
      });
      expect(selection).toEqual({ filters: defaultFilters, excluded_ids: ['id1'] });
    });

    it('should send the search term when select all is combined with a search', () => {
      const selection = buildEntitiesSelection({
        ...baseArgs,
        selectAll: true,
        excludedIds: ['id1'],
        searchTerm: 'toto',
      });
      expect(selection).toEqual({
        filters: defaultFilters,
        excluded_ids: ['id1'],
        search: 'toto',
      });
    });

    it('should forward the user filters on select all', () => {
      const selection = buildEntitiesSelection({
        ...baseArgs,
        selectAll: true,
        filters: customFilters,
      });
      expect(selection?.filters).toEqual(customFilters);
    });

    it('should send the selected ids alone on an explicit selection', () => {
      const selection = buildEntitiesSelection({
        ...baseArgs,
        selectedIds: ['id1', 'id2'],
        excludedIds: ['id3'],
        searchTerm: 'toto',
        filters: customFilters,
      });
      expect(selection).toEqual({ selected_ids: ['id1', 'id2'] });
    });

    it('should omit the search key when the search term is empty', () => {
      const selection = buildEntitiesSelection({
        ...baseArgs,
        selectAll: true,
        searchTerm: '',
      });
      expect(selection).not.toHaveProperty('search');
    });

    it('should omit the excluded ids key when nothing is unchecked', () => {
      const selection = buildEntitiesSelection({ ...baseArgs, selectAll: true });
      expect(selection).not.toHaveProperty('excluded_ids');
    });
  });
});
