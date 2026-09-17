import { describe, expect, it } from 'vitest';
import { buildExportFilterGroup } from '../../components/dataGrid/DataTableFilters';
import { serializeSavedFilterGroup } from '../../components/saved_filters/SavedFilterCreateDialog';
import { buildSearchFiltersUrlParams } from '../../private/components/common/lists/Filters';
import { buildParamsFromHistory } from '../ListParameters';
import { FilterGroup } from '../filters/filtersHelpers-types';
import { expectNoFrontendIds } from './filtersTestHelpers';

const nestedFilters = (): FilterGroup => ({
  mode: 'and',
  filters: [{ id: 'root-id', key: 'entity_type', values: ['Report'], operator: 'eq', mode: 'or' }],
  filterGroups: [{
    mode: 'or',
    filters: [{ id: 'level-1-id', key: 'objectLabel', values: ['label-1'], operator: 'eq', mode: 'or' }],
    filterGroups: [{
      mode: 'and',
      filters: [{ id: 'level-2-id', key: 'createdBy', values: ['author-1'], operator: 'eq', mode: 'or' }],
      filterGroups: [],
    }],
  }],
});

describe('Nested filter groups serialization', () => {
  describe('buildExportFilterGroup (DataTableFilters)', () => {
    it('should strip the frontend ids at any depth', () => {
      const result = buildExportFilterGroup(nestedFilters(), nestedFilters());
      expectNoFrontendIds(result);
    });

    it('should keep the same structure for the flat case', () => {
      const contextFilters: FilterGroup = { mode: 'and', filters: [{ key: 'entity_type', values: ['Report'] }], filterGroups: [] };
      const filters: FilterGroup = { mode: 'and', filters: [{ key: 'createdBy', values: ['author-1'] }], filterGroups: [] };
      expect(buildExportFilterGroup(contextFilters, filters)).toEqual({
        mode: 'and',
        filters: [],
        filterGroups: [contextFilters, filters],
      });
    });

    it('should ignore the empty groups', () => {
      const empty: FilterGroup = { mode: 'and', filters: [], filterGroups: [] };
      const filters: FilterGroup = { mode: 'and', filters: [{ key: 'createdBy', values: ['author-1'] }], filterGroups: [] };
      expect(buildExportFilterGroup(empty, filters)).toEqual({
        mode: 'and',
        filters: [],
        filterGroups: [filters],
      });
    });
  });

  describe('serializeSavedFilterGroup (saved filters)', () => {
    it('should strip the frontend ids at any depth', () => {
      expectNoFrontendIds(JSON.parse(serializeSavedFilterGroup(nestedFilters()) as string));
    });

    it('should keep the frontend format (single string keys, empty filters kept)', () => {
      const filters: FilterGroup = {
        mode: 'and',
        filters: [{ id: 'an-id', key: 'createdBy', values: [], operator: 'eq', mode: 'or' }],
        filterGroups: [],
      };
      expect(serializeSavedFilterGroup(filters)).toEqual(JSON.stringify({
        mode: 'and',
        filters: [{ key: 'createdBy', values: [], operator: 'eq', mode: 'or' }],
        filterGroups: [],
      }));
    });

    it('should behave as JSON.stringify for undefined filters', () => {
      expect(serializeSavedFilterGroup(undefined)).toEqual(JSON.stringify(undefined));
    });
  });

  describe('buildSearchFiltersUrlParams (Filters)', () => {
    it('should strip the frontend ids at any depth', () => {
      const { filters } = buildSearchFiltersUrlParams(nestedFilters());
      expectNoFrontendIds(JSON.parse(filters as string));
    });

    it('should not change the flat case', () => {
      const filters: FilterGroup = { mode: 'and', filters: [{ key: 'createdBy', values: ['author-1'] }], filterGroups: [] };
      expect(buildSearchFiltersUrlParams(filters)).toEqual({ filters: JSON.stringify(filters) });
    });
  });

  describe('buildParamsFromHistory (ListParameters)', () => {
    it('should strip the frontend ids at any depth in filters and timeLineFilters', () => {
      const params = buildParamsFromHistory({ filters: nestedFilters(), timeLineFilters: nestedFilters() });
      const urlParams = new URLSearchParams(params);
      expectNoFrontendIds(JSON.parse(urlParams.get('filters') as string));
      expectNoFrontendIds(JSON.parse(urlParams.get('timeLineFilters') as string));
    });

    it('should not change the flat case', () => {
      const filters = { mode: 'and', filters: [{ key: 'createdBy', values: ['author-1'] }], filterGroups: [] };
      const urlParams = new URLSearchParams(buildParamsFromHistory({ filters }));
      expect(urlParams.get('filters')).toEqual(JSON.stringify(filters));
    });

    it('should leave a non filter group value untouched', () => {
      const urlParams = new URLSearchParams(buildParamsFromHistory({ filters: { foo: 'bar' } }));
      expect(urlParams.get('filters')).toEqual(JSON.stringify({ foo: 'bar' }));
    });
  });
});
