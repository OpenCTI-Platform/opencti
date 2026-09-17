import { Filter, FilterGroup, FilterValue, handleFilterHelpers } from './filtersHelpers-types';
import {
  addFilterGroupUtil,
  handleAddFilterWithEmptyValueUtil,
  handleAddRepresentationFilterUtil,
  handleAddSingleValueFilterUtil,
  handleChangeFilterKeyUtil,
  handleChangeOperatorFiltersUtil,
  handleChangeRepresentationFilterUtil,
  handleRemoveFilterUtil,
  handleRemoveRepresentationFilterUtil,
  handleReplaceFilterValuesUtil,
  handleSwitchGlobalModeUtil,
  handleSwitchLocalModeUtil,
  removeFilterGroupUtil,
} from './filtersManageStateUtil';
import { extractAllFilters } from './filtersUtils';

/**
 * Chip the filter value popover must open on after a change. Every change resets it except the
 * ones that create a filter the user still has to fill in.
 */
export interface FilterAnchor {
  id?: string;
  key?: string;
}

/** Outcome of a change, or `null` when the current filters must be left untouched. */
export type FilterChangeResult = { filters: FilterGroup; anchor?: FilterAnchor } | null;

/** How a change behaves when the state holds no filters at all yet. */
export type WhenNoFilters = 'skip' | 'useEmptyGroup';

/**
 * What a filter state container must provide for `createFilterHelpers` to drive it. Each
 * container decides *where* the filters live (React state, local storage + url, …); the change
 * semantics are the factory's.
 */
export interface FilterStateAdapter {
  /**
   * Computes the next filters from the current ones and stores the result, together with the
   * popover anchor the change asks for.
   */
  applyChange: (compute: (filters: FilterGroup) => FilterChangeResult, whenNoFilters: WhenNoFilters) => void;
  getLatestAddFilterId: () => string | undefined;
  /** Reset semantics differ per container (defaults, search term, saved filters…). */
  clearAllFilters: () => void;
}

/**
 * The one implementation of the filter edition semantics, shared by every filter state
 * container (`useFiltersState`, `usePaginationLocalStorage`).
 *
 * Adding a filter operation means adding it here once: the containers only know how to read and
 * write their own storage.
 */
export const createFilterHelpers = (adapter: FilterStateAdapter): handleFilterHelpers => ({
  getLatestAddFilterId: () => adapter.getLatestAddFilterId(),
  handleClearAllFilters: () => adapter.clearAllFilters(),
  handleAddFilterWithEmptyValue: (filter: Filter, groupId?: string) => adapter.applyChange(
    (filters) => ({
      filters: handleAddFilterWithEmptyValueUtil({ filters, filter, groupId }),
      // when the filter is added in a non-root group, there is no chip in the root chip line to
      // anchor the popover on: reset the anchor.
      anchor: groupId ? undefined : { id: filter.id, key: filter.key },
    }),
    'useEmptyGroup',
  ),
  handleAddFilterGroup: (parentGroupId?: string) => adapter.applyChange(
    (filters) => ({ filters: addFilterGroupUtil({ filters, parentGroupId }) }),
    'useEmptyGroup',
  ),
  handleRemoveFilterGroup: (groupId: string) => adapter.applyChange(
    (filters) => ({ filters: removeFilterGroupUtil({ filters, groupId }) }),
    'useEmptyGroup',
  ),
  handleAddRepresentationFilter: (id: string, value: string | null) => adapter.applyChange(
    (filters) => {
      if (value !== null) {
        return { filters: handleAddRepresentationFilterUtil({ filters, id, value }) };
      }
      // clicking on 'no label' in an entities list: the filter switches to a nil operator
      // instead of receiving a value, and the popover stays on that filter.
      const correspondingFilter = extractAllFilters(filters).find((f) => id === f.id);
      if (!correspondingFilter || !['objectLabel'].includes(correspondingFilter.key)) return null;
      return {
        filters: handleChangeOperatorFiltersUtil({
          filters,
          id,
          operator: correspondingFilter.operator === 'not_eq' ? 'not_nil' : 'nil',
        }),
        anchor: { id, key: correspondingFilter.key },
      };
    },
    'skip',
  ),
  handleAddSingleValueFilter: (id: string, valueId?: string) => adapter.applyChange(
    (filters) => ({ filters: handleAddSingleValueFilterUtil({ filters, id, valueId }) }),
    'skip',
  ),
  handleReplaceFilterValues: (id: string, values: string[] | FilterGroup[]) => adapter.applyChange(
    (filters) => ({ filters: handleReplaceFilterValuesUtil({ filters, id, values }) }),
    'skip',
  ),
  handleChangeFilterKey: (id: string, newFilter: Filter) => adapter.applyChange(
    (filters) => ({ filters: handleChangeFilterKeyUtil({ filters, id, newFilter }) }),
    'skip',
  ),
  handleChangeOperatorFilters: (id: string, operator: string) => adapter.applyChange(
    (filters) => ({ filters: handleChangeOperatorFiltersUtil({ filters, id, operator }) }),
    'skip',
  ),
  handleRemoveFilterById: (id: string) => adapter.applyChange(
    (filters) => ({ filters: handleRemoveFilterUtil({ filters, id }) }),
    'skip',
  ),
  handleRemoveRepresentationFilter: (id: string, value: string | Filter | undefined | null) => adapter.applyChange(
    (filters) => ({ filters: handleRemoveRepresentationFilterUtil({ filters, id, value }) }),
    'skip',
  ),
  handleSwitchGlobalMode: (groupId?: string) => adapter.applyChange(
    (filters) => ({ filters: handleSwitchGlobalModeUtil({ filters, groupId }) }),
    'skip',
  ),
  handleSwitchLocalMode: (filter: Filter) => adapter.applyChange(
    (filters) => ({ filters: handleSwitchLocalModeUtil({ filters, filter }) }),
    'skip',
  ),
  handleChangeRepresentationFilter: (id: string, oldValue: FilterValue, newValue: FilterValue) => adapter.applyChange(
    (filters) => {
      if (oldValue && newValue) {
        return { filters: handleChangeRepresentationFilterUtil({ filters, id, oldValue, newValue }) };
      }
      if (oldValue) {
        return { filters: handleRemoveRepresentationFilterUtil({ filters, id, value: oldValue }) };
      }
      if (newValue) {
        return { filters: handleAddRepresentationFilterUtil({ filters, id, value: newValue }) };
      }
      return null;
    },
    'skip',
  ),
});

export default createFilterHelpers;
