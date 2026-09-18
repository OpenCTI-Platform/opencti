import { createContext, FunctionComponent, ReactNode, useContext, useMemo } from 'react';
import { handleFilterHelpers } from '../../../utils/filters/filtersHelpers-types';
import { FilterSearchContext } from '../../../utils/filters/filtersUtils';
import type { WidgetHost } from '../../../utils/widget/widget';
import { FilterRepresentative } from '../FiltersModel';

/**
 * Everything the filter editor needs that is the same for every node of its tree: the mutation
 * helpers, the filter keys the editor may offer, and the whole search configuration used to
 * resolve and search filter values.
 *
 * These nine values used to be threaded by hand from the two roots of the tree down to the
 * autocomplete, crossing components that only forwarded them (a textbook data clump). They are
 * tree-wide by nature, so they live in a context; anything that varies per node — `filter`,
 * `filterKey`, `subKey`, `disabled`, `label`, the input values, ... — stays an explicit prop.
 */
export interface FilterEditorContextValue {
  /** Absent only in read-only-ish callers of the chip popover, hence optional as before. */
  helpers?: handleFilterHelpers;
  /** Filter keys offered by the nested-group row key picker. Empty in the chip popover, which edits an existing filter and never offers a key. */
  availableFilterKeys: string[];
  entityTypes?: string[];
  filtersRepresentativesMap: Map<string, FilterRepresentative>;
  availableEntityTypes?: string[];
  availableRelationshipTypes?: string[];
  availableRelationFilterTypes?: Record<string, string[]>;
  searchContext?: FilterSearchContext;
  host?: WidgetHost;
}

const FilterEditorContext = createContext<FilterEditorContextValue | undefined>(undefined);

interface FilterEditorProviderProps extends FilterEditorContextValue {
  children: ReactNode;
}

/**
 * Provided at the two roots of the editor tree: the nested group panel host and the chip popover.
 */
export const FilterEditorProvider: FunctionComponent<FilterEditorProviderProps> = ({
  children,
  helpers,
  availableFilterKeys,
  entityTypes,
  filtersRepresentativesMap,
  availableEntityTypes,
  availableRelationshipTypes,
  availableRelationFilterTypes,
  searchContext,
  host,
}) => {
  // The roots re-render on every keystroke of the editor: without memoizing, a new object
  // identity would invalidate every consumer of the tree each time.
  const value = useMemo<FilterEditorContextValue>(() => ({
    helpers,
    availableFilterKeys,
    entityTypes,
    filtersRepresentativesMap,
    availableEntityTypes,
    availableRelationshipTypes,
    availableRelationFilterTypes,
    searchContext,
    host,
  }), [
    helpers,
    availableFilterKeys,
    entityTypes,
    filtersRepresentativesMap,
    availableEntityTypes,
    availableRelationshipTypes,
    availableRelationFilterTypes,
    searchContext,
    host,
  ]);

  return (
    <FilterEditorContext.Provider value={value}>
      {children}
    </FilterEditorContext.Provider>
  );
};

export const useFilterEditorContext = (): FilterEditorContextValue => {
  const context = useContext(FilterEditorContext);
  if (!context) {
    throw new Error('useFilterEditorContext must be used inside a <FilterEditorProvider>, rendered by FilterGroupPanelHost or FilterChipPopover');
  }
  return context;
};
