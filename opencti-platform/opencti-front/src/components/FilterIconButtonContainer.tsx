import Box from '@mui/material/Box';
import { ChipOwnProps } from '@mui/material/Chip/Chip';
import React, { FunctionComponent } from 'react';
import { PreloadedQuery } from 'react-relay';
import { FilterSearchContext, FiltersRestrictions } from '../utils/filters/filtersUtils';
import { FilterValuesContentQuery } from './__generated__/FilterValuesContentQuery.graphql';
import { DataColumns } from './list_lines';

import type { WidgetHost } from '../utils/widget/widget';
import { Filter, FilterGroup, handleFilterHelpers } from '../utils/filters/filtersHelpers-types';
import { FilterChipPopover, FilterChipsParameter } from './filters/FilterChipPopover';
import FilterChipLine from './filters/FilterChipLine';
import FilterGroupPanelHost from './filters/group/FilterGroupPanelHost';
import useFilterPopoverAnchor from './filters/useFilterPopoverAnchor';
import useFilterRepresentatives from './filters/useFilterRepresentatives';

export type FilterIconButtonVariant
  = undefined // default variant (variant is undefined), for filters applied in datatables or widgets for instance
    | 'small' // small variant, for filters in a datatable line for instance
    | 'tag'; // for filters with a style similar as the Tag component, in an entity Overview for instance

export interface FilterIconButtonSharedProps {
  handleRemoveFilter?: (key: string, op?: string) => void;
  handleSwitchGlobalMode?: () => void;
  handleSwitchLocalMode?: (filter: Filter) => void;
  variant?: FilterIconButtonVariant;
  chipColor?: ChipOwnProps['color'];
  disabledPossible?: boolean;
  redirection?: boolean;
  helpers?: handleFilterHelpers;
  availableRelationFilterTypes?: Record<string, string[]>;
  entityTypes?: string[];
  filtersRestrictions?: FiltersRestrictions;
  searchContext?: FilterSearchContext;
  availableEntityTypes?: string[];
  availableRelationshipTypes?: string[];
  host?: WidgetHost;
  hasSavedFilters?: boolean;
  availableFilterKeys?: string[];
  /**
   * When true, the nested filter group editor is rendered as a floating `Popper` instead of in
   * the normal document flow. Default is inline; opt into floating where a dropdown-style
   * trigger is more appropriate than growing the layout.
   */
  floating?: boolean;
}

interface FilterIconButtonContainerProps extends FilterIconButtonSharedProps {
  filters: FilterGroup;
  dataColumns?: DataColumns;
  filtersRepresentativesQueryRef: PreloadedQuery<FilterValuesContentQuery>;
  hasRendered: boolean;
  setHasRendered: (value: boolean) => void;
  filterChipsParams: FilterChipsParameter;
  setFilterChipsParams: React.Dispatch<React.SetStateAction<FilterChipsParameter>>;
}

/**
 * Wires the three concerns of the applied-filters area together:
 * - `useFilterRepresentatives` resolves the labels and the editable filter keys,
 * - `useFilterPopoverAnchor` owns the anchoring and the open/close state,
 * - `FilterChipLine` / `FilterChipPopover` / `FilterGroupPanelHost` render them.
 */
const FilterIconButtonContainer: FunctionComponent<
  FilterIconButtonContainerProps
> = ({
  filters,
  handleSwitchGlobalMode,
  handleSwitchLocalMode,
  variant,
  disabledPossible,
  redirection,
  filtersRepresentativesQueryRef,
  chipColor,
  handleRemoveFilter,
  helpers,
  hasRendered,
  setHasRendered,
  availableRelationFilterTypes,
  entityTypes,
  filtersRestrictions,
  searchContext,
  availableEntityTypes,
  availableRelationshipTypes,
  host,
  hasSavedFilters,
  filterChipsParams,
  setFilterChipsParams,
  availableFilterKeys,
  floating,
}) => {
  const displayedFilters = filters.filters;
  const displayedFilterGroups = filters.filterGroups ?? [];

  const { filtersRepresentativesMap, filterKeysMap, panelFilterKeys } = useFilterRepresentatives({
    filtersRepresentativesQueryRef,
    entityTypes,
    availableFilterKeys,
  });

  const {
    itemRefToPopover,
    filterLineRef,
    openedGroupId,
    toggleGroup,
    registerChipRef,
    handleChipClick,
    handleClose,
    handleClickAwayPanel,
  } = useFilterPopoverAnchor({
    helpers,
    displayedFilters,
    hasRendered,
    setHasRendered,
    setFilterChipsParams,
  });

  const openedGroup = displayedFilterGroups.find((group) => group.id === openedGroupId);

  return (
    <Box sx={{ width: '100%', position: 'relative' }}>
      <FilterChipLine
        displayedFilters={displayedFilters}
        displayedFilterGroups={displayedFilterGroups}
        globalMode={filters.mode}
        filterKeysMap={filterKeysMap}
        filtersRepresentativesMap={filtersRepresentativesMap}
        variant={variant}
        chipColor={chipColor}
        disabledPossible={disabledPossible}
        redirection={redirection}
        filtersRestrictions={filtersRestrictions}
        entityTypes={entityTypes}
        host={host}
        hasSavedFilters={hasSavedFilters}
        helpers={helpers}
        handleRemoveFilter={handleRemoveFilter}
        handleSwitchGlobalMode={handleSwitchGlobalMode}
        handleSwitchLocalMode={handleSwitchLocalMode}
        openedGroupId={openedGroupId}
        onToggleGroup={toggleGroup}
        registerChipRef={registerChipRef}
        onChipClick={handleChipClick}
        latestFilterChipRef={itemRefToPopover}
        lineRef={filterLineRef}
      >
        {filterChipsParams.filterId && filterChipsParams.anchorPosition && (
          <FilterChipPopover
            filters={filters.filters}
            params={filterChipsParams}
            handleClose={handleClose}
            open={Boolean(filterChipsParams.filterId)}
            helpers={helpers}
            filtersRepresentativesMap={filtersRepresentativesMap}
            availableRelationFilterTypes={availableRelationFilterTypes}
            entityTypes={entityTypes}
            searchContext={searchContext}
            availableEntityTypes={availableEntityTypes}
            availableRelationshipTypes={availableRelationshipTypes}
            host={host}
          />
        )}
      </FilterChipLine>
      {helpers && (
        <FilterGroupPanelHost
          group={openedGroup}
          floating={floating}
          anchorRef={filterLineRef}
          onClickAway={handleClickAwayPanel}
          helpers={helpers}
          availableFilterKeys={panelFilterKeys}
          entityTypes={entityTypes}
          filtersRepresentativesMap={filtersRepresentativesMap}
          availableEntityTypes={availableEntityTypes}
          availableRelationshipTypes={availableRelationshipTypes}
          availableRelationFilterTypes={availableRelationFilterTypes}
          searchContext={searchContext}
          host={host}
        />
      )}
    </Box>
  );
};

export default FilterIconButtonContainer;
