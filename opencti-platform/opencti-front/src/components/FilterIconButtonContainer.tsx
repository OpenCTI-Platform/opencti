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

interface FilterIconButtonContainerProps {
  filters: FilterGroup;
  handleRemoveFilter?: (key: string, op?: string) => void;
  handleSwitchGlobalMode?: () => void;
  handleSwitchLocalMode?: (filter: Filter) => void;
  variant?: FilterIconButtonVariant;
  dataColumns?: DataColumns;
  disabledPossible?: boolean;
  redirection?: boolean;
  filtersRepresentativesQueryRef: PreloadedQuery<FilterValuesContentQuery>;
  chipColor?: ChipOwnProps['color'];
  helpers?: handleFilterHelpers;
  hasRenderedRef: boolean;
  setHasRenderedRef: (value: boolean) => void;
  availableRelationFilterTypes?: Record<string, string[]>;
  entityTypes?: string[];
  filtersRestrictions?: FiltersRestrictions;
  searchContext?: FilterSearchContext;
  availableEntityTypes?: string[];
  availableRelationshipTypes?: string[];
  host?: WidgetHost;
  hasSavedFilters?: boolean;
  filterChipsParams: FilterChipsParameter;
  setFilterChipsParams: React.Dispatch<React.SetStateAction<FilterChipsParameter>>;
  availableFilterKeys?: string[];
  /**
   * When true, the nested filter group editor is rendered in the normal document flow
   * (a plain Box) instead of a floating `Popper`. Used in contexts where a floating panel
   * would overflow its container without resizing it, e.g. the widget creation dialog.
   */
  inline?: boolean;
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
  hasRenderedRef,
  setHasRenderedRef,
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
  inline,
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
    hasRenderedRef,
    setHasRenderedRef,
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
          inline={inline}
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
