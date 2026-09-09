import Box from '@mui/material/Box';
import Chip from '@mui/material/Chip';
import { ChipOwnProps } from '@mui/material/Chip/Chip';
import { Tooltip, TooltipContent, TooltipTrigger } from '@filigran/design-system';
import React, { CSSProperties, Fragment, FunctionComponent, useContext, useEffect, useRef, useState } from 'react';
import { PreloadedQuery, usePreloadedQuery } from 'react-relay';
import {
  convertOperatorToIcon,
  filterOperatorsWithIcon,
  FILTER_LINE_ITEM_HEIGHT,
  FilterSearchContext,
  FiltersRestrictions,
  getFilterDefinitionFromFilterKeysMap,
  isFilterEditable,
  NO_VALUES_FILTER_OPERATORS,
  useBuildFilterKeysMapFromEntityType,
} from '../utils/filters/filtersUtils';
import { truncate } from '../utils/String';
import { FilterValuesContentQuery } from './__generated__/FilterValuesContentQuery.graphql';
import FilterValues from './filters/FilterValues';
import { useFormatter } from './i18n';
import { DataColumns } from './list_lines';

import type { WidgetHost } from '../utils/widget/widget';
import { Filter, FilterGroup, handleFilterHelpers } from '../utils/filters/filtersHelpers-types';
import FilterIconButtonGlobalMode from './FilterIconButtonGlobalMode';
import FilterGroupChipButton from './filters/group/FilterGroupChipButton';
import FilterGroupPanel from './filters/group/FilterGroupPanel';
import { FilterChipPopover, FilterChipsParameter } from './filters/FilterChipPopover';
import { FilterRepresentative } from './filters/FiltersModel';
import { filterValuesContentQuery } from './FilterValuesContent';
import { PageContainerContext } from './PageContainer';
import { useTheme } from '@mui/material/styles';
import { ClickAwayListener, Grow, Popper, Stack } from '@mui/material';
import { Paper } from '@filigran/design-system';

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
}

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
}) => {
  const { t_i18n } = useFormatter();
  const theme = useTheme();

  const { inPageContainer } = useContext(PageContainerContext);

  const { filtersRepresentatives } = usePreloadedQuery<FilterValuesContentQuery>(
    filterValuesContentQuery,
    filtersRepresentativesQueryRef,
  );

  const displayedFilters = filters.filters;
  const displayedFilterGroups = filters.filterGroups ?? [];
  const globalMode = filters.mode;
  const itemRefToPopover = useRef(null);
  const oldItemRefToPopover = useRef(null);
  const filterLineRef = useRef<HTMLDivElement | null>(null);
  const [openedGroupId, setOpenedGroupId] = useState<string | undefined>(undefined);
  const chipRefs = useRef<Record<string, HTMLDivElement | null>>({});
  const filterKeysMap = useBuildFilterKeysMapFromEntityType(entityTypes);
  const panelFilterKeys = availableFilterKeys ?? Array.from(filterKeysMap.keys());
  const filtersRepresentativesMap = new Map<string, FilterRepresentative>(
    filtersRepresentatives.map((n: FilterRepresentative) => [n.id, n]),
  );

  const getAnchorPosition = (element: HTMLElement) => {
    const rect = element.getBoundingClientRect();
    return { top: rect.bottom, left: rect.left };
  };

  // activate popover feature on chip only when "helper" is defined, not the best way to handle but
  // it means that the new filter feature is activated. Will be removed in the next version when we generalize the feature on every filter.
  useEffect(() => {
    if (!helpers) return;
    const latestFilterId = helpers.getLatestAddFilterId();
    const newFilterAdded = hasRenderedRef
      && latestFilterId
      && itemRefToPopover.current
      && oldItemRefToPopover.current !== itemRefToPopover.current;
    if (newFilterAdded) {
      const anchorEl = itemRefToPopover.current as unknown as HTMLElement;
      const anchorPosition = getAnchorPosition(anchorEl);
      setFilterChipsParams({
        filterId: latestFilterId,
        anchorEl,
        anchorPosition,
      });
    } else {
      setHasRenderedRef(true);
    }
    oldItemRefToPopover.current = itemRefToPopover.current;
  }, [displayedFilters, helpers, hasRenderedRef, setFilterChipsParams, setHasRenderedRef]);

  const handleClose = () => {
    setFilterChipsParams({
      filterId: undefined,
      anchorEl: undefined,
      anchorPosition: undefined,
    });
  };
  const handleChipClick = (
    event: React.MouseEvent<HTMLButtonElement>,
    filterId?: string,
  ) => {
    if (helpers) {
      const anchorEl = event.currentTarget.parentElement ?? event.currentTarget;
      const anchorPosition = getAnchorPosition(anchorEl);
      setFilterChipsParams({
        filterId,
        anchorEl,
        anchorPosition,
      });
    }
  };
  const manageRemoveFilter = (
    currentFilterId: string | undefined,
    filterKey: string,
    filterOperator: string,
  ) => {
    if (helpers && currentFilterId) {
      helpers?.handleRemoveFilterById(currentFilterId);
    } else if (handleRemoveFilter) {
      handleRemoveFilter(filterKey, filterOperator ?? undefined);
    }
  };

  const isReadWriteFilter = !!(helpers || handleRemoveFilter);
  let filterStyle: CSSProperties | undefined = undefined;
  let operatorStyle: CSSProperties = {
    borderRadius: 4,
    fontFamily: 'Consolas, monaco, monospace',
    backgroundColor: theme.palette.action?.selected,
    padding: '0 8px',
    display: 'flex',
    alignItems: 'center',
  };
  let margin = inPageContainer ? '0 0 0 0' : '0 0 8px 0';

  if (variant === 'small') {
    filterStyle = {
      fontSize: 12,
      height: 20,
      borderRadius: 4,
      lineHeight: `${FILTER_LINE_ITEM_HEIGHT}px`,
    };
    operatorStyle = {
      borderRadius: 4,
      fontFamily: 'Consolas, monaco, monospace',
      backgroundColor: theme.palette.action?.selected,
      padding: '0 8px',
      height: 20,
      marginRight: 5,
      marginLeft: 5,
    };
    if (isReadWriteFilter) margin = '0 0 0 0';
  } else if (variant === 'tag') {
    filterStyle = { height: 25 };
  }

  let boxStyle = {
    margin: `${margin}`,
    display: 'flex',
    flexWrap: 'wrap',
    gap: 1,
    overflow: 'hidden',
    backgroundColor: hasSavedFilters ? 'rgba(37, 150, 190, 0.3)' : 'transparent',
    borderRadius: hasSavedFilters ? '4px' : '0px',
  };

  if (!isReadWriteFilter) {
    boxStyle = {
      margin: '0 0 0 0',
      display: 'flex',
      flexWrap: 'no-wrap',
      gap: 0,
      overflow: 'hidden',
      backgroundColor: 'none',
      borderRadius: '0px',
    };
  }

  const isGroupPanelReadOnly = !helpers || variant === 'small' || variant === 'tag';
  const openedGroup = displayedFilterGroups.find((group) => group.id === openedGroupId);

  const handleClickAwayPanel = (event: MouseEvent | TouchEvent) => {
    // This listener runs on `pointerdown` (see `mouseEvent` on the ClickAwayListener below), so the
    // chip that toggles the panel would be closed here and immediately reopened by its own click
    // handler. The chip owns its toggle: ignore the gesture when it starts inside it.
    const target = event.target as Node | null;
    if (openedGroupId && target && chipRefs.current[openedGroupId]?.contains(target)) {
      return;
    }
    setOpenedGroupId(undefined);
  };

  const globalModeSeparator = (
    <Box
      sx={{
        padding: variant === 'small' ? '0 4px' : '0',
        display: 'flex',
      }}
    >
      <FilterIconButtonGlobalMode
        operatorStyle={operatorStyle}
        isOperatorClickable={isReadWriteFilter}
        globalMode={globalMode}
        handleSwitchGlobalMode={() => {
          if (helpers?.handleSwitchGlobalMode) {
            helpers.handleSwitchGlobalMode();
          } else if (handleSwitchGlobalMode) {
            handleSwitchGlobalMode();
          }
        }}
      />
    </Box>
  );

  return (
    <Box sx={{ width: '100%', position: 'relative' }}>
      <Box sx={boxStyle} ref={filterLineRef}>
        {displayedFilterGroups.map((group, index) => (
          <Fragment key={group.id ?? `filter-group-${index}`}>
            <FilterGroupChipButton
              ref={(node) => {
                chipRefs.current[group.id ?? ''] = node;
              }}
              filterGroup={group}
              isOpen={openedGroupId === group.id}
              readOnly={isGroupPanelReadOnly}
              chipColor={chipColor}
              style={filterStyle}
              onClick={() => setOpenedGroupId((current) => (current === group.id ? undefined : group.id))}
            />
            {(index < displayedFilterGroups.length - 1 || displayedFilters.length > 0) && globalModeSeparator}
          </Fragment>
        ))}
        {displayedFilters.map((currentFilter, index) => {
          const filterKey = currentFilter.key;
          const filterLabel = t_i18n(getFilterDefinitionFromFilterKeysMap(filterKey, filterKeysMap)?.label ?? filterKey);
          const filterOperator = currentFilter.operator ?? 'eq';
          const filterValues = currentFilter.values;
          const isOperatorDisplayed = filterOperatorsWithIcon.includes(filterOperator ?? 'eq');
          const keyLabel = (
            <>
              {truncate(filterLabel, 20)}
              {!isOperatorDisplayed && (
                <Box
                  component="span"
                  sx={{ padding: '0 4px', fontWeight: 'normal' }}
                >
                  {t_i18n(filterOperator)}
                </Box>
              )}
              {isOperatorDisplayed
                ? convertOperatorToIcon(filterOperator ?? 'eq')
                : currentFilter.values.length > 0 && ':'}
            </>
          );
          const isNotLastFilter = index < displayedFilters.length - 1;

          const chipVariant = currentFilter.values.length === 0 && !NO_VALUES_FILTER_OPERATORS.includes(filterOperator ?? 'eq')
            ? 'outlined'
            : 'filled';
          // darken the bg color when filled (quickfix for 'warning' and 'success' chipColor unreadable with regardingOf filter)
          const chipBackgroundColorStyle = (chipColor === 'warning' || chipColor === 'success') && chipVariant === 'filled'
            ? { bgcolor: `${chipColor}.dark` }
            : undefined;
          const authorizeFilterRemoving = !(filtersRestrictions?.preventRemoveFor?.includes(filterKey))
            && isFilterEditable(filtersRestrictions, filterKey, filterValues);
          const tooltipContent = filterKey === 'regardingOf' || filterKey === 'dynamicRegardingOf'
            ? undefined
            : (
                // As inline content the key, the values and the operator sat on three different baselines.
                <Box
                  sx={{
                    display: 'flex',
                    alignItems: 'center',
                    flexWrap: 'wrap',
                    gap: '4px',
                  }}
                >
                  <FilterValues
                    label={keyLabel}
                    tooltip={true}
                    currentFilter={currentFilter}
                    handleSwitchLocalMode={handleSwitchLocalMode}
                    filtersRepresentativesMap={filtersRepresentativesMap}
                    redirection={redirection}
                    entityTypes={entityTypes}
                    filtersRestrictions={filtersRestrictions}
                    host={host}
                  />
                </Box>
              );
          const chip = (
            <Box
              sx={{
                padding: '0',
                display: 'flex',
              }}
            >
              <Chip
                color={chipColor}
                ref={
                  helpers?.getLatestAddFilterId() === currentFilter.id
                    ? itemRefToPopover
                    : null
                }
                variant={chipVariant}
                sx={{
                  ...filterStyle,
                  ...chipBackgroundColorStyle,
                  borderRadius: 1,
                  '& .MuiChip-label': {
                    lineHeight: `${FILTER_LINE_ITEM_HEIGHT}px`,
                    maxWidth: 400,
                    whiteSpace: 'nowrap',
                    overflow: 'hidden',
                    textOverflow: 'ellipsis',
                    display: 'flex',
                    alignItems: 'center',
                    gap: 4,
                  },
                }}
                label={(
                  <Stack
                    alignItems="center"
                    direction="row"
                    gap={0.5}
                    sx={{
                      overflow: 'hidden',
                      textOverflow: 'ellipsis',
                    }}
                  >
                    <FilterValues
                      label={keyLabel}
                      tooltip={false}
                      currentFilter={currentFilter}
                      handleSwitchLocalMode={helpers?.handleSwitchLocalMode ?? handleSwitchLocalMode}
                      filtersRepresentativesMap={filtersRepresentativesMap}
                      redirection={redirection}
                      onClickLabel={(event) => handleChipClick(event, currentFilter?.id)}
                      isReadWriteFilter={isReadWriteFilter}
                      chipColor={chipColor}
                      entityTypes={entityTypes}
                      filtersRestrictions={filtersRestrictions}
                      host={host}
                    />
                  </Stack>
                )}
                disabled={
                  disabledPossible ? displayedFilters.length === 1 : undefined
                }
                onDelete={
                  (isReadWriteFilter && authorizeFilterRemoving)
                    ? () => manageRemoveFilter(
                        currentFilter.id,
                        filterKey,
                        filterOperator,
                      )
                    : undefined
                }
              />
            </Box>
          );
          return (
            <Fragment key={currentFilter.id ?? `filter-${index}`}>
              {tooltipContent
                ? (
                    <Tooltip>
                      <TooltipTrigger asChild>{chip}</TooltipTrigger>
                      <TooltipContent>{tooltipContent}</TooltipContent>
                    </Tooltip>
                  )
                : chip}
              {isNotLastFilter && globalModeSeparator}
            </Fragment>
          );
        })}
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
      </Box>
      {helpers && (
        <Popper
          open={Boolean(openedGroup)}
          anchorEl={filterLineRef.current}
          placement="bottom-start"
          disablePortal
          transition
          // Sized against the wrapping `Box` (position: relative) instead of a JS-measured
          // offsetWidth: stays in sync with the chip line's real width on every resize /
          // sidebar collapse, with no state tracking needed.
          style={{ width: '100%', zIndex: theme.zIndex.modal }}
        >
          {({ TransitionProps }) => (
            <Grow {...TransitionProps} style={{ transformOrigin: 'left top' }}>
              <Paper padding={0} style={{ width: '100%', marginTop: 8 }}>
                {/* The decision must be taken on `pointerdown`: the design system Select opens on
                    that event and portals its content, and the resulting `click` is then dispatched
                    on the common ancestor of the trigger and of the freshly mounted content, i.e.
                    the document element — outside the panel and outside any React tree, where no
                    listener can recognize it. On `pointerdown` the target is still the trigger.
                    Clicks landing inside an already open portal are handled by ClickAwayListener
                    itself, which forgives events bubbling through a React portal.
                    FDS-WORKAROUND #61: removable once SelectContent accepts `portalled`. */}
                <ClickAwayListener mouseEvent="onPointerDown" onClickAway={handleClickAwayPanel}>
                  <Box sx={{ padding: 2 }}>
                    {openedGroup && (
                      <FilterGroupPanel
                        group={openedGroup}
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
                </ClickAwayListener>
              </Paper>
            </Grow>
          )}
        </Popper>
      )}
    </Box>
  );
};

export default FilterIconButtonContainer;
