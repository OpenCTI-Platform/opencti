import Chip from '@mui/material/Chip';
import Tooltip from '@mui/material/Tooltip';
import React, { Fragment, FunctionComponent, useContext, useEffect, useRef, useState } from 'react';
import makeStyles from '@mui/styles/makeStyles';
import { PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { ChipOwnProps } from '@mui/material/Chip/Chip';
import Box from '@mui/material/Box';
import { truncate } from '../utils/String';
import { DataColumns } from './list_lines';
import { useFormatter } from './i18n';
import type { Theme } from './Theme';
import { convertOperatorToIcon, filterOperatorsWithIcon, FilterSearchContext, FiltersRestrictions, isFilterEditable, useFilterDefinition } from '../utils/filters/filtersUtils';
import { FilterValuesContentQuery } from './__generated__/FilterValuesContentQuery.graphql';
import FilterValues from './filters/FilterValues';

import { FilterChipPopover, FilterChipsParameter } from './filters/FilterChipPopover';
import DisplayFilterGroup from './filters/DisplayFilterGroup';
import FilterIconButtonGlobalMode from './FilterIconButtonGlobalMode';
import { filterValuesContentQuery } from './FilterValuesContent';
import { FilterRepresentative } from './filters/FiltersModel';
import { Filter, FilterGroup, handleFilterHelpers } from '../utils/filters/filtersHelpers-types';
import { PageContainerContext } from './PageContainer';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles<Theme>((theme) => ({
  filter3: {
    fontSize: 12,
    height: 20,
    borderRadius: 4,
    lineHeight: '32px',
  },
  operator1: {
    borderRadius: 4,
    fontFamily: 'Consolas, monaco, monospace',
    backgroundColor: theme.palette.action?.selected,
    padding: '0 8px',
    display: 'flex',
    alignItems: 'center',
    cursor: 'pointer',
    '&:hover': {
      backgroundColor: theme.palette.action?.disabled,
      textDecorationLine: 'underline',
    },
  },
  operator1ReadOnly: {
    borderRadius: 4,
    fontFamily: 'Consolas, monaco, monospace',
    backgroundColor: theme.palette.action?.selected,
    padding: '0 8px',
    display: 'flex',
    alignItems: 'center',
  },
  operator2: {
    borderRadius: 4,
    fontFamily: 'Consolas, monaco, monospace',
    backgroundColor: theme.palette.action?.selected,
    padding: '0 8px',
    display: 'flex',
    alignItems: 'center',
    cursor: 'pointer',
    '&:hover': {
      backgroundColor: theme.palette.action?.disabled,
      textDecorationLine: 'underline',
    },
  },
  operator2ReadOnly: {
    borderRadius: 4,
    fontFamily: 'Consolas, monaco, monospace',
    backgroundColor: theme.palette.action?.selected,
    padding: '0 8px',
    display: 'flex',
    alignItems: 'center',
  },
  operator3: {
    borderRadius: 4,
    fontFamily: 'Consolas, monaco, monospace',
    backgroundColor: theme.palette.action?.selected,
    height: 20,
    padding: '0 8px',
    marginRight: 5,
    marginLeft: 5,
    cursor: 'pointer',
    '&:hover': {
      backgroundColor: theme.palette.action?.disabled,
      textDecorationLine: 'underline',
    },
  },
  operator3ReadOnly: {
    borderRadius: 4,
    fontFamily: 'Consolas, monaco, monospace',
    backgroundColor: theme.palette.action?.selected,
    height: 20,
    padding: '0 8px',
    marginRight: 5,
    marginLeft: 5,
  },
  chipLabel: {
    lineHeight: '32px',
    maxWidth: 400,
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    display: 'flex',
    alignItems: 'center',
    gap: 4,
  },
}));

interface FilterIconButtonContainerProps {
  filters: FilterGroup;
  handleRemoveFilter?: (key: string, op?: string) => void;
  handleSwitchGlobalMode?: () => void;
  handleSwitchLocalMode?: (filter: Filter) => void;
  styleNumber?: number;
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
  fintelTemplatesContext?: boolean;
  hasSavedFilters?: boolean;
}

const FilterIconButtonContainer: FunctionComponent<
  FilterIconButtonContainerProps
> = ({
  filters,
  handleSwitchGlobalMode,
  handleSwitchLocalMode,
  styleNumber,
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
  fintelTemplatesContext,
  hasSavedFilters,
}) => {
  const { t_i18n } = useFormatter();
  const classes = useStyles();

  const { inPageContainer } = useContext(PageContainerContext);

  const { filtersRepresentatives } = usePreloadedQuery<FilterValuesContentQuery>(
    filterValuesContentQuery,
    filtersRepresentativesQueryRef,
  );

  const displayedFilters = filters.filters;
  const globalMode = filters.mode;
  const itemRefToPopover = useRef(null);
  const oldItemRefToPopover = useRef(null);
  let classFilter = classes.filter1;
  const filtersRepresentativesMap = new Map<string, FilterRepresentative>(
    filtersRepresentatives.map((n: FilterRepresentative) => [n.id, n]),
  );
  const [filterChipsParams, setFilterChipsParams] = useState<FilterChipsParameter>({
    filter: undefined,
    anchorEl: undefined,
  } as FilterChipsParameter);
  const open = Boolean(filterChipsParams.anchorEl);
  if (helpers) {
    // activate popover feature on chip only when "helper" is defined, not the best way to handle but
    // it means that the new filter feature is activated. Will be removed in the next version when we generalize the feature on every filter.
    useEffect(() => {
      const newFilterAdded = hasRenderedRef
        && itemRefToPopover.current
        && oldItemRefToPopover.current !== itemRefToPopover.current;
      if (newFilterAdded) {
        setFilterChipsParams({
          filterId: helpers?.getLatestAddFilterId(),
          anchorEl: itemRefToPopover.current as unknown as HTMLElement,
        });
      } else {
        setHasRenderedRef(true);
      }
      oldItemRefToPopover.current = itemRefToPopover.current;
    }, [displayedFilters]);
  }
  const handleClose = () => {
    setFilterChipsParams({
      filterId: undefined,
      anchorEl: undefined,
    });
  };
  const handleChipClick = (
    event: React.MouseEvent<HTMLButtonElement>,
    filterId?: string,
  ) => {
    if (helpers) {
      setFilterChipsParams({
        filterId,
        anchorEl: event.currentTarget.parentElement ?? event.currentTarget,
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
  let classOperator = classes.operator1;
  let margin = inPageContainer ? '0 0 0 0' : '0 0 8px 0';
  if (!isReadWriteFilter) {
    classOperator = classes.operator1ReadOnly;
    if (styleNumber === 2) {
      classFilter = classes.filter2;
      classOperator = classes.operator2ReadOnly;
    } else if (styleNumber === 3) {
      classFilter = classes.filter3;
      classOperator = classes.operator3ReadOnly;
    }
  } else if (styleNumber === 2) {
    classFilter = classes.filter2;
    classOperator = classes.operator2;
    margin = '10px 0 10px 0';
  } else if (styleNumber === 3) {
    classFilter = classes.filter3;
    classOperator = classes.operator3;
    margin = '0 0 0 0';
  }

  let boxStyle = {
    margin: `${margin}`,
    display: 'flex',
    flexWrap: 'wrap',
    gap: 1,
    overflow: 'auto',
    backgroundColor: hasSavedFilters ? 'rgba(37, 150, 190, 0.3)' : 'transparent',
    borderRadius: hasSavedFilters ? '4px' : '0px',
  };

  if (!isReadWriteFilter) {
    if (styleNumber !== 2) {
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
  }

  return (
    <Box sx={boxStyle}>
      {displayedFilters.map((currentFilter, index) => {
        const filterKey = currentFilter.key;
        const filterLabel = t_i18n(useFilterDefinition(filterKey, entityTypes)?.label ?? filterKey);
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

        const chipVariant = currentFilter.values.length === 0 && !['nil', 'not_nil'].includes(filterOperator ?? 'eq')
          ? 'outlined'
          : 'filled';
        // darken the bg color when filled (quickfix for 'warning' and 'success' chipColor unreadable with regardingOf filter)
        const chipSx = (chipColor === 'warning' || chipColor === 'success') && chipVariant === 'filled'
          ? { bgcolor: `${chipColor}.dark` }
          : undefined;
        const authorizeFilterRemoving = !(filtersRestrictions?.preventRemoveFor?.includes(filterKey))
          && isFilterEditable(filtersRestrictions, filterKey, filterValues);
        return (
          <Fragment key={currentFilter.id ?? `filter-${index}`}>
            <Tooltip
              title={
                filterKey === 'regardingOf' || filterKey === 'dynamicRegardingOf'
                  ? undefined
                  : (
                      <FilterValues
                        label={keyLabel}
                        tooltip={true}
                        currentFilter={currentFilter}
                        handleSwitchLocalMode={handleSwitchLocalMode}
                        filtersRepresentativesMap={filtersRepresentativesMap}
                        redirection={redirection}
                        entityTypes={entityTypes}
                        filtersRestrictions={filtersRestrictions}
                      />
                    )
              }
            >
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
                  classes={{ root: classFilter, label: classes.chipLabel }}
                  variant={chipVariant}
                  sx={{ ...chipSx, borderRadius: 1 }}
                  label={(
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
                    />
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
            </Tooltip>
            {isNotLastFilter && (
              <Box
                sx={{
                  padding: styleNumber === 3 ? '0 4px' : '0',
                  display: 'flex',
                }}
              >
                <FilterIconButtonGlobalMode
                  classOperator={classOperator}
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
            )}
          </Fragment>
        );
      })}
      {filterChipsParams.anchorEl && (
        <>
          <FilterChipPopover
            filters={filters.filters}
            params={filterChipsParams}
            handleClose={handleClose}
            open={open}
            helpers={helpers}
            filtersRepresentativesMap={filtersRepresentativesMap}
            availableRelationFilterTypes={availableRelationFilterTypes}
            entityTypes={entityTypes}
            searchContext={searchContext}
            availableEntityTypes={availableEntityTypes}
            availableRelationshipTypes={availableRelationshipTypes}
            fintelTemplatesContext={fintelTemplatesContext}
          />
        </>
      )}
      {filters.filterGroups
        && filters.filterGroups.length > 0 && ( // if there are filterGroups, we display a warning box // TODO display correctly filterGroups
        <DisplayFilterGroup
          filtersRepresentativesMap={filtersRepresentativesMap}
          filterObj={filters}
          filterMode={filters.mode}
          classFilter={classFilter}
          classChipLabel={classes.chipLabel}
        />
      )}
    </Box>
  );
};

export default FilterIconButtonContainer;
