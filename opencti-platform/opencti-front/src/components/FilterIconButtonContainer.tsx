import Chip from '@mui/material/Chip';
import Tooltip from '@mui/material/Tooltip';
import React, { Fragment, FunctionComponent, useEffect, useRef } from 'react';
import makeStyles from '@mui/styles/makeStyles';
import { PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { ChipOwnProps } from '@mui/material/Chip/Chip';
import Box from '@mui/material/Box';
import { truncate } from '../utils/String';
import { DataColumns } from './list_lines';
import { useFormatter } from './i18n';
import type { Theme } from './Theme';
import { Filter, FilterGroup, useFilterDefinition } from '../utils/filters/filtersUtils';
import { FilterValuesContentQuery } from './__generated__/FilterValuesContentQuery.graphql';
import FilterValues from './filters/FilterValues';
import { FilterChipPopover, FilterChipsParameter } from './filters/FilterChipPopover';
import DisplayFilterGroup from './filters/DisplayFilterGroup';
import { handleFilterHelpers } from '../utils/hooks/useLocalStorage';
import FilterIconButtonGlobalMode from './FilterIconButtonGlobalMode';
import { filterValuesContentQuery } from './FilterValuesContent';
import { FilterRepresentative } from './filters/FiltersModel';

const useStyles = makeStyles<Theme>((theme) => ({
  filter3: {
    fontSize: 12,
    height: 20,
    borderRadius: 10,
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
  setHasRenderedRef: () => void;
  availableRelationFilterTypes?: Record<string, string[]>;
  entityTypes?: string[];
  restrictedFilters?: string[];
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
  restrictedFilters,
}) => {
  const { t_i18n } = useFormatter();
  const classes = useStyles();
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
  const [filterChipsParams, setFilterChipsParams] = React.useState<FilterChipsParameter>({
    filter: undefined,
    anchorEl: undefined,
  } as FilterChipsParameter);
  const open = Boolean(filterChipsParams.anchorEl);
  if (helpers) {
    // activate popover feature on chip only when "helper" is defined, not the best way to handle but
    // it means that the new filter feature is activated. Will be removed in the next version when we generalize the feature on every filter.
    useEffect(() => {
      if (hasRenderedRef && itemRefToPopover.current && oldItemRefToPopover.current !== itemRefToPopover.current) {
        setFilterChipsParams({
          filterId: helpers?.getLatestAddFilterId(),
          anchorEl: itemRefToPopover.current as unknown as HTMLElement,
        });
      } else {
        setHasRenderedRef();
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
        anchorEl: event.currentTarget,
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
  const operatorIcon = [
    'lt',
    'lte',
    'gt',
    'gte',
    'nil',
    'not_nil',
    'eq',
    'not_eq',
  ];
  const convertOperatorToIcon = (operator: string) => {
    switch (operator) {
      case 'lt':
        return <>&nbsp;&#60;</>;
      case 'lte':
        return <>&nbsp;&#8804;</>;
      case 'gt':
        return <>&nbsp;&#62;</>;
      case 'gte':
        return <>&nbsp;&#8805;</>;
      case 'eq':
        return <>&nbsp;=</>;
      case 'not_eq':
        return <>&nbsp;&#8800;</>;
      default:
        return null;
    }
  };
  const isReadWriteFilter = !!(helpers || handleRemoveFilter);
  let classOperator = classes.operator1;
  let marginTop = '2px';
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
    marginTop = '10px';
  } else if (styleNumber === 3) {
    classFilter = classes.filter3;
    classOperator = classes.operator3;
    marginTop = '0px';
  }
  return (
    <Box
      sx={
        !isReadWriteFilter
          ? {
            display: 'flex',
            overflow: 'hidden',
          }
          : {
            marginTop: displayedFilters.length === 0 ? '0px' : marginTop,
            display: 'flex',
            flexWrap: 'wrap',
          }
      }
    >
      {displayedFilters.map((currentFilter, index) => {
        const filterKey = currentFilter.key;
        const filterLabel = t_i18n(useFilterDefinition(filterKey, entityTypes)?.label ?? filterKey);
        const filterOperator = currentFilter.operator ?? 'eq';
        const isOperatorDisplayed = operatorIcon.includes(filterOperator ?? 'eq');
        const keyLabel = (
          <>
            {truncate(filterLabel, 20)}
            {!isOperatorDisplayed && (
              <Box
                component={'span'}
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

        return (
          <Fragment key={currentFilter.id ?? `filter-${index}`}>
            <Tooltip
              title={
                <FilterValues
                  label={keyLabel}
                  tooltip={true}
                  currentFilter={currentFilter}
                  handleSwitchLocalMode={handleSwitchLocalMode}
                  filtersRepresentativesMap={filtersRepresentativesMap}
                  helpers={helpers}
                  redirection={redirection}
                  entityTypes={entityTypes}
                  restrictedFilters={restrictedFilters}
                />
              }
            >
              <Box
                sx={{
                  padding: styleNumber === 3 ? '0 4px' : '8px 4px',
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
                  sx={chipSx}
                  label={
                    <FilterValues
                      label={keyLabel}
                      tooltip={false}
                      currentFilter={currentFilter}
                      handleSwitchLocalMode={helpers?.handleSwitchLocalMode ?? handleSwitchLocalMode}
                      filtersRepresentativesMap={filtersRepresentativesMap}
                      redirection={redirection}
                      helpers={helpers}
                      onClickLabel={(event) => handleChipClick(event, currentFilter?.id)}
                      isReadWriteFilter={isReadWriteFilter}
                      chipColor={chipColor}
                      entityTypes={entityTypes}
                      restrictedFilters={restrictedFilters}
                    />
                  }
                  disabled={
                    disabledPossible ? displayedFilters.length === 1 : undefined
                  }
                  onDelete={
                    (isReadWriteFilter && !(restrictedFilters?.includes(filterKey)))
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
                  padding: styleNumber === 3 ? '0 4px' : '8px 4px',
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
        <Box>
          <FilterChipPopover
            filters={filters.filters}
            params={filterChipsParams}
            handleClose={handleClose}
            open={open}
            helpers={helpers}
            filtersRepresentativesMap={filtersRepresentativesMap}
            availableRelationFilterTypes={availableRelationFilterTypes}
            entityTypes={entityTypes}
          />
        </Box>
      )}
      {filters.filterGroups
        && filters.filterGroups.length > 0 && ( // if there are filterGroups, we display a warning box // TODO display correctly filterGroups
          <Box style={{
            padding: '8px 4px',
          }}
          >
            <DisplayFilterGroup
              filtersRepresentativesMap={filtersRepresentativesMap}
              filterObj={filters}
              filterMode={filters.mode}
              classFilter={classFilter}
              classChipLabel={classes.chipLabel}
            />
          </Box>
      )}
    </Box>
  );
};

export default FilterIconButtonContainer;
