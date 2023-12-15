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
import { Filter, FilterGroup, filtersUsedAsApiParameters } from '../utils/filters/filtersUtils';
import { filterIconButtonContentQuery } from './FilterIconButtonContent';
import { FilterIconButtonContentQuery } from './__generated__/FilterIconButtonContentQuery.graphql';
import FilterValues from './filters/FilterValues';
import { FilterChipPopover, FilterChipsParameter } from './filters/FilterChipPopover';
import DisplayFilterGroup from './filters/DisplayFilterGroup';
import { UseLocalStorageHelpers } from '../utils/hooks/useLocalStorage';
import FilterIconButtonGlobalOperator from './FilterIconButtonGlobalOperator';

const useStyles = makeStyles<Theme>((theme) => ({
  filter3: {
    fontSize: 12,
    height: 20,
    borderRadius: 10,
    lineHeight: '32px',
  },
  operator1: {
    borderRadius: 5,
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
    borderRadius: 5,
    fontFamily: 'Consolas, monaco, monospace',
    backgroundColor: theme.palette.action?.selected,
    padding: '0 8px',
    display: 'flex',
    alignItems: 'center',
  },
  operator2: {
    borderRadius: 5,
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
    borderRadius: 5,
    fontFamily: 'Consolas, monaco, monospace',
    backgroundColor: theme.palette.action?.selected,
    padding: '0 8px',
    display: 'flex',
    alignItems: 'center',
  },
  operator3: {
    borderRadius: 5,
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
    borderRadius: 5,
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
  filtersRepresentativesQueryRef: PreloadedQuery<FilterIconButtonContentQuery>;
  chipColor?: ChipOwnProps['color'];
  helpers?: UseLocalStorageHelpers;
  hasRenderedRef: boolean;
  setHasRenderedRef: () => void;
  availableRelationFilterTypes?: Record<string, string[]>;
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
}) => {
  const { t } = useFormatter();
  const classes = useStyles();
  const { filtersRepresentatives } = usePreloadedQuery<FilterIconButtonContentQuery>(
    filterIconButtonContentQuery,
    filtersRepresentativesQueryRef,
  );
  const displayedFilters = filters.filters;
  const displayedSpecificFilters = displayedFilters.filter((f) => filtersUsedAsApiParameters.includes(f.key));
  const othersFilters = displayedFilters.filter(
    (f) => !filtersUsedAsApiParameters.includes(f.key),
  );
  const globalMode = filters.mode;
  const itemRefToPopover = useRef(null);
  const oldItemRefToPopover = useRef(null);
  let classFilter = classes.filter1;
  const filtersRepresentativesMap = new Map(
    filtersRepresentatives.map((n) => [n.id, n.value]),
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
  const backgroundGroupingChipsStyle = {
    ...(styleNumber !== 3 && { backgroundColor: 'rgba(74, 117, 162, 0.2)' }),
  };
  const generateFilterElement = (filtersElmt: Filter[], isOthers: boolean) => {
    return filtersElmt.map((currentFilter, index) => {
      const filterKey = currentFilter.key;
      const filterOperator = currentFilter.operator;
      const isOperatorDisplayed = operatorIcon.includes(filterOperator);
      const keyLabel = (
        <>
          {truncate(t(filterKey), 20)}
          {!isOperatorDisplayed && (
            <Box
              component={'span'}
              sx={{ padding: '0 4px', fontWeight: 'normal' }}
            >
              {t(filterOperator)}
            </Box>
          )}
          {isOperatorDisplayed
            ? convertOperatorToIcon(filterOperator)
            : currentFilter.values.length > 0 && ':'}
        </>
      );
      const isNotLastFilter = index < filtersElmt.length - 1;
      return (
        <Fragment key={currentFilter.id}>
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
              />
            }
          >
            <Box
              sx={{
                padding: styleNumber === 3 ? '0 4px' : '8px 4px',
                display: 'flex',
                ...(isOthers ? {} : backgroundGroupingChipsStyle),
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
                variant={
                  currentFilter.values.length === 0
                  && !['nil', 'not_nil'].includes(filterOperator)
                    ? 'outlined'
                    : 'filled'
                }
                label={
                  <FilterValues
                    label={keyLabel}
                    tooltip={false}
                    currentFilter={currentFilter}
                    handleSwitchLocalMode={handleSwitchLocalMode}
                    filtersRepresentativesMap={filtersRepresentativesMap}
                    redirection={redirection}
                    helpers={helpers}
                    onClickLabel={(event) => handleChipClick(event, currentFilter?.id)
                    }
                    isReadWriteFilter={isReadWriteFilter}
                  />
                }
                disabled={
                  disabledPossible
                    ? filtersElmt.length === 1
                    : undefined
                }
                onDelete={
                  isReadWriteFilter
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
                ...(!isOthers ? backgroundGroupingChipsStyle : {}),
              }}
            >
              <FilterIconButtonGlobalOperator
                currentIndex={index}
                displayedFilters={filtersElmt}
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
    });
  };
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
      {generateFilterElement(displayedSpecificFilters, false)}
      {displayedSpecificFilters.length > 0
        && othersFilters.length > 0 && (
          <Box
            sx={{
              padding: styleNumber === 3 ? '0 4px' : '8px 4px 8px 8px',
              display: 'flex',
            }}
          >
            <div
              className={classOperator}
              onClick={() => {
                if (helpers?.handleSwitchGlobalMode) {
                  helpers.handleSwitchGlobalMode();
                } else if (handleSwitchGlobalMode) {
                  handleSwitchGlobalMode();
                }
              }}
            >
              {t(globalMode.toUpperCase())}
            </div>
          </Box>
      )}
      {generateFilterElement(othersFilters, true)}
      {filterChipsParams.anchorEl && (
        <Box>
          <FilterChipPopover
            filters={filters.filters}
            params={filterChipsParams}
            handleClose={handleClose}
            open={open}
            helpers={helpers}
            availableRelationFilterTypes={availableRelationFilterTypes}
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
