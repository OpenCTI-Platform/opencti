import React, { Fragment, FunctionComponent } from 'react';
import { last } from 'ramda';
import makeStyles from '@mui/styles/makeStyles';
import Tooltip from '@mui/material/Tooltip';
import Box from '@mui/material/Box';
import Chip from '@mui/material/Chip';
import { ChipOwnProps } from '@mui/material/Chip/Chip';
import { useFormatter } from '../i18n';
import type { Theme } from '../Theme';
import { FiltersRestrictions, isFilterEditable, useFilterDefinition } from '../../utils/filters/filtersUtils';
import { truncate } from '../../utils/String';
import FilterValuesContent from '../FilterValuesContent';
import { FilterRepresentative } from './FiltersModel';
import { Filter } from '../../utils/filters/filtersHelpers-types';

// Deprecated - https://mui.com/system/styles/basics/
// Do not use it for new code.
const useStyles = makeStyles<Theme>((theme) => ({
  inlineOperator: {
    display: 'inline-block',
    height: '100%',
    borderRadius: 0,
    margin: '0 5px 0 5px',
    padding: '0 5px 0 5px',
    cursor: 'pointer',
    backgroundColor: theme.palette.action?.disabled,
    fontFamily: 'Consolas, monaco, monospace',
    '&:hover': {
      textDecorationLine: 'underline',
      backgroundColor: theme.palette.text?.disabled,
    },
  },
  inlineOperatorReadOnly: {
    display: 'inline-block',
    height: '100%',
    borderRadius: 0,
    margin: '0 5px 0 5px',
    padding: '0 5px 0 5px',
    backgroundColor: theme.palette.action?.disabled,
    fontFamily: 'Consolas, monaco, monospace',
  },
  label: {
    cursor: 'pointer',
    '&:hover': {
      textDecorationLine: 'underline',
    },
  },
}));

interface FilterValuesProps {
  label: string | React.JSX.Element;
  tooltip?: boolean;
  currentFilter: Filter;
  filtersRepresentativesMap: Map<string, FilterRepresentative>;
  redirection?: boolean;
  handleSwitchLocalMode?: (filter: Filter) => void;
  onClickLabel?: (event: React.MouseEvent<HTMLButtonElement>) => void;
  isReadWriteFilter?: boolean;
  chipColor?: ChipOwnProps['color'];
  noLabelDisplay?: boolean;
  entityTypes?: string[];
  filtersRestrictions?: FiltersRestrictions;
}

const FilterValues: FunctionComponent<FilterValuesProps> = ({
  label,
  tooltip,
  currentFilter,
  filtersRepresentativesMap,
  redirection,
  handleSwitchLocalMode,
  onClickLabel,
  isReadWriteFilter,
  chipColor,
  noLabelDisplay,
  entityTypes,
  filtersRestrictions,
}) => {
  const { t_i18n } = useFormatter();
  const filterKey = currentFilter.key;
  const filterOperator = currentFilter.operator;
  const filterValues = currentFilter.values;
  const isOperatorNil = ['nil', 'not_nil'].includes(filterOperator ?? 'eq');
  const classes = useStyles();
  const deactivatePopoverMenu = !isFilterEditable(filtersRestrictions, filterKey, filterValues);
  const onCLick = deactivatePopoverMenu ? () => {} : onClickLabel;
  const menuClassName = deactivatePopoverMenu ? '' : classes.label;
  if (isOperatorNil) {
    return (
      <>
        <strong
          className={menuClassName}
          onClick={onCLick}
        >
          {label}
        </strong>{' '}
        <span>
          {filterOperator === 'nil' ? t_i18n('is empty') : t_i18n('is not empty')}
        </span>
      </>
    );
  }
  const filterDefinition = useFilterDefinition(filterKey, entityTypes);
  const values = filterValues.map((id) => {
    const isLocalModeSwitchable = isReadWriteFilter
      && handleSwitchLocalMode
      && !filtersRestrictions?.preventLocalModeSwitchingFor?.includes(filterKey)
      && isFilterEditable(filtersRestrictions, filterKey, filterValues);
    const operatorClassName = isLocalModeSwitchable ? classes.inlineOperator : classes.inlineOperatorReadOnly;
    const operatorOnClick = isLocalModeSwitchable ? () => handleSwitchLocalMode(currentFilter) : undefined;
    return (
      <Fragment key={id}>
        <FilterValuesContent
          redirection={tooltip ? false : redirection}
          isFilterTooltip={!!tooltip}
          filterKey={filterKey}
          id={id}
          value={filtersRepresentativesMap.get(id) ? filtersRepresentativesMap.get(id)?.value : id}
          filterDefinition={filterDefinition}
        />
        {filterKey !== 'regardingOf' && last(filterValues) !== id && (
          <div
            className={operatorClassName}
            onClick={operatorOnClick}
          >
            {t_i18n((currentFilter.mode ?? 'or').toUpperCase())}
          </div>
        )}
      </Fragment>
    );
  });

  if (filterKey === 'regardingOf') {
    const sortedFilterValues = [...filterValues].sort((a, b) => -a.key.localeCompare(b.key)); // display type first, then id

    return (
      <>
        <strong
          className={menuClassName}
          onClick={onCLick}
        >
          {label}
        </strong>{' '}
        <Box sx={{ display: 'flex', flexDirection: 'row', overflow: 'hidden' }}>
          {sortedFilterValues
            .map((val) => {
              const subKey = val.key;
              const keyLabel = (
                <>
                  {truncate(t_i18n(subKey), 20)}
                  <>&nbsp;=</>
                </>
              );
              return (
                <Fragment key={val.key}>
                  <Tooltip
                    title={
                      <FilterValues
                        label={keyLabel}
                        tooltip={true}
                        currentFilter={val}
                        filtersRepresentativesMap={filtersRepresentativesMap}
                      />
                    }
                  >
                    <Box
                      sx={{
                        padding: '0 4px',
                        display: 'flex',
                      }}
                    >
                      <Chip
                        label={
                          <FilterValues
                            label={keyLabel}
                            tooltip={false}
                            currentFilter={val}
                            filtersRepresentativesMap={filtersRepresentativesMap}
                            redirection
                            noLabelDisplay={true}
                          />
                        }
                        color={chipColor}
                      />
                    </Box>
                  </Tooltip>
                </Fragment>
              );
            })
          }
        </Box>
      </>
    );
  }
  if (noLabelDisplay) {
    return (
      <>{values}</>
    );
  }
  return (
    <>
      <strong
        className={menuClassName}
        onClick={onCLick}
      >
        {label}
      </strong>{' '}
      {values}
    </>
  );
};

export default FilterValues;
