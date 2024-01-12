import React, { Fragment, FunctionComponent } from 'react';
import { last } from 'ramda';
import makeStyles from '@mui/styles/makeStyles';
import Tooltip from '@mui/material/Tooltip';
import Box from '@mui/material/Box';
import Chip from '@mui/material/Chip';
import { ChipOwnProps } from '@mui/material/Chip/Chip';
import { useFormatter } from '../i18n';
import type { Theme } from '../Theme';
import { Filter } from '../../utils/filters/filtersUtils';
import { handleFilterHelpers } from '../../utils/hooks/useLocalStorage';
import { truncate } from '../../utils/String';
import FilterValuesContent from '../FilterValuesContent';

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
  filtersRepresentativesMap: Map<string, string | null>;
  redirection?: boolean;
  handleSwitchLocalMode?: (filter: Filter) => void;
  onClickLabel?: (event: React.MouseEvent<HTMLButtonElement>) => void;
  helpers?: handleFilterHelpers;
  isReadWriteFilter?: boolean;
  chipColor?: ChipOwnProps['color'];
  noLabelDisplay?: boolean;
}

const FilterValues: FunctionComponent<FilterValuesProps> = ({
  label,
  tooltip,
  currentFilter,
  filtersRepresentativesMap,
  redirection,
  handleSwitchLocalMode,
  onClickLabel,
  helpers,
  isReadWriteFilter,
  chipColor,
  noLabelDisplay,
}) => {
  const { t } = useFormatter();
  const filterKey = currentFilter.key;
  const filterOperator = currentFilter.operator;
  const filterValues = currentFilter.values;
  const isOperatorNil = ['nil', 'not_nil'].includes(filterOperator ?? 'eq');
  const classes = useStyles();
  const deactivatePopoverMenu = !helpers;
  const onCLick = deactivatePopoverMenu ? () => {} : onClickLabel;
  if (isOperatorNil) {
    return (
      <>
        <strong
          className={deactivatePopoverMenu ? '' : classes.label}
          onClick={onCLick}
        >
          {label}
        </strong>{' '}
        <span>
          {filterOperator === 'nil' ? t('is empty') : t('is not empty')}
        </span>
      </>
    );
  }
  const values = filterValues.map((id) => {
    const operatorClassName = (isReadWriteFilter && handleSwitchLocalMode) ? classes.inlineOperator : classes.inlineOperatorReadOnly;
    const operatorOnClick = (isReadWriteFilter && handleSwitchLocalMode) ? () => handleSwitchLocalMode(currentFilter) : undefined;
    return (
      <Fragment key={id}>
        <FilterValuesContent
          redirection={tooltip ? false : redirection}
          isFilterTooltip={!!tooltip}
          filterKey={filterKey}
          id={id}
          value={filtersRepresentativesMap.get(id) ?? id}
        />
        {filterKey !== 'regardingOf' && last(filterValues) !== id && (
          <div
            className={operatorClassName}
            onClick={operatorOnClick}
          >
            {t((currentFilter.mode ?? 'or').toUpperCase())}
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
          className={deactivatePopoverMenu ? '' : classes.label}
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
                  {truncate(t(subKey), 20)}
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
        className={deactivatePopoverMenu ? '' : classes.label}
        onClick={onCLick}
      >
        {label}
      </strong>{' '}
      {values}
    </>
  );
};

export default FilterValues;
