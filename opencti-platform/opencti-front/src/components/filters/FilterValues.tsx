import React, { Fragment, FunctionComponent } from 'react';
import { last } from 'ramda';
import Chip from '@mui/material/Chip';
import makeStyles from '@mui/styles/makeStyles';
import { useFormatter } from '../i18n';
import FilterIconButtonContent from '../FilterIconButtonContent';
import { Theme } from '../Theme';
import { Filter } from '../../utils/filters/filtersUtils';
import { UseLocalStorageHelpers } from '../../utils/hooks/useLocalStorage';

const useStyles = makeStyles<Theme>(() => ({
  inlineOperator: {
    display: 'inline-block',
    height: '100%',
    borderRadius: 0,
    margin: '0 5px 0 5px',
    padding: '0 5px 0 5px',
    backgroundColor: 'rgba(255, 255, 255, .1)',
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
  filtersRepresentativesMap: Map<string, string | null>
  redirection?: boolean;
  handleSwitchLocalMode?: (filter: Filter) => void;
  onClickLabel?: (event: React.MouseEvent<HTMLButtonElement>) => void;
  helpers?: UseLocalStorageHelpers
}

const FilterValues: FunctionComponent<FilterValuesProps> = (
  { label,
    tooltip,
    currentFilter,
    filtersRepresentativesMap,
    redirection,
    handleSwitchLocalMode,
    onClickLabel,
    helpers },
) => {
  const { t } = useFormatter();
  const filterKey = currentFilter.key;
  const filterOperator = currentFilter.operator;
  const filterValues = currentFilter.values;
  const isOperatorNil = ['nil', 'not_nil'].includes(filterOperator);

  const classes = useStyles();

  const deactivatePopoverMenu = !helpers;

  const onCLick = deactivatePopoverMenu ? () => {
  } : onClickLabel;

  if (isOperatorNil) {
    return <>
      <strong className={deactivatePopoverMenu ? '' : classes.label}
              onClick={onCLick}>{label}</strong> :<span>{filterOperator === 'nil' ? t('is null') : t('is not null')}</span>
    </>;
  }
  const values = filterValues.map((id) => {
    return (
      <Fragment key={id}>
        {filtersRepresentativesMap.has(id)
          && (<FilterIconButtonContent
            redirection={tooltip ? false : redirection}
            isFilterTooltip={!!tooltip}
            filterKey={filterKey}
            id={id}
            value={filtersRepresentativesMap.get(id)}
          ></FilterIconButtonContent>)
        }
        {last(filterValues) !== id && (
          <Chip
            className={classes.inlineOperator}
            label={t((currentFilter.mode ?? 'or').toUpperCase())}
            onClick={() => handleSwitchLocalMode?.(currentFilter)}
          />
        )}
      </Fragment>
    );
  });

  return <>
    <strong className={deactivatePopoverMenu ? '' : classes.label}
            onClick={onCLick}>{label}</strong> {values}
  </>;
};

export default FilterValues;
