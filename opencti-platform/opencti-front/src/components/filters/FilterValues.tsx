import React, { Fragment, FunctionComponent } from 'react';
import { last } from 'ramda';
import makeStyles from '@mui/styles/makeStyles';
import { useFormatter } from '../i18n';
import FilterIconButtonContent from '../FilterIconButtonContent';
import type { Theme } from '../Theme';
import { Filter, filtersUsedAsApiParameters } from '../../utils/filters/filtersUtils';
import { handleFilterHelpers, UseLocalStorageHelpers } from '../../utils/hooks/useLocalStorage';

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
}) => {
  const { t } = useFormatter();
  const filterKey = currentFilter.key;
  const filterOperator = currentFilter.operator;
  const filterValues = currentFilter.values;
  const isOperatorNil = ['nil', 'not_nil'].includes(filterOperator);
  const classes = useStyles();
  const deactivatePopoverMenu = !helpers;
  const onCLick = deactivatePopoverMenu ? () => {} : onClickLabel;
  const isFiltersUsedAsApiParameters = filtersUsedAsApiParameters.includes(filterKey);
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
    return (
      <Fragment key={id}>
        {filtersRepresentativesMap.has(id) && (
          <FilterIconButtonContent
            redirection={tooltip ? false : redirection}
            isFilterTooltip={!!tooltip}
            filterKey={filterKey}
            id={id}
            value={filtersRepresentativesMap.get(id)}
          />
        )}
        {last(filterValues) !== id && (
          <div
            className={
              (isReadWriteFilter && !isFiltersUsedAsApiParameters)
                ? classes.inlineOperator
                : classes.inlineOperatorReadOnly
            }
            onClick={ () => {
              if (isReadWriteFilter && !isFiltersUsedAsApiParameters) {
                if (helpers) {
                  helpers.handleSwitchLocalMode(currentFilter);
                } else {
                  handleSwitchLocalMode?.(currentFilter);
                }
              }
            }}
          >
            {t((currentFilter.mode ?? 'or').toUpperCase())}
          </div>
        )}
      </Fragment>
    );
  });

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
