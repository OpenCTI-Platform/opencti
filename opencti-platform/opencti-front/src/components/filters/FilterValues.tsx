import React, { Fragment, FunctionComponent } from 'react';
import { last } from 'ramda';
import Chip from '@mui/material/Chip';
import makeStyles from '@mui/styles/makeStyles';
import { useLocation } from 'react-router-dom';
import { useFormatter } from '../i18n';
import FilterIconButtonContent from '../FilterIconButtonContent';
import { Theme } from '../Theme';
import { Filter } from '../../utils/filters/filtersUtils';

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
  label: string;
  tooltip?: boolean;
  currentFilter: Filter;
  filtersRepresentatives: ReadonlyArray<{
    readonly id: string;
    readonly value: string | null;
  }>;
  redirection?: boolean;
  handleSwitchLocalMode?: (filter: Filter) => void;
  onClickLabel?: (event: React.MouseEvent<HTMLButtonElement>) => void;
}

const FilterValues: FunctionComponent<FilterValuesProps> = ({ label, tooltip, currentFilter, filtersRepresentatives, redirection, handleSwitchLocalMode, onClickLabel }) => {
  const { t } = useFormatter();
  const location = useLocation();
  const filterKey = currentFilter.key;
  const filterOperator = currentFilter.operator;
  const filterValues = currentFilter.values;
  const isOperatorNil = ['nil', 'not_nil'].includes(filterOperator);
  const filtersRepresentativesMap = new Map(filtersRepresentatives.map((n) => [n.id, n.value]));
  const classes = useStyles();
  const deactivatePopoverMenu = location.pathname.includes('dashboard/data/sharing');

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
            onClick={onCLick}>{label}</strong> {filterValues.length > 0 && ':'} {values}
  </>;
};

export default FilterValues;
