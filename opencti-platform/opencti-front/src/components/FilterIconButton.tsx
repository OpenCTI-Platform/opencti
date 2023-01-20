import { last, toPairs } from 'ramda';
import Chip from '@mui/material/Chip';
import React, { FunctionComponent } from 'react';
import makeStyles from '@mui/styles/makeStyles';
import { truncate } from '../utils/String';
import { DataColumns, Filters } from './list_lines';
import { useFormatter } from './i18n';
import { Theme } from './Theme';

const useStyles = makeStyles<Theme>((theme) => ({
  filters1: {
    float: 'left',
    margin: '5px 0 0 10px',
  },
  filters2: {
    marginTop: 20,
  },
  filters3: {
    height: 20,
    fontSize: 13,
    float: 'left',
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    paddingRight: 5,
  },
  filters4: {
    margin: '0 0 20px 0',
  },
  filters5: {
    float: 'left',
    margin: '2px 0 0 10px',
  },
  filters6: {
    float: 'left',
    margin: '2px 0 0 15px',
  },
  filter1: {
    marginRight: 10,
    lineHeight: 32,
  },
  filter2: {
    margin: '0 10px 10px 0',
    lineHeight: 32,
  },
  filter3: {
    fontSize: 12,
    height: 20,
    marginRight: 7,
    borderRadius: 10,
    lineHeight: 32,
  },
  operator1: {
    fontFamily: 'Consolas, monaco, monospace',
    backgroundColor: theme.palette.background.accent,
    marginRight: 10,
  },
  operator2: {
    fontFamily: 'Consolas, monaco, monospace',
    backgroundColor: theme.palette.background.accent,
    margin: '0 10px 10px 0',
  },
  operator3: {
    fontFamily: 'Consolas, monaco, monospace',
    backgroundColor: theme.palette.background.accent,
    height: 20,
    marginRight: 10,
  },
  inlineOperator: {
    display: 'inline-block',
    height: '100%',
    borderRadius: 0,
    margin: '0 5px 0 5px',
    padding: '0 5px 0 5px',
    backgroundColor: 'rgba(255, 255, 255, .1)',
    fontFamily: 'Consolas, monaco, monospace',
  },
  chipLabel: {
    lineHeight: '32px',
  },
}));

interface FilterIconButtonProps {
  filters: Filters<{ id: string; value: string }[]>;
  handleRemoveFilter?: (key: string) => void;
  classNameNumber?: number;
  styleNumber?: number;
  dataColumns?: DataColumns;
  disabledPossible?: boolean;
}

const FilterIconButton: FunctionComponent<FilterIconButtonProps> = ({
  filters,
  handleRemoveFilter,
  classNameNumber,
  styleNumber,
  dataColumns,
  disabledPossible,
}) => {
  const { t } = useFormatter();
  const classes = useStyles();

  let finalClassName = classes.filters1;
  if (classNameNumber === 2) {
    finalClassName = classes.filters2;
  } else if (classNameNumber === 3) {
    finalClassName = classes.filters3;
  } else if (classNameNumber === 4) {
    finalClassName = classes.filters4;
  } else if (classNameNumber === 5) {
    finalClassName = classes.filters5;
  } else if (classNameNumber === 6) {
    finalClassName = classes.filters6;
  }

  let classFilter = classes.filter1;
  let classOperator = classes.operator1;
  if (styleNumber === 2) {
    classFilter = classes.filter2;
    classOperator = classes.operator2;
  } else if (styleNumber === 3) {
    classFilter = classes.filter3;
    classOperator = classes.operator3;
  }

  const lastKey = last(toPairs(filters))?.[0];

  return (
    <div
      className={finalClassName}
      style={{ width: dataColumns?.filters.width }}
    >
      {toPairs(filters).map((currentFilter) => {
        const filterKey = currentFilter[0];
        const filterContent = currentFilter[1];
        const label = `${truncate(t(`filter_${filterKey}`), 20)}`;
        const negative = filterKey.endsWith('not_eq');
        const localFilterMode = negative ? t('AND') : t('OR');
        const values = (
          <span>
            {filterContent.map((n) => (
              <span key={n.value}>
                <span>
                  {n.value && n.value.length > 0
                    ? truncate(n.value, 15)
                    : t('No label')}{' '}
                </span>
                {last(filterContent)?.value !== n.value && (
                  <div className={classes.inlineOperator}>
                    {localFilterMode}
                  </div>
                )}{' '}
              </span>
            ))}
          </span>
        );
        return (
          <span key={filterKey}>
            <Chip
              classes={{ root: classFilter, label: classes.chipLabel }}
              label={
                <div>
                  <strong>{label}</strong>: {values}
                </div>
              }
              disabled={
                disabledPossible ? Object.keys(filters).length === 1 : undefined
              }
              onDelete={
                handleRemoveFilter
                  ? () => handleRemoveFilter?.(filterKey)
                  : undefined
              }
            />
            {lastKey !== filterKey && (
              <Chip classes={{ root: classOperator }} label={t('AND')} />
            )}
          </span>
        );
      })}
    </div>
  );
};

export default FilterIconButton;
