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
  },
  filter2: {
    margin: '0 10px 10px 0',
  },
  filter3: {
    fontSize: 12,
    lineHeight: '12px',
    height: 20,
    marginRight: 7,
    borderRadius: 10,
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
}));

interface FilterIconButtonProps {
  filters: Filters,
  handleRemoveFilter?: (key: string) => void,
  classNameNumber?: number,
  styleNumber?: number,
  dataColumns?: DataColumns,
  disabledPossible?: boolean,
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

  return <div
    className={finalClassName}
    style={dataColumns ? { width: dataColumns.filters.width } : undefined}
  >
    {
      toPairs(filters).map((currentFilter) => {
        const label = `${truncate(t(`filter_${currentFilter[0]}`), 20)}`;
        const negative = currentFilter[0].endsWith('not_eq');
        const localFilterMode = negative ? t('AND') : t('OR');
        const values = (
        <span>
        {currentFilter[1].map(
          (n) => (
            <span key={n.value as string}>
              {n.value && (n.value as string).length > 0
                ? truncate(n.value, 15)
                : t('No label')}{' '}
              {last(currentFilter[1])?.value !== n.value && (
                <Chip
                  label={localFilterMode}
                />
              )}{' '}
            </span>
          ),
        )}
      </span>
        );
        return (
        <span key={currentFilter[0]}>
          <Chip
          classes={{ root: classFilter }}
          label={
            <div>
              <strong>{label}</strong>: {values}
            </div>
          }
          disabled={disabledPossible ? Object.keys(filters).length === 1 : undefined}
          onDelete={handleRemoveFilter ? () => handleRemoveFilter(currentFilter[0]) : undefined}
        />
          {last(toPairs(filters))?.[0] !== currentFilter[0] && (
            <Chip
              classes={{ root: classOperator }}
              label={t('AND')}
            />
          )}
      </span>
        );
      })
    }
  </div>;
};

export default FilterIconButton;
