import * as R from 'ramda';
import Chip from '@mui/material/Chip';
import React from 'react';
import makeStyles from '@mui/styles/makeStyles';
import { truncate } from '../utils/String';
import { useFormatter } from './i18n';

const useStyles = makeStyles(() => ({
  filters: {
    marginTop: 20,
  },
}));

const FilterCard = ({ filters, handleRemoveFilter }) => {
  const classes = useStyles();
  const { t } = useFormatter();
  return <>
    <div className="clearfix" />
    <div className={classes.filters}>
      {R.map((currentFilter) => {
        const label = `${truncate(t(`filter_${currentFilter[0]}`), 20)}`;
        const labelValues = (
          <span>
                 {R.map(
                   (n) => (
                     <span key={n.value}>
                       {n.value && n.value.length > 0 ? truncate(n.value, 15) : t('No label')}{' '}
                       {R.last(currentFilter[1]).value !== n.value && (<code>OR</code>)}{' '}
                     </span>
                   ),
                   currentFilter[1],
                 )}
              </span>
        );
        return (
          <span key={currentFilter[0]}>
                <Chip classes={{ root: classes.filter }}
                      label={<div><strong>{label}</strong>: {labelValues}</div>}
                      onDelete={() => handleRemoveFilter && handleRemoveFilter(currentFilter[0])} />
            {R.last(R.toPairs(filters))[0] !== currentFilter[0] && (
              <Chip classes={{ root: classes.operator }} label={t('AND')} />
            )}
              </span>
        );
      }, R.toPairs(filters))}
    </div>
  <div className="clearfix" />
  </>;
};

export default FilterCard;
