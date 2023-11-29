import React from 'react';
import Chip from '@mui/material/Chip';
import makeStyles from '@mui/styles/makeStyles';
import Tooltip from '@mui/material/Tooltip';
import { InformationOutline } from 'mdi-material-ui';
import { FilterGroup, GqlFilterGroup } from '../utils/filters/filtersUtils';
import { filterIconButtonContentQuery } from './FilterIconButtonContent';
import useQueryLoading from '../utils/hooks/useQueryLoading';
import TaskFilterValue from './TaskFilterValue';
import Loader from './Loader';
import { FilterIconButtonContentQuery } from './__generated__/FilterIconButtonContentQuery.graphql';
import { Theme } from './Theme';
import { useFormatter } from './i18n';

const useStyles = makeStyles<Theme>(() => ({
  filter: {
    marginRight: 10,
    marginTop: 10,
    lineHeight: 32,
    marginBottom: 10,
  },
  chipLabel: {
    lineHeight: '32px',
    maxWidth: 400,
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    display: 'flex',
    alignItems: 'center',
    gap: '4px',
  },
}));

const TasksFilterValueContainer = ({ filters, isFiltersInOldFormat }: { filters: FilterGroup, isFiltersInOldFormat?: boolean }) => {
  const classes = useStyles();
  const { t } = useFormatter();
  const queryRef = useQueryLoading<FilterIconButtonContentQuery>(
    filterIconButtonContentQuery,
    { filters: filters as unknown as GqlFilterGroup },
  );
  return (
    <>
      {queryRef && (
        <React.Suspense fallback={<Loader />}>
          <TaskFilterValue
            filters={filters}
            queryRef={queryRef}
          />
        </React.Suspense>
      )}
      {isFiltersInOldFormat
        && <Chip
          classes={{ root: classes.filter, label: classes.chipLabel }}
          color={'warning'}
          label={
            <>
              {t('deprecated format')}
              <Tooltip
                title={t('Filters are stored in a deprecated format (before 5.12)')}
              >
                <InformationOutline
                  fontSize="small"
                  color="secondary"
                  style={{ cursor: 'default' }}
                />
              </Tooltip>
            </>
          }
        />
      }
    </>
  );
};

export default TasksFilterValueContainer;
