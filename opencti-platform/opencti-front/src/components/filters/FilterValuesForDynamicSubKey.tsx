import React, { Fragment } from 'react';
import Tooltip from '@mui/material/Tooltip';
import Box from '@mui/material/Box';
import Chip from '@mui/material/Chip';
import { ChipOwnProps } from '@mui/material/Chip/Chip';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { WarningOutlined } from '@mui/icons-material';
import TasksFilterValueContainer from '../TasksFilterValueContainer';
import { FilterGroup } from '../../utils/filters/filtersHelpers-types';
import { useFormatter } from '../i18n';
import useQueryLoading from '../../utils/hooks/useQueryLoading';
import Loader, { LoaderVariant } from '../Loader';
import { FilterValuesForDynamicSubKeyQuery } from './__generated__/FilterValuesForDynamicSubKeyQuery.graphql';
import { sanitizeFilterGroupKeysForBackend } from '../../utils/filters/filtersUtils';

// TODO, use MAX_RUNTIME_RESOLUTION_SIZE from backend
const MAX_NUMBER_DYNAMIC_IDS_RESULT = 5000;

export const filterValuesForDynamicSubKeyQuery = graphql`
  query FilterValuesForDynamicSubKeyQuery(
    $filters: FilterGroup
  ) {
    stixCoreObjectsNumber(
      filters: $filters
    ) {
      total
    }
  }
`;

interface FilterValuesForDynamicSubKeyContainerProps {
  queryRef: PreloadedQuery<FilterValuesForDynamicSubKeyQuery>;
  filterValue: FilterGroup;
  chipColor?: ChipOwnProps['color'];
}

const FilterValuesForDynamicSubKeyContainer = ({
  queryRef,
  filterValue,
  chipColor,
}: FilterValuesForDynamicSubKeyContainerProps) => {
  const { t_i18n } = useFormatter();
  const { stixCoreObjectsNumber } = usePreloadedQuery(filterValuesForDynamicSubKeyQuery, queryRef);
  const numberOfIdsTargeted = stixCoreObjectsNumber?.total ?? 0;
  const displayWarning = numberOfIdsTargeted > MAX_NUMBER_DYNAMIC_IDS_RESULT;

  return (
    <Fragment>
      <Tooltip
        title={
          <TasksFilterValueContainer
            filters={filterValue}
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
            label={t_i18n('Dynamic filter')}
            color={chipColor}
          />
        </Box>
      </Tooltip>
      {displayWarning && (
        <Tooltip title={
          t_i18n('All the results may not be displayed since the Dynamic filter targets too many entities.')
        }
        >
          <WarningOutlined
            color={'inherit'}
            style={{ fontSize: 20, color: '#f44336', margin: 5 }}
          />
        </Tooltip>
      )}
    </Fragment>
  );
};

interface FilterValuesForDynamicSubKeyProps {
  filterValue: FilterGroup,
  chipColor?: ChipOwnProps['color'];
}

const FilterValuesForDynamicSubKey = ({
  filterValue,
  chipColor,
}: FilterValuesForDynamicSubKeyProps) => {
  const queryRef = useQueryLoading<FilterValuesForDynamicSubKeyQuery>(
    filterValuesForDynamicSubKeyQuery,
    { filters: sanitizeFilterGroupKeysForBackend(filterValue) },
  );

  return (
    <>
      {queryRef && (
        <React.Suspense
          fallback={<Loader variant={LoaderVariant.inElement} />}
        >
          <FilterValuesForDynamicSubKeyContainer
            queryRef={queryRef}
            filterValue={filterValue}
            chipColor={chipColor}
          />
        </React.Suspense>
      )}
    </>
  );
};

export default FilterValuesForDynamicSubKey;
