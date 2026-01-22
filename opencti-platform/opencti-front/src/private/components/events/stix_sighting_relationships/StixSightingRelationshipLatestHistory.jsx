import React from 'react';
import Typography from '@mui/material/Typography';
import StixSightingRelationshipHistoryLines, { stixCoreObjectHistoryLinesQuery } from './StixSightingRelationshipHistoryLines';
import { useFormatter } from 'src/components/i18n';
import useQueryLoading from 'src/utils/hooks/useQueryLoading';

const StixSightingRelationshipLatestHistory = ({ stixSightingRelationshipId }) => {
  const { t_i18n } = useFormatter();
  const paginationOptions = {
    filters: {
      mode: 'and',
      filters: [
        { key: 'context_data.id', values: [stixSightingRelationshipId] },
        { key: 'event_type', values: ['mutation', 'create', 'update', 'delete', 'merge'] },
      ],
      filterGroups: [],
    },
    first: 6,
    orderBy: 'timestamp',
    orderMode: 'desc',
  };
  const queryRef = useQueryLoading(
    stixCoreObjectHistoryLinesQuery,
    { count: 25, ...paginationOptions },
  );
  return (
    <>
      <Typography variant="h4" gutterBottom={true}>
        {t_i18n('Most recent history')}
      </Typography>
      {queryRef && (
        <React.Suspense fallback={<div />}>
          <StixSightingRelationshipHistoryLines
            stixSightingRelationshipId={stixSightingRelationshipId}
            queryRef={queryRef}
            isRelationLog={false}
            paginationOptions={paginationOptions}
          />
        </React.Suspense>
      )
      }
    </>
  );
};

export default StixSightingRelationshipLatestHistory;
