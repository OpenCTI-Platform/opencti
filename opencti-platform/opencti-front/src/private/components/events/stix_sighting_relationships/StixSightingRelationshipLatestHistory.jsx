import React from 'react';
import StixSightingRelationshipHistoryLines, { stixCoreObjectHistoryLinesQuery } from './StixSightingRelationshipHistoryLines';
import useQueryLoading from 'src/utils/hooks/useQueryLoading';

const StixSightingRelationshipLatestHistory = ({ stixSightingRelationshipId }) => {
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
      {queryRef && (
        <React.Suspense fallback={<div />}>
          <StixSightingRelationshipHistoryLines
            stixSightingRelationshipId={stixSightingRelationshipId}
            queryRef={queryRef}
            isRelationLog={false}
            paginationOptions={paginationOptions}
          />
        </React.Suspense>
      )}
    </>
  );
};

export default StixSightingRelationshipLatestHistory;
