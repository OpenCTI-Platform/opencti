import React from 'react';
import StixSightingRelationshipHistoryLines, { stixCoreObjectHistoryLinesQuery } from './StixSightingRelationshipHistoryLines';
import useQueryLoading from 'src/utils/hooks/useQueryLoading';
import { StixSightingRelationshipHistoryLinesQuery, StixSightingRelationshipHistoryLinesQuery$variables } from './__generated__/StixSightingRelationshipHistoryLinesQuery.graphql';

interface StixSightingRelationshipLatestHistoryProps {
  stixSightingRelationshipId: string;
}

const StixSightingRelationshipLatestHistory = ({ stixSightingRelationshipId }: StixSightingRelationshipLatestHistoryProps) => {
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
  } as unknown as StixSightingRelationshipHistoryLinesQuery$variables;
  const queryRef = useQueryLoading<StixSightingRelationshipHistoryLinesQuery>(
    stixCoreObjectHistoryLinesQuery,
    { count: 25, ...paginationOptions },
  );
  return (
    <>
      {queryRef && (
        <React.Suspense fallback={<div />}>
          <StixSightingRelationshipHistoryLines
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
