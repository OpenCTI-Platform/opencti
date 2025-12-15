import React from 'react';
import Typography from '@mui/material/Typography';
import { useFormatter } from '../../../../components/i18n';
import StixCoreRelationshipHistoryLines, { stixCoreRelationshipHistoryLinesQuery } from './StixCoreRelationshipHistoryLines';
import useQueryLoading from 'src/utils/hooks/useQueryLoading';

const StixCoreRelationshipLatestHistory = ({ stixCoreRelationshipId }) => {
  const { t_i18n } = useFormatter();
  const paginationOptions = {
    filters: {
      mode: 'and',
      filterGroups: [],
      filters: [
        { key: 'context_data.id', values: [stixCoreRelationshipId] },
        { key: 'event_type', values: ['mutation', 'create', 'update', 'delete', 'merge'] },
      ],
    },
    first: 7,
    orderBy: 'timestamp',
    orderMode: 'desc',
  };
  const queryRef = useQueryLoading(
    stixCoreRelationshipHistoryLinesQuery,
    paginationOptions,
  );
  return (
    <div className="break">
      <Typography variant="h4" gutterBottom={true}>
        {t_i18n('Most recent history')}
      </Typography>
      {queryRef && (
        <React.Suspense fallback={<div />}>
          <StixCoreRelationshipHistoryLines
            stixCoreRelationshipId={stixCoreRelationshipId}
            queryRef={queryRef}
            isRelationLog={false}
            paginationOptions={paginationOptions}
          />
        </React.Suspense>
      )}
    </div>
  );
};

export default StixCoreRelationshipLatestHistory;
