import React from 'react';
import Typography from '@mui/material/Typography';
import { useFormatter } from '../../../../components/i18n';
import StixCoreRelationshipHistoryLines, { stixCoreRelationshipHistoryLinesQuery } from './StixCoreRelationshipHistoryLines';
import CardTitle from '../../../../components/common/card/CardTitle';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import useAuth from '../../../../utils/hooks/useAuth';

const StixCoreRelationshipLatestHistory = ({ stixCoreRelationshipId }) => {
  const { t_i18n } = useFormatter();
  const { tz, locale, unitSystem } = useAuth();
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
    tz,
    locale: locale,
    unit_system: unitSystem,
  };
  const queryRef = useQueryLoading(
    stixCoreRelationshipHistoryLinesQuery,
    paginationOptions,
  );

  const Fallback = (
    <>
      <CardTitle>{t_i18n('Most recent history')}</CardTitle>
      <div />
    </>
  );

  return (
    <div className="break">
      <Typography variant="h4" gutterBottom={true}>
        {t_i18n('Most recent history')}
      </Typography>
      {queryRef && (
        <React.Suspense fallback={Fallback}>
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
