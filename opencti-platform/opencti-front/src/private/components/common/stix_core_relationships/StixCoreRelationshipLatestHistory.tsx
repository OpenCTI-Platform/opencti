import React from 'react';
import { useFormatter } from '../../../../components/i18n';
import StixCoreRelationshipHistoryLines, { stixCoreRelationshipHistoryLinesQuery } from './StixCoreRelationshipHistoryLines';
import CardTitle from '../../../../components/common/card/CardTitle';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import useAuth from '../../../../utils/hooks/useAuth';
import { StixCoreRelationshipHistoryLinesQuery, StixCoreRelationshipHistoryLinesQuery$variables } from './__generated__/StixCoreRelationshipHistoryLinesQuery.graphql';

interface StixCoreRelationshipLatestHistoryProps {
  stixCoreRelationshipId: string;
}

const StixCoreRelationshipLatestHistory = ({ stixCoreRelationshipId }: StixCoreRelationshipLatestHistoryProps) => {
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
  } as unknown as StixCoreRelationshipHistoryLinesQuery$variables;
  const queryRef = useQueryLoading<StixCoreRelationshipHistoryLinesQuery>(
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
    <>
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
    </>
  );
};

export default StixCoreRelationshipLatestHistory;
