import { Suspense } from 'react';
import { useFormatter } from '../../../../components/i18n';
import StixCoreRelationshipHistoryLines, { stixCoreRelationshipHistoryLinesQuery } from './StixCoreRelationshipHistoryLines';
import CardTitle from '../../../../components/common/card/CardTitle';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';

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

  const Fallback = (
    <>
      <CardTitle>{t_i18n('Most recent history')}</CardTitle>
      <div />
    </>
  );

  return (
    <div className="break">
      {queryRef && (
        <Suspense fallback={Fallback}>
          <StixCoreRelationshipHistoryLines
            stixCoreRelationshipId={stixCoreRelationshipId}
            queryRef={queryRef}
            isRelationLog={false}
            paginationOptions={paginationOptions}
          />
        </Suspense>
      )}
    </div>
  );
};

export default StixCoreRelationshipLatestHistory;
