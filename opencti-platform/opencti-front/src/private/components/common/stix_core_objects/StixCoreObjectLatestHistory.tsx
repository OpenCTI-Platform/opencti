import {
  StixCoreObjectHistoryLinesQuery,
  StixCoreObjectHistoryLinesQuery$variables,
} from '@components/common/stix_core_objects/__generated__/StixCoreObjectHistoryLinesQuery.graphql';
import React from 'react';
import { useFormatter } from '../../../../components/i18n';
import useAuth from '../../../../utils/hooks/useAuth';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import CardListSkeleton from '../CardListSkeleton';
import StixCoreObjectHistoryLines, { stixCoreObjectHistoryLinesQuery } from './StixCoreObjectHistoryLines';

type StixCoreObjectLatestHistoryProps = {
  stixCoreObjectId: string;
};

const StixCoreObjectLatestHistory = ({ stixCoreObjectId }: StixCoreObjectLatestHistoryProps) => {
  const { t_i18n } = useFormatter();
  const { tz, locale, unitSystem } = useAuth();

  const paginationOptions: StixCoreObjectHistoryLinesQuery$variables = {
    filters: {
      mode: 'and',
      filterGroups: [],
      filters: [
        { key: ['context_data.id'], values: [stixCoreObjectId] },
        {
          key: ['event_type'],
          values: ['mutation', 'create', 'update', 'delete', 'merge'],
        },
      ],
    },
    first: 7,
    orderBy: 'timestamp',
    orderMode: 'desc',
    tz,
    locale: locale,
    unit_system: unitSystem,
  };

  const queryRef = useQueryLoading<StixCoreObjectHistoryLinesQuery>(
    stixCoreObjectHistoryLinesQuery,
    paginationOptions,
  );

  return (
    <>
      {queryRef && (
        <React.Suspense
          fallback={<CardListSkeleton title={t_i18n('Most recent history')} />}
        >
          <StixCoreObjectHistoryLines
            title={t_i18n('Most recent history')}
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

export default StixCoreObjectLatestHistory;
