import React, { FunctionComponent } from 'react';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import {
  StixCoreObjectQuickSubscriptionContentPaginationQuery, TriggerFilter,
} from './__generated__/StixCoreObjectQuickSubscriptionContentPaginationQuery.graphql';
import StixCoreObjectQuickSubscriptionContent, {
  stixCoreObjectQuickSubscriptionContentQuery,
} from './StixCoreObjectQuickSubscriptionContent';

interface StixCoreObjectQuickSubscriptionProps {
  instanceId: string,
  instanceName: string,
}

const StixCoreObjectQuickSubscription: FunctionComponent<StixCoreObjectQuickSubscriptionProps> = ({ instanceId, instanceName }) => {
  const paginationOptions = {
    filters: [
      {
        key: ['filters'] as TriggerFilter[],
        values: [instanceId],
        operator: 'match',
      },
      {
        key: ['instance_trigger'] as TriggerFilter[],
        values: [true.toString()],
        operator: 'match',
      },
    ],
  };
  const queryRef = useQueryLoading<StixCoreObjectQuickSubscriptionContentPaginationQuery>(
    stixCoreObjectQuickSubscriptionContentQuery,
    paginationOptions,
  );

  return (
    <div>
      {queryRef
        && <React.Suspense fallback={<Loader variant={LoaderVariant.inElement}/>}>
          <StixCoreObjectQuickSubscriptionContent queryRef={queryRef} paginationOptions={paginationOptions} instanceId={instanceId} instanceName={instanceName} />
        </React.Suspense>
      }
    </div>
  );
};

export default StixCoreObjectQuickSubscription;
