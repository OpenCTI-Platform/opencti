import React, { FunctionComponent } from 'react';
import ToggleButton from '@mui/material/ToggleButton';
import { NotificationsOutlined } from '@mui/icons-material';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import {
  StixCoreObjectQuickSubscriptionContentPaginationQuery,
  TriggerFilter,
} from './__generated__/StixCoreObjectQuickSubscriptionContentPaginationQuery.graphql';
import StixCoreObjectQuickSubscriptionContent, {
  stixCoreObjectQuickSubscriptionContentQuery,
} from './StixCoreObjectQuickSubscriptionContent';

interface StixCoreObjectQuickSubscriptionProps {
  instanceId: string;
  instanceName: string;
}

const StixCoreObjectQuickSubscription: FunctionComponent<
StixCoreObjectQuickSubscriptionProps
> = ({ instanceId, instanceName }) => {
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
    <>
      {queryRef && (
        <React.Suspense
          fallback={
            <ToggleButton
              value="quick-subscription"
              size="small"
              style={{ marginRight: 3 }}
              disabled={true}
            >
              <NotificationsOutlined fontSize="small" />
            </ToggleButton>
          }
        >
          <StixCoreObjectQuickSubscriptionContent
            queryRef={queryRef}
            paginationOptions={paginationOptions}
            instanceId={instanceId}
            instanceName={instanceName}
          />
        </React.Suspense>
      )}
    </>
  );
};

export default StixCoreObjectQuickSubscription;
