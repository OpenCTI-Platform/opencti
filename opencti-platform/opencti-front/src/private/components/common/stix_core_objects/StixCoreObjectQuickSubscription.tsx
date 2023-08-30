import React, { FunctionComponent } from 'react';
import ToggleButton from '@mui/material/ToggleButton';
import { NotificationsOutlined } from '@mui/icons-material';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import {
  StixCoreObjectQuickSubscriptionContentPaginationQuery,
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
    filters: {
      mode: 'and',
      filterGroups: [],
      filters: [
        {
          key: ['filters'],
          values: [instanceId],
          operator: 'match',
          mode: 'or',
        },
        {
          key: ['instance_trigger'],
          values: [true.toString()],
          operator: 'match',
          mode: 'or',
        },
      ],
    },
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
