import { Suspense, useMemo, useState } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { ErrorBoundary } from '@components/Error';
import { MESSAGING$ } from 'src/relay/environment';
import Loader from '../../../components/Loader';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import useDashboard from '../../../components/dashboard/useDashboard';
import DashboardContent from '../../../components/dashboard/DashboardContent';
import { CustomView_Query } from './__generated__/CustomView_Query.graphql';
import { DashboardConfig } from 'src/components/dashboard/dashboard-types';
import DashboardTimeFilters from 'src/components/dashboard/DashboardTimeFilters';
import { Stack } from '@mui/material';

const customViewQuery = graphql`
  query CustomView_Query($id: ID!) {
    customView(id: $id) {
      id
      manifest
    }
  }
`;

interface CustomViewComponentProps {
  queryRef: PreloadedQuery<CustomView_Query>;
  entityId: string;
  entityType: string;
}

const CustomViewComponent = ({ queryRef, entityId, entityType }: CustomViewComponentProps) => {
  const { customView } = usePreloadedQuery(customViewQuery, queryRef);
  if (!customView) {
    MESSAGING$.notifyError('Failed to load custom view');
    return null;
  }
  if (!customView?.manifest) {
    // Admin hasn't save the dashboard once yet
    return null;
  }

  const helpers = useDashboard({ entity: customView });

  const [dateOverride, setDateOverride] = useState<DashboardConfig | null>(null);
  const effectiveConfig = dateOverride ?? helpers.config;

  const handleDateChange = (
    type: 'startDate' | 'endDate' | 'relativeDate',
    value: string | null,
  ) => {
    setDateOverride((prev) => {
      const base = prev ?? helpers.config;
      const normalizedValue = value === 'none' ? null : value;

      let nextConfig: DashboardConfig = {
        startDate: base?.startDate ?? null,
        endDate: base?.endDate ?? null,
        relativeDate: base?.relativeDate ?? null,
        [type]: normalizedValue,
      };

      if (type === 'relativeDate' && value !== 'none') {
        nextConfig = {
          ...nextConfig,
          startDate: null,
          endDate: null,
        };
      }

      return nextConfig;
    });
  };

  const host = useMemo(() => ({
    kind: 'custom-view' as const,
    customViewTargetEntityType: entityType,
    customViewTargetEntityId: entityId,
  }), [entityType]);

  return (
    <Stack gap={2}>
      <DashboardTimeFilters
        config={effectiveConfig}
        handleDateChange={handleDateChange}
      />
      <DashboardContent
        helpers={{ ...helpers, config: effectiveConfig }}
        isEditable={false}
        entity={customView}
        host={host}
      />
    </Stack>
  );
};

export interface CustomViewProps {
  customViewId: string;
  entityId: string;
  entityType: string;
}

export const CustomView = ({ customViewId, entityId, entityType }: CustomViewProps) => {
  const queryRef = useQueryLoading<CustomView_Query>(
    customViewQuery,
    { id: customViewId },
  );

  return (
    <ErrorBoundary>
      <Suspense fallback={<Loader />}>
        {queryRef && <CustomViewComponent queryRef={queryRef} entityId={entityId} entityType={entityType} />}
      </Suspense>
    </ErrorBoundary>
  );
};

export default CustomView;
