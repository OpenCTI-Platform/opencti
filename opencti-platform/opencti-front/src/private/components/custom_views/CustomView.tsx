import { Suspense, useMemo } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import { ErrorBoundary } from '@components/Error';
import { MESSAGING$ } from '../../../relay/environment';
import Loader from '../../../components/Loader';
import useQueryLoading from '../../../utils/hooks/useQueryLoading';
import useDashboard from '../../../components/dashboard/useDashboard';
import DashboardContent from '../../../components/dashboard/DashboardContent';
import { CustomView_Query } from './__generated__/CustomView_Query.graphql';

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
  const host = useMemo(() => ({
    kind: 'custom-view' as const,
    customViewTargetEntityType: entityType,
    customViewTargetEntityId: entityId,
  }), [entityType]);
  return (
    <DashboardContent
      helpers={helpers}
      isEditable={false}
      entity={customView}
      host={host}
    />
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
