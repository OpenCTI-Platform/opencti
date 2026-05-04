import { Suspense } from 'react';
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
}

const CustomViewComponent = ({ queryRef }: CustomViewComponentProps) => {
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
  return <DashboardContent helpers={helpers} isEditable={false} entity={customView} />;
};

export interface CustomViewProps {
  customViewId: string;
}

export const CustomView = ({ customViewId }: CustomViewProps) => {
  const queryRef = useQueryLoading<CustomView_Query>(
    customViewQuery,
    { id: customViewId },
  );

  return (
    <ErrorBoundary>
      <Suspense fallback={<Loader />}>
        {queryRef && <CustomViewComponent queryRef={queryRef} />}
      </Suspense>
    </ErrorBoundary>
  );
};

export default CustomView;
