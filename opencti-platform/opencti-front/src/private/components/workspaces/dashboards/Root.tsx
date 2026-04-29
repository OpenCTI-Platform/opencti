import { Suspense, useEffect } from 'react';
import { useParams } from 'react-router-dom';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import CustomDashboard from './CustomDashboard';
import Loader from '../../../../components/Loader';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { RootCustomDashboardQuery } from './__generated__/RootCustomDashboardQuery.graphql';
import { requestSubscription } from '../../../../relay/environment';

const subscription = graphql`
  subscription RootCustomDashboardSubscription($id: ID!) {
    workspace(id: $id) {
      ...CustomDashboard_workspace
    }
  }
`;

const dashboardQuery = graphql`
  query RootCustomDashboardQuery($id: String!) {
    workspace(id: $id) {
      id
      ...CustomDashboard_workspace
    }
  }
`;

interface RootCustomDashboardComponentProps {
  queryRef: PreloadedQuery<RootCustomDashboardQuery>;
}

const RootCustomDashboardComponent = ({ queryRef }: RootCustomDashboardComponentProps) => {
  const { workspace } = usePreloadedQuery(dashboardQuery, queryRef);
  if (!workspace) return <ErrorNotFound />;

  useEffect(() => {
    const sub = requestSubscription({
      subscription,
      variables: { id: workspace.id },
    });
    return () => sub.dispose();
  }, [workspace.id]);

  return (
    <div
      data-testid="dashboard-details-page"
      style={{
        overflow: 'auto',
        marginRight: -20,
        paddingRight: 20,
        paddingTop: 5,
        height: '100%',
      }}
    >
      <CustomDashboard data={workspace} />
    </div>
  );
};

const RootCustomDashboard = () => {
  const { workspaceId } = useParams();
  if (!workspaceId) return <ErrorNotFound />;

  const queryRef = useQueryLoading<RootCustomDashboardQuery>(
    dashboardQuery,
    { id: workspaceId },
  );

  return (
    <Suspense fallback={<Loader />}>
      {queryRef && <RootCustomDashboardComponent queryRef={queryRef} />}
    </Suspense>
  );
};

export default RootCustomDashboard;
