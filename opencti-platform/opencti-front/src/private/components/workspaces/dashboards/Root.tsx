import { Suspense } from 'react';
import { useParams } from 'react-router-dom';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import Dashboard from './Dashboard';
import Loader from '../../../../components/Loader';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { RootDashboardQuery } from './__generated__/RootDashboardQuery.graphql';

const dashboardQuery = graphql`
  query RootDashboardQuery($id: String!) {
    workspace(id: $id) {
      ...Dashboard_workspace
    }
  }
`;

interface RootDashboardComponentProps {
  queryRef: PreloadedQuery<RootDashboardQuery>;
}

const RootDashboardComponent = ({ queryRef }: RootDashboardComponentProps) => {
  const { workspace } = usePreloadedQuery(dashboardQuery, queryRef);
  if (!workspace) return <ErrorNotFound />;

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
      <Dashboard data={workspace} />
    </div>
  );
};

const RootDashboard = () => {
  const { workspaceId } = useParams();
  if (!workspaceId) return <ErrorNotFound />;

  const queryRef = useQueryLoading<RootDashboardQuery>(
    dashboardQuery,
    { id: workspaceId },
  );

  return (
    <Suspense fallback={<Loader />}>
      {queryRef && <RootDashboardComponent queryRef={queryRef} />}
    </Suspense>
  );
};

export default RootDashboard;
