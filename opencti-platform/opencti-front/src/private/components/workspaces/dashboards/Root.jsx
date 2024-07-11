import React, { useEffect, useState } from 'react';
import * as PropTypes from 'prop-types';
import { Route, Routes, useParams } from 'react-router-dom';
import { graphql } from 'react-relay';
import { QueryRenderer, requestSubscription } from '../../../../relay/environment';
import Dashboard from './Dashboard';
import Loader from '../../../../components/Loader';
import ErrorNotFound from '../../../../components/ErrorNotFound';

const subscription = graphql`
  subscription RootDashboardSubscription($id: ID!) {
    workspace(id: $id) {
      ...Dashboard_workspace
    }
  }
`;

const dashboardQuery = graphql`
  query RootDashboardQuery($id: String!) {
    settings {
      platform_banner_text
      platform_banner_level
    }
    workspace(id: $id) {
      id
      name
      type
      ...Dashboard_workspace
    }
  }
`;

const RootDashboard = () => {
  const { workspaceId } = useParams();
  const [workspace, setWorkspace] = useState(null);
  const [settings, setSettings] = useState(null);

  useEffect(() => {
    const sub = requestSubscription({
      subscription,
      variables: { id: workspaceId },
    });

    return () => {
      sub.dispose();
    };
  }, [workspaceId]);

  return (
    <div data-testid="dashboard-details-page">
      <QueryRenderer
        query={dashboardQuery}
        variables={{ id: workspaceId }}
        render={({ props }) => {
          if (props) {
            if (props.workspace) {
              setWorkspace(props.workspace);
              setSettings(props.settings);
            }
            return <Loader/>;
          }
          return <ErrorNotFound/>;
        }}
      />
      {workspace && (
        <Routes>
          <Route
            path="/"
            element={<Dashboard workspace={workspace} settings={settings}/>}
          />
        </Routes>
      )}
    </div>
  );
};

RootDashboard.propTypes = {
  children: PropTypes.node,
  params: PropTypes.object,
};

export default RootDashboard;
