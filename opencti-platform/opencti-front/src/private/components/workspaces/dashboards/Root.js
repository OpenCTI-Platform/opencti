import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Route, withRouter } from 'react-router-dom';
import graphql from 'babel-plugin-relay/macro';
import {
  QueryRenderer,
  requestSubscription,
} from '../../../../relay/environment';
import TopBar from '../../nav/TopBar';
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
    workspace(id: $id) {
      id
      name
      ...Dashboard_workspace
    }
  }
`;

class RootDashboard extends Component {
  constructor(props) {
    super(props);
    const {
      match: {
        params: { workspaceId },
      },
    } = props;
    this.sub = requestSubscription({
      subscription,
      variables: { id: workspaceId },
    });
  }

  componentWillUnmount() {
    this.sub.dispose();
  }

  render() {
    const {
      me,
      match: {
        params: { workspaceId },
      },
    } = this.props;
    const workspace = {
      description: 'Hello World',
      id: 'ab989ecb-55b1-4656-8998-856f6621991c',
      manifest: 'eyJ3aWRnZXRzIjp7IjkxNGQ5MzdkLTFjNGMtNGEzOC1hZTE1LTExMjk2YmQ2OWViOSI6eyJpZCI6IjkxNGQ5MzdkLTFjNGMtNGEzOC1hZTE1LTExMjk2YmQ2OWViOSIsInBlcnNwZWN0aXZlIjoiZ2xvYmFsIiwiZGF0YVR5cGUiOiJhbGwiLCJ2aXN1YWxpemF0aW9uVHlwZSI6ImRvbnV0IiwiZW50aXR5IjpudWxsLCJsYXlvdXQiOnsidyI6MjAsImgiOjcsIngiOjAsInkiOjAsImkiOiI5MTRkOTM3ZC0xYzRjLTRhMzgtYWUxNS0xMTI5NmJkNjllYjkiLCJtaW5XIjoyLCJtaW5IIjoyLCJtb3ZlZCI6ZmFsc2UsInN0YXRpYyI6ZmFsc2V9fX0sImNvbmZpZyI6e319',
      name: 'Aman',
      owner: { id: '6a4b11e1-90ca-4e42-ba42-db7bc7f7d505', name: 'SYSTEM' },
      tags: null,
      type: 'dashboard',
    };

    return (
      <div>
        <TopBar me={me || null} />
        <QueryRenderer
          query={dashboardQuery}
          variables={{ id: workspaceId }}
          render={({ props }) => {
            if (props) {
              if (props.workspace) {
                return (
                  <div>
                    <Route
                      exact
                      path="/dashboard/workspaces/dashboards/:workspaceId"
                      render={(routeProps) => (
                        <Dashboard
                          {...routeProps}
                          workspace={props.workspace}
                        />
                      )}
                    />
                  </div>
                );
              }
              // return <ErrorNotFound />;
              return <Dashboard workspace={workspace} />;
            }
            return <Loader />;
          }}
        />
      </div>
    );
  }
}

RootDashboard.propTypes = {
  children: PropTypes.node,
  match: PropTypes.object,
  me: PropTypes.object,
};

export default withRouter(RootDashboard);
