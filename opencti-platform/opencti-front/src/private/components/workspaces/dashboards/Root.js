import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Route, withRouter } from 'react-router-dom';
import graphql from 'babel-plugin-relay/macro';
import {
  QueryRenderer,
  requestSubscription,
} from '../../../../relay/environment';
import TopBar from '../../nav/TopBar';
import CyioDashboard from './CyioDashboard';
import Loader from '../../../../components/Loader';
import { toastGenericError } from '../../../../utils/bakedToast';

const subscription = graphql`
  subscription RootDashboardSubscription($id: ID!) {
    workspace(id: $id) {
      ...CyioDashboard_workspace
    }
  }
`;

const dashboardQuery = graphql`
  query RootDashboardQuery($id: String!) {
    workspace(id: $id) {
      id
      name
      ...CyioDashboard_workspace
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

  handleErrorNotFound() {
    toastGenericError('Workspace Not Found');
    this.props.history.push('/dashboard/workspaces/dashboards');
  }

  render() {
    const {
      me,
      match: {
        params: { workspaceId },
      },
    } = this.props;
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
                        <CyioDashboard
                          {...routeProps}
                          workspace={props.workspace}
                        />
                      )}
                    />
                  </div>
                );
              }
              return this.handleErrorNotFound();
            }
            return <Loader />;
          }}
        />
      </div>
    );
  }
}

RootDashboard.propTypes = {
  history: PropTypes.object,
  children: PropTypes.node,
  match: PropTypes.object,
  me: PropTypes.object,
};

export default withRouter(RootDashboard);
