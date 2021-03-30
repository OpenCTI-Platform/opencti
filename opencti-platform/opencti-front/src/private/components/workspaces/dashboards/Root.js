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
  componentDidMount() {
    const {
      match: {
        params: { workspaceId },
      },
    } = this.props;
    const sub = requestSubscription({
      subscription,
      variables: { id: workspaceId },
    });
    this.setState({ sub });
  }

  componentWillUnmount() {
    this.state.sub.dispose();
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
                        <Dashboard
                          {...routeProps}
                          workspace={props.workspace}
                        />
                      )}
                    />
                  </div>
                );
              }
              return <ErrorNotFound />;
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
