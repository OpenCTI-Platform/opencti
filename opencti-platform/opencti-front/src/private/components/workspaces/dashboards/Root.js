import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Route, withRouter } from 'react-router-dom';
import graphql from 'babel-plugin-relay/macro';
import {
  QueryRenderer,
  requestSubscription,
} from '../../../../relay/environment';
import TopBar from '../../nav/TopBar';
import Workspace from './Dashboard';
import Loader from '../../../../components/Loader';

const subscription = graphql`
  subscription RootWorkspacesSubscription($id: ID!) {
    workspace(id: $id) {
      ...Dashboard_workspace
    }
  }
`;

const workspaceQuery = graphql`
  query RootWorkspaceQuery($id: String!) {
    workspace(id: $id) {
      id
      name
      ...Dashboard_workspace
    }
  }
`;

class RootWorkspace extends Component {
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
          query={workspaceQuery}
          variables={{ id: workspaceId }}
          render={({ props }) => {
            if (props && props.workspace) {
              return (
                <div>
                  <Route
                    exact
                    path="/dashboard/workspaces/dashboards/:workspaceId"
                    render={(routeProps) => (
                      <Workspace {...routeProps} workspace={props.workspace} />
                    )}
                  />
                </div>
              );
            }
            return <Loader />;
          }}
        />
      </div>
    );
  }
}

RootWorkspace.propTypes = {
  children: PropTypes.node,
  match: PropTypes.object,
  me: PropTypes.object,
};

export default withRouter(RootWorkspace);
