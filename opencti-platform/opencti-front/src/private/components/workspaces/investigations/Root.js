import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Route, withRouter } from 'react-router-dom';
import graphql from 'babel-plugin-relay/macro';
import {
  QueryRenderer,
  requestSubscription,
} from '../../../../relay/environment';
import TopBar from '../../nav/TopBar';
import Investigation from './Investigation';
import Loader from '../../../../components/Loader';

const subscription = graphql`
  subscription RootInvestigationSubscription($id: ID!) {
    workspace(id: $id) {
      ...Investigation_workspace
    }
  }
`;

const investigationQuery = graphql`
  query RootInvestigationQuery($id: String!) {
    workspace(id: $id) {
      id
      name
      ...Investigation_workspace
    }
  }
`;

class RootInvestigation extends Component {
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
          query={investigationQuery}
          variables={{ id: workspaceId }}
          render={({ props }) => {
            if (props && props.workspace) {
              return (
                <Route
                  exact
                  path="/dashboard/workspaces/investigations/:workspaceId"
                  render={(routeProps) => (
                    <Investigation
                      {...routeProps}
                      workspace={props.workspace}
                    />
                  )}
                />
              );
            }
            return <Loader />;
          }}
        />
      </div>
    );
  }
}

RootInvestigation.propTypes = {
  children: PropTypes.node,
  match: PropTypes.object,
  me: PropTypes.object,
};

export default withRouter(RootInvestigation);
