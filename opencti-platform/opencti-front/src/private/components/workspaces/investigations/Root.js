import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Route, withRouter } from 'react-router-dom';
import { graphql } from 'react-relay';
import {
  QueryRenderer,
  requestSubscription,
} from '../../../../relay/environment';
import TopBar from '../../nav/TopBar';
import Investigation from './Investigation';
import Loader from '../../../../components/Loader';
import ErrorNotFound from '../../../../components/ErrorNotFound';

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
      type
      ...Investigation_workspace
    }
  }
`;

class RootInvestigation extends Component {
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
    return (
      <div>
        <TopBar me={me || null} />
        <QueryRenderer
          query={investigationQuery}
          variables={{ id: workspaceId }}
          render={({ props }) => {
            if (props) {
              if (props.workspace) {
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
              return <ErrorNotFound />;
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
