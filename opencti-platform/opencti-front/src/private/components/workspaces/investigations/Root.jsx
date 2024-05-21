import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Route, Routes } from 'react-router-dom';
import { graphql } from 'react-relay';
import withRouter from '../../../../utils/compat-router/withRouter';
import { QueryRenderer, requestSubscription } from '../../../../relay/environment';
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
      params: { workspaceId },
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
      params: { workspaceId },
    } = this.props;
    // Div is required below, if not set, graph is showing a scrollbar
    return (
      <div data-testid="investigation-details-page">
        <QueryRenderer
          query={investigationQuery}
          variables={{ id: workspaceId }}
          render={({ props }) => {
            if (props) {
              if (props.workspace) {
                return (
                  <Routes>
                    <Route
                      path="/"
                      element={
                        <Investigation
                          workspace={props.workspace}
                        />
                    }
                    />
                  </Routes>
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
  params: PropTypes.object,
};

export default withRouter(RootInvestigation);
