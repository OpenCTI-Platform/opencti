import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Route, Redirect, withRouter } from 'react-router-dom';
import graphql from 'babel-plugin-relay/macro';
import { QueryRenderer, requestSubscription } from '../../../relay/environment';
import TopBar from '../nav/TopBar';
import Tool from './Tool';
import ToolReports from './ToolReports';
import ToolKnowledge from './ToolKnowledge';

const subscription = graphql`
  subscription RootToolSubscription($id: ID!) {
    stixDomainEntity(id: $id) {
      ... on Tool {
        ...Tool_tool
        ...ToolEditionContainer_tool
      }
      ...StixDomainEntityKnowledgeGraph_stixDomainEntity
    }
  }
`;

const toolQuery = graphql`
  query RootToolQuery($id: String!) {
    tool(id: $id) {
      ...Tool_tool
      ...ToolHeader_tool
      ...ToolOverview_tool
      ...ToolReports_tool
      ...ToolKnowledge_tool
    }
  }
`;

class RootTool extends Component {
  componentDidMount() {
    const {
      match: {
        params: { toolId },
      },
    } = this.props;
    const sub = requestSubscription({
      subscription,
      variables: { id: toolId },
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
        params: { toolId },
      },
    } = this.props;
    return (
      <div>
        <TopBar me={me || null} />
        <QueryRenderer
          query={toolQuery}
          variables={{ id: toolId }}
          render={({ props }) => {
            if (props && props.tool) {
              return (
                <div>
                  <Route
                    exact
                    path="/dashboard/catalogs/tools/:toolId"
                    render={routeProps => (
                      <Tool {...routeProps} tool={props.tool} />
                    )}
                  />
                  <Route
                    exact
                    path="/dashboard/catalogs/tools/:toolId/reports"
                    render={routeProps => (
                      <ToolReports {...routeProps} tool={props.tool} />
                    )}
                  />
                  <Route
                    exact
                    path="/dashboard/catalogs/tools/:toolId/knowledge"
                    render={() => (
                      <Redirect
                        to={`/dashboard/catalogs/tools/${toolId}/knowledge/overview`}
                      />
                    )}
                  />
                  <Route
                    path="/dashboard/catalogs/tools/:toolId/knowledge"
                    render={routeProps => (
                      <ToolKnowledge {...routeProps} tool={props.tool} />
                    )}
                  />
                </div>
              );
            }
            return <div> &nbsp; </div>;
          }}
        />
      </div>
    );
  }
}

RootTool.propTypes = {
  children: PropTypes.node,
  match: PropTypes.object,
  me: PropTypes.object,
};

export default withRouter(RootTool);
