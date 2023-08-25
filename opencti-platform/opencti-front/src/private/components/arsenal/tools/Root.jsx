import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Route, Redirect, withRouter, Switch } from 'react-router-dom';
import { graphql } from 'react-relay';
import {
  QueryRenderer,
  requestSubscription,
} from '../../../../relay/environment';
import TopBar from '../../nav/TopBar';
import Tool from './Tool';
import ToolKnowledge from './ToolKnowledge';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';
import FileManager from '../../common/files/FileManager';
import ToolPopover from './ToolPopover';
import Loader from '../../../../components/Loader';
import StixCoreObjectHistory from '../../common/stix_core_objects/StixCoreObjectHistory';
import StixCoreObjectOrStixCoreRelationshipContainers from '../../common/containers/StixCoreObjectOrStixCoreRelationshipContainers';
import StixCoreObjectKnowledgeBar from '../../common/stix_core_objects/StixCoreObjectKnowledgeBar';
import ErrorNotFound from '../../../../components/ErrorNotFound';

const subscription = graphql`
  subscription RootToolSubscription($id: ID!) {
    stixDomainObject(id: $id) {
      ... on Tool {
        ...Tool_tool
        ...ToolEditionContainer_tool
      }
      ...FileImportViewer_entity
      ...FileExportViewer_entity
      ...FileExternalReferencesViewer_entity
      ...WorkbenchFileViewer_entity
        ...PictureManagementViewer_entity

    }
  }
`;

const toolQuery = graphql`
  query RootToolQuery($id: String!) {
    tool(id: $id) {
      id
      standard_id
      name
      aliases
      x_opencti_graph_data
      ...Tool_tool
      ...ToolKnowledge_tool
      ...FileImportViewer_entity
      ...FileExportViewer_entity
      ...FileExternalReferencesViewer_entity
      ...WorkbenchFileViewer_entity
        ...PictureManagementViewer_entity

    }
    connectorsForImport {
      ...FileManager_connectorsImport
    }
    connectorsForExport {
      ...FileManager_connectorsExport
    }
  }
`;

class RootTool extends Component {
  constructor(props) {
    super(props);
    const {
      match: {
        params: { toolId },
      },
    } = props;
    this.sub = requestSubscription({
      subscription,
      variables: { id: toolId },
    });
  }

  componentWillUnmount() {
    this.sub.dispose();
  }

  render() {
    const {
      match: {
        params: { toolId },
      },
    } = this.props;
    const link = `/dashboard/arsenal/tools/${toolId}/knowledge`;
    return (
      <div>
        <TopBar />
        <Route path="/dashboard/arsenal/tools/:toolId/knowledge">
          <StixCoreObjectKnowledgeBar
            stixCoreObjectLink={link}
            availableSections={[
              'threat_actors',
              'intrusion_sets',
              'campaigns',
              'incidents',
              'malwares',
              'attack_patterns',
              'vulnerabilities',
              'indicators',
              'observables',
              'sightings',
            ]}
          />
        </Route>
        <QueryRenderer
          query={toolQuery}
          variables={{ id: toolId }}
          render={({ props }) => {
            if (props) {
              if (props.tool) {
                return (
                  <Switch>
                    <Route
                      exact
                      path="/dashboard/arsenal/tools/:toolId"
                      render={(routeProps) => (
                        <Tool
                          {...routeProps}
                          tool={props.tool}
                        />
                      )}
                    />
                    <Route
                      exact
                      path="/dashboard/arsenal/tools/:toolId/knowledge"
                      render={() => (
                        <Redirect
                          to={`/dashboard/arsenal/tools/${toolId}/knowledge/overview`}
                        />
                      )}
                    />
                    <Route
                      path="/dashboard/arsenal/tools/:toolId/knowledge"
                      render={(routeProps) => (
                        <ToolKnowledge {...routeProps} tool={props.tool} />
                      )}
                    />
                    <Route
                      exact
                      path="/dashboard/arsenal/tools/:toolId/analyses"
                      render={(routeProps) => (
                        <React.Fragment>
                          <StixDomainObjectHeader
                            entityType={'Tool'}
                            stixDomainObject={props.tool}
                            PopoverComponent={<ToolPopover />}
                          />
                          <StixCoreObjectOrStixCoreRelationshipContainers
                            {...routeProps}
                            stixDomainObjectOrStixCoreRelationship={props.tool}
                          />
                        </React.Fragment>
                      )}
                    />
                    <Route
                      exact
                      path="/dashboard/arsenal/tools/:toolId/files"
                      render={(routeProps) => (
                        <React.Fragment>
                          <StixDomainObjectHeader
                            entityType={'Tool'}
                            stixDomainObject={props.tool}
                            PopoverComponent={<ToolPopover />}
                          />
                          <FileManager
                            {...routeProps}
                            id={toolId}
                            connectorsImport={props.connectorsForImport}
                            connectorsExport={props.connectorsForExport}
                            entity={props.tool}
                          />
                        </React.Fragment>
                      )}
                    />
                    <Route
                      exact
                      path="/dashboard/arsenal/tools/:toolId/history"
                      render={(routeProps) => (
                        <React.Fragment>
                          <StixDomainObjectHeader
                            entityType={'Tool'}
                            stixDomainObject={props.tool}
                            PopoverComponent={<ToolPopover />}
                          />
                          <StixCoreObjectHistory
                            {...routeProps}
                            stixCoreObjectId={toolId}
                          />
                        </React.Fragment>
                      )}
                    />
                  </Switch>
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

RootTool.propTypes = {
  children: PropTypes.node,
  match: PropTypes.object,
};

export default withRouter(RootTool);
