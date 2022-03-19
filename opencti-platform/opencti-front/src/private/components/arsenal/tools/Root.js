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
import StixDomainObjectIndicators from '../../observations/indicators/StixDomainObjectIndicators';
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
      ...FilePendingViewer_entity
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
      ...FilePendingViewer_entity
    }
    connectorsForExport {
      ...FileManager_connectorsExport
    }
    settings {
      platform_enable_reference
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
      me,
      match: {
        params: { toolId },
      },
    } = this.props;
    const link = `/dashboard/arsenal/tools/${toolId}/knowledge`;
    return (
      <div>
        <TopBar me={me || null} />
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
                          enableReferences={props.settings.platform_enable_reference?.includes(
                            'Tool',
                          )}
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
                      path="/dashboard/arsenal/tools/:toolId/analysis"
                      render={(routeProps) => (
                        <React.Fragment>
                          <StixDomainObjectHeader
                            stixDomainObject={props.tool}
                            PopoverComponent={<ToolPopover />}
                            enableReferences={props.settings.platform_enable_reference?.includes(
                              'Tool',
                            )}
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
                      path="/dashboard/arsenal/tools/:toolId/indicators"
                      render={(routeProps) => (
                        <React.Fragment>
                          <StixDomainObjectHeader
                            stixDomainObject={props.tool}
                            PopoverComponent={<ToolPopover />}
                            variant="noaliases"
                          />
                          <StixDomainObjectIndicators
                            {...routeProps}
                            stixDomainObjectId={toolId}
                            stixDomainObjectLink={`/dashboard/arsenal/tools/${toolId}/indicators`}
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
                            stixDomainObject={props.tool}
                            PopoverComponent={<ToolPopover />}
                            enableReferences={props.settings.platform_enable_reference?.includes(
                              'Tool',
                            )}
                          />
                          <FileManager
                            {...routeProps}
                            id={toolId}
                            connectorsImport={[]}
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
                            stixDomainObject={props.tool}
                            PopoverComponent={<ToolPopover />}
                            enableReferences={props.settings.platform_enable_reference?.includes(
                              'Tool',
                            )}
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
  me: PropTypes.object,
};

export default withRouter(RootTool);
