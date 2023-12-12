import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Route, Redirect, withRouter, Switch, Link } from 'react-router-dom';
import { graphql } from 'react-relay';
import * as R from 'ramda';
import Box from '@mui/material/Box';
import Tabs from '@mui/material/Tabs';
import Tab from '@mui/material/Tab';
import { QueryRenderer, requestSubscription } from '../../../../relay/environment';
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
import inject18n from '../../../../components/i18n';

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
      entity_type
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
      t,
      location,
      match: {
        params: { toolId },
      },
    } = this.props;
    const link = `/dashboard/arsenal/tools/${toolId}/knowledge`;
    return (
      <>
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
                const { tool } = props;
                return (
                  <div
                    style={{
                      paddingRight: location.pathname.includes(
                        `/dashboard/arsenal/tools/${tool.id}/knowledge`,
                      )
                        ? 200
                        : 0,
                    }}
                  >
                    <StixDomainObjectHeader
                      entityType="Tool"
                      stixDomainObject={tool}
                      PopoverComponent={<ToolPopover />}
                      enableQuickSubscription={true}
                    />
                    <Box
                      sx={{
                        borderBottom: 1,
                        borderColor: 'divider',
                        marginBottom: 4,
                      }}
                    >
                      <Tabs
                        value={
                          location.pathname.includes(
                            `/dashboard/arsenal/tools/${tool.id}/knowledge`,
                          )
                            ? `/dashboard/arsenal/tools/${tool.id}/knowledge`
                            : location.pathname
                        }
                      >
                        <Tab
                          component={Link}
                          to={`/dashboard/arsenal/tools/${tool.id}`}
                          value={`/dashboard/arsenal/tools/${tool.id}`}
                          label={t('Overview')}
                        />
                        <Tab
                          component={Link}
                          to={`/dashboard/arsenal/tools/${tool.id}/knowledge`}
                          value={`/dashboard/arsenal/tools/${tool.id}/knowledge`}
                          label={t('Knowledge')}
                        />
                        <Tab
                          component={Link}
                          to={`/dashboard/arsenal/tools/${tool.id}/analyses`}
                          value={`/dashboard/arsenal/tools/${tool.id}/analyses`}
                          label={t('Analyses')}
                        />
                        <Tab
                          component={Link}
                          to={`/dashboard/arsenal/tools/${tool.id}/files`}
                          value={`/dashboard/arsenal/tools/${tool.id}/files`}
                          label={t('Data')}
                        />
                        <Tab
                          component={Link}
                          to={`/dashboard/arsenal/tools/${tool.id}/history`}
                          value={`/dashboard/arsenal/tools/${tool.id}/history`}
                          label={t('History')}
                        />
                      </Tabs>
                    </Box>
                    <Switch>
                      <Route
                        exact
                        path="/dashboard/arsenal/tools/:toolId"
                        render={(routeProps) => (
                          <Tool {...routeProps} tool={props.tool} />
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
                          <StixCoreObjectOrStixCoreRelationshipContainers
                            {...routeProps}
                            stixDomainObjectOrStixCoreRelationship={props.tool}
                          />
                        )}
                      />
                      <Route
                        exact
                        path="/dashboard/arsenal/tools/:toolId/files"
                        render={(routeProps) => (
                          <FileManager
                            {...routeProps}
                            id={toolId}
                            connectorsImport={props.connectorsForImport}
                            connectorsExport={props.connectorsForExport}
                            entity={props.tool}
                          />
                        )}
                      />
                      <Route
                        exact
                        path="/dashboard/arsenal/tools/:toolId/history"
                        render={(routeProps) => (
                          <StixCoreObjectHistory
                            {...routeProps}
                            stixCoreObjectId={toolId}
                          />
                        )}
                      />
                    </Switch>
                  </div>
                );
              }
              return <ErrorNotFound />;
            }
            return <Loader />;
          }}
        />
      </>
    );
  }
}

RootTool.propTypes = {
  children: PropTypes.node,
  match: PropTypes.object,
};

export default R.compose(inject18n, withRouter)(RootTool);
