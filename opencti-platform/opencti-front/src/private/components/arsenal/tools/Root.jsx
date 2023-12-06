import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Route, Routes, Link, Navigate } from 'react-router-dom';
import { graphql } from 'react-relay';
import * as R from 'ramda';
import Box from '@mui/material/Box';
import Tabs from '@mui/material/Tabs';
import Tab from '@mui/material/Tab';
import withRouter from '../../../../utils/compat-router/withRouter';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../../utils/hooks/useGranted';
import { QueryRenderer, requestSubscription } from '../../../../relay/environment';
import Tool from './Tool';
import ToolKnowledge from './ToolKnowledge';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';
import FileManager from '../../common/files/FileManager';
import Loader from '../../../../components/Loader';
import StixCoreObjectHistory from '../../common/stix_core_objects/StixCoreObjectHistory';
import StixCoreObjectOrStixCoreRelationshipContainers from '../../common/containers/StixCoreObjectOrStixCoreRelationshipContainers';
import StixCoreObjectKnowledgeBar from '../../common/stix_core_objects/StixCoreObjectKnowledgeBar';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import inject18n from '../../../../components/i18n';
import Breadcrumbs from '../../../../components/Breadcrumbs';
import ToolEdition from './ToolEdition';
import CreateRelationshipButtonComponent from '../../common/menus/RelateComponent';
import RelateComponentContextProvider from '../../common/menus/RelateComponentProvider';

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
      created_at
      updated_at
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
      params: { toolId },
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
      params: { toolId },
    } = this.props;
    const link = `/dashboard/arsenal/tools/${toolId}/knowledge`;
    return (
      <RelateComponentContextProvider>
        <Routes>
          <Route path="/knowledge/*" element={<StixCoreObjectKnowledgeBar
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
                                              />}
          >
          </Route>
        </Routes>
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
                    <Breadcrumbs variant="object" elements={[
                      { label: t('Arsenal') },
                      { label: t('Tools'), link: '/dashboard/arsenal/tools' },
                      { label: tool.name, current: true },
                    ]}
                    />
                    <StixDomainObjectHeader
                      entityType="Tool"
                      stixDomainObject={tool}
                      EditComponent={<Security needs={[KNOWLEDGE_KNUPDATE]}>
                        <ToolEdition toolId={tool.id} />
                      </Security>}
                      RelateComponent={<CreateRelationshipButtonComponent
                        id={tool.id}
                        defaultStartTime={tool.created_at}
                        defaultStopTime={tool.updated_at}
                                       />}
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
                          to={`/dashboard/arsenal/tools/${tool.id}/knowledge/overview`}
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
                    <Routes>
                      <Route
                        path="/"
                        element={ (
                          <Tool tool={tool} />
                        )}
                      />
                      <Route
                        path="/knowledge"
                        element={
                          <Navigate
                            to={`/dashboard/arsenal/tools/${toolId}/knowledge/overview`}
                          />
                        }
                      />
                      <Route
                        path="/knowledge/*"
                        element={(
                          <ToolKnowledge tool={tool} />
                        )}
                      />
                      <Route
                        path="/analyses/*"
                        element={(
                          <StixCoreObjectOrStixCoreRelationshipContainers
                            stixDomainObjectOrStixCoreRelationship={tool}
                          />
                        )}
                      />
                      <Route
                        path="/files"
                        element={(
                          <FileManager
                            id={toolId}
                            connectorsImport={props.connectorsForImport}
                            connectorsExport={props.connectorsForExport}
                            entity={tool}
                          />
                        )}
                      />
                      <Route
                        path="/history"
                        element={ (
                          <StixCoreObjectHistory
                            stixCoreObjectId={toolId}
                          />
                        )}
                      />
                    </Routes>
                  </div>
                );
              }
              return <ErrorNotFound />;
            }
            return <Loader />;
          }}
        />
      </RelateComponentContextProvider>
    );
  }
}

RootTool.propTypes = {
  children: PropTypes.node,
  params: PropTypes.object,
};

export default R.compose(inject18n, withRouter)(RootTool);
