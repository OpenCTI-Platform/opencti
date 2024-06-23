import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Route, Routes, Link, Navigate } from 'react-router-dom';
import { graphql } from 'react-relay';
import * as R from 'ramda';
import Box from '@mui/material/Box';
import Tabs from '@mui/material/Tabs';
import Tab from '@mui/material/Tab';
import StixCoreObjectContentRoot from '../../common/stix_core_objects/StixCoreObjectContentRoot';
import withRouter from '../../../../utils/compat-router/withRouter';
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
import Breadcrumbs from '../../../../components/Breadcrumbs';
import { getCurrentTab, getPaddingRight } from '../../../../utils/utils';

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
      stixCoreObjectsDistribution(field: "entity_type", operation: count) {
        label
        value
      }
      ...Tool_tool
      ...ToolKnowledge_tool
      ...FileImportViewer_entity
      ...FileExportViewer_entity
      ...FileExternalReferencesViewer_entity
      ...WorkbenchFileViewer_entity
      ...PictureManagementViewer_entity
      ...StixCoreObjectContent_stixCoreObject
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
      <>
        <QueryRenderer
          query={toolQuery}
          variables={{ id: toolId }}
          render={({ props }) => {
            if (props) {
              if (props.tool) {
                const { tool } = props;
                const paddingRight = getPaddingRight(location.pathname, tool.id, '/dashboard/arsenal/tools');
                return (
                  <>
                    <Routes>
                      <Route
                        path="/knowledge/*"
                        element={
                          <StixCoreObjectKnowledgeBar
                            stixCoreObjectLink={link}
                            availableSections={[
                              'threats',
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
                            stixCoreObjectsDistribution={tool.stixCoreObjectsDistribution}
                          />
                        }
                      />
                    </Routes>
                    <div style={{ paddingRight }}>
                      <Breadcrumbs variant="object" elements={[
                        { label: t('Arsenal') },
                        { label: t('Tools'), link: '/dashboard/arsenal/tools' },
                        { label: tool.name, current: true },
                      ]}
                      />
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
                          value={getCurrentTab(location.pathname, tool.id, '/dashboard/arsenal/tools')}
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
                            to={`/dashboard/arsenal/tools/${tool.id}/content`}
                            value={`/dashboard/arsenal/tools/${tool.id}/content`}
                            label={t('Content')}
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
                              replace={true}
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
                          path="/content/*"
                          element={
                            <StixCoreObjectContentRoot
                              stixCoreObject={tool}
                            />
                        }
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
                  </>
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
  params: PropTypes.object,
};

export default R.compose(inject18n, withRouter)(RootTool);
