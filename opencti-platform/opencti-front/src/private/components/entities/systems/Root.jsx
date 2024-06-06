import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Route, Routes, Link, Navigate } from 'react-router-dom';
import { graphql } from 'react-relay';
import { propOr } from 'ramda';
import * as R from 'ramda';
import Box from '@mui/material/Box';
import Tabs from '@mui/material/Tabs';
import Tab from '@mui/material/Tab';
import StixCoreObjectContentRoot from '../../common/stix_core_objects/StixCoreObjectContentRoot';
import withRouter from '../../../../utils/compat-router/withRouter';
import { QueryRenderer, requestSubscription } from '../../../../relay/environment';
import System from './System';
import SystemKnowledge from './SystemKnowledge';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';
import FileManager from '../../common/files/FileManager';
import SystemPopover from './SystemPopover';
import Loader from '../../../../components/Loader';
import StixCoreObjectHistory from '../../common/stix_core_objects/StixCoreObjectHistory';
import SystemAnalysis from './SystemAnalysis';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import { buildViewParamsFromUrlAndStorage, saveViewParameters } from '../../../../utils/ListParameters';
import StixCoreObjectKnowledgeBar from '../../common/stix_core_objects/StixCoreObjectKnowledgeBar';
import EntityStixSightingRelationships from '../../events/stix_sighting_relationships/EntityStixSightingRelationships';
import inject18n from '../../../../components/i18n';
import Breadcrumbs from '../../../../components/Breadcrumbs';
import { getCurrentTab, getPaddingRight } from '../../../../utils/utils';

const subscription = graphql`
  subscription RootSystemsSubscription($id: ID!) {
    stixDomainObject(id: $id) {
      ... on System {
        ...System_system
        ...SystemEditionContainer_system
      }
      ...FileImportViewer_entity
      ...FileExportViewer_entity
      ...FileExternalReferencesViewer_entity
      ...WorkbenchFileViewer_entity
    }
  }
`;

const systemQuery = graphql`
  query RootSystemQuery($id: String!) {
    system(id: $id) {
      id
      entity_type
      name
      x_opencti_aliases
      ...System_system
      ...SystemKnowledge_system
      ...FileImportViewer_entity
      ...FileExportViewer_entity
      ...FileExternalReferencesViewer_entity
      ...WorkbenchFileViewer_entity
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

class RootSystem extends Component {
  constructor(props) {
    super(props);
    const {
      params: { systemId },
    } = props;
    const LOCAL_STORAGE_KEY = `system-${systemId}`;
    const params = buildViewParamsFromUrlAndStorage(
      props.navigate,
      props.location,
      LOCAL_STORAGE_KEY,
    );
    this.state = {
      viewAs: propOr('knowledge', 'viewAs', params),
    };
    this.sub = requestSubscription({
      subscription,
      variables: { id: systemId },
    });
  }

  componentWillUnmount() {
    this.sub.dispose();
  }

  saveView() {
    const {
      params: { systemId },
    } = this.props;
    const LOCAL_STORAGE_KEY = `system-${systemId}`;
    saveViewParameters(
      this.props.navigate,
      this.props.location,
      LOCAL_STORAGE_KEY,
      this.state,
      true,
    );
  }

  handleChangeViewAs(event) {
    this.setState({ viewAs: event.target.value }, () => this.saveView());
  }

  render() {
    const {
      t,
      location,
      params: { systemId },
    } = this.props;
    const { viewAs } = this.state;
    const link = `/dashboard/entities/systems/${systemId}/knowledge`;

    return (
      <>
        <Routes>
          <Route path="/knowledge/*"
            element = { viewAs === 'knowledge' && (
            <StixCoreObjectKnowledgeBar
              stixCoreObjectLink={link}
              availableSections={[
                'systems',
                'systems',
                'threats',
                'threat_actors',
                'intrusion_sets',
                'campaigns',
                'incidents',
                'malwares',
                'attack_patterns',
                'tools',
                'observables',
              ]}
            />)}
          >
          </Route>
        </Routes>
        <QueryRenderer
          query={systemQuery}
          variables={{ id: systemId }}
          render={({ props }) => {
            if (props) {
              if (props.system) {
                const { system } = props;
                const paddingRight = getPaddingRight(location.pathname, system.id, '/dashboard/entities/systems');
                return (
                  <div style={{ paddingRight }}>
                    <Breadcrumbs variant="object" elements={[
                      { label: t('Entities') },
                      { label: t('Systems'), link: '/dashboard/entities/systems' },
                      { label: system.name, current: true },
                    ]}
                    />
                    <StixDomainObjectHeader
                      entityType="System"
                      disableSharing={true}
                      stixDomainObject={system}
                      isOpenctiAlias={true}
                      enableQuickSubscription={true}
                      PopoverComponent={<SystemPopover />}
                      onViewAs={this.handleChangeViewAs.bind(this)}
                      viewAs={viewAs}
                    />
                    <Box
                      sx={{
                        borderBottom: 1,
                        borderColor: 'divider',
                        marginBottom: 4,
                      }}
                    >
                      <Tabs
                        value={getCurrentTab(location.pathname, system.id, '/dashboard/entities/systems')}
                      >
                        <Tab
                          component={Link}
                          to={`/dashboard/entities/systems/${system.id}`}
                          value={`/dashboard/entities/systems/${system.id}`}
                          label={t('Overview')}
                        />
                        <Tab
                          component={Link}
                          to={`/dashboard/entities/systems/${system.id}/knowledge/overview`}
                          value={`/dashboard/entities/systems/${system.id}/knowledge`}
                          label={t('Knowledge')}
                        />
                        <Tab
                          component={Link}
                          to={`/dashboard/entities/systems/${system.id}/content`}
                          value={`/dashboard/entities/systems/${system.id}/content`}
                          label={t('Content')}
                        />
                        <Tab
                          component={Link}
                          to={`/dashboard/entities/systems/${system.id}/analyses`}
                          value={`/dashboard/entities/systems/${system.id}/analyses`}
                          label={t('Analyses')}
                        />
                        <Tab
                          component={Link}
                          to={`/dashboard/entities/systems/${system.id}/sightings`}
                          value={`/dashboard/entities/systems/${system.id}/sightings`}
                          label={t('Sightings')}
                        />
                        <Tab
                          component={Link}
                          to={`/dashboard/entities/systems/${system.id}/files`}
                          value={`/dashboard/entities/systems/${system.id}/files`}
                          label={t('Data')}
                        />
                        <Tab
                          component={Link}
                          to={`/dashboard/entities/systems/${system.id}/history`}
                          value={`/dashboard/entities/systems/${system.id}/history`}
                          label={t('History')}
                        />
                      </Tabs>
                    </Box>
                    <Routes>
                      <Route
                        path="/"
                        element={
                          <System
                            system={system}
                            viewAs={viewAs}
                          />
                        }
                      />
                      <Route
                        path="/knowledge"
                        element={
                          <Navigate
                            replace={true}
                            to={`/dashboard/entities/systems/${systemId}/knowledge/overview`}
                          />
                        }
                      />
                      <Route
                        path="/knowledge/*"
                        element={
                          <SystemKnowledge
                            system={system}
                            viewAs={viewAs}
                          />
                        }
                      />
                      <Route
                        path="/content/*"
                        element={
                          <StixCoreObjectContentRoot
                            stixCoreObject={system}
                          />
                        }
                      />
                      <Route
                        path="/analyses/*"
                        element={
                          <SystemAnalysis
                            system={system}
                            viewAs={viewAs}
                          />
                        }
                      />
                      <Route
                        path="/sightings"
                        element={
                          <EntityStixSightingRelationships
                            entityId={system.id}
                            entityLink={link}
                            noPadding={true}
                            isTo={true}
                          />
                        }
                      />
                      <Route
                        path="/files"
                        element={
                          <FileManager
                            id={systemId}
                            connectorsImport={props.connectorsForImport}
                            connectorsExport={props.connectorsForExport}
                            entity={system}
                          />
                        }
                      />
                      <Route
                        path="/history"
                        element={
                          <StixCoreObjectHistory
                            stixCoreObjectId={systemId}
                          />
                        }
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
      </>
    );
  }
}

RootSystem.propTypes = {
  children: PropTypes.node,
  params: PropTypes.object,
};

export default R.compose(inject18n, withRouter)(RootSystem);
