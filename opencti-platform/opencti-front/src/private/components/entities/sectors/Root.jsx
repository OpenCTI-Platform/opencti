import React, { Component } from 'react';
import * as PropTypes from 'prop-types';
import { Route, Routes, Link, Navigate } from 'react-router-dom';
import { graphql } from 'react-relay';
import * as R from 'ramda';
import Box from '@mui/material/Box';
import Tabs from '@mui/material/Tabs';
import Tab from '@mui/material/Tab';
import withRouter from '../../../../utils/compat-router/withRouter';
import { QueryRenderer, requestSubscription } from '../../../../relay/environment';
import Sector from './Sector';
import SectorKnowledge from './SectorKnowledge';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';
import FileManager from '../../common/files/FileManager';
import Loader from '../../../../components/Loader';
import StixCoreObjectHistory from '../../common/stix_core_objects/StixCoreObjectHistory';
import StixCoreObjectOrStixCoreRelationshipContainers from '../../common/containers/StixCoreObjectOrStixCoreRelationshipContainers';
import StixCoreObjectKnowledgeBar from '../../common/stix_core_objects/StixCoreObjectKnowledgeBar';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import EntityStixSightingRelationships from '../../events/stix_sighting_relationships/EntityStixSightingRelationships';
import inject18n from '../../../../components/i18n';
import Breadcrumbs from '../../../../components/Breadcrumbs';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../../utils/hooks/useGranted';
import SectorEdition from './SectorEdition';
import CreateRelationshipButtonComponent from '../../common/menus/RelateComponent';
import RelateComponentContextProvider from '../../common/menus/RelateComponentProvider';

const subscription = graphql`
  subscription RootSectorSubscription($id: ID!) {
    stixDomainObject(id: $id) {
      ... on Sector {
        ...Sector_sector
        ...SectorEditionContainer_sector
      }
      ...FileImportViewer_entity
      ...FileExportViewer_entity
      ...FileExternalReferencesViewer_entity
      ...WorkbenchFileViewer_entity
    }
  }
`;

const sectorQuery = graphql`
  query RootSectorQuery($id: String!) {
    sector(id: $id) {
      id
      standard_id
      entity_type
      name
      x_opencti_aliases
      x_opencti_graph_data
      created_at
      updated_at
      ...Sector_sector
      ...SectorKnowledge_sector
      ...FileImportViewer_entity
      ...FileExportViewer_entity
      ...FileExternalReferencesViewer_entity
      ...WorkbenchFileViewer_entity
    }
    connectorsForImport {
      ...FileManager_connectorsImport
    }
    connectorsForExport {
      ...FileManager_connectorsExport
    }
  }
`;

class RootSector extends Component {
  constructor(props) {
    super(props);
    const {
      params: { sectorId },
    } = props;
    this.sub = requestSubscription({
      subscription,
      variables: { id: sectorId },
    });
  }

  componentWillUnmount() {
    this.sub.dispose();
  }

  render() {
    const {
      t,
      location,
      params: { sectorId },
    } = this.props;
    const link = `/dashboard/entities/sectors/${sectorId}/knowledge`;
    return (
      <RelateComponentContextProvider>
        <Routes>
          <Route path="/knowledge/*" element={<StixCoreObjectKnowledgeBar
            stixCoreObjectLink={link}
            availableSections={[
              'organizations',
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
                                              />}
          >
          </Route>
        </Routes>
        <QueryRenderer
          query={sectorQuery}
          variables={{ id: sectorId }}
          render={({ props }) => {
            if (props) {
              if (props.sector) {
                const { sector } = props;
                return (
                  <div
                    style={{
                      paddingRight: location.pathname.includes(
                        `/dashboard/entities/sectors/${sector.id}/knowledge`,
                      )
                        ? 200
                        : 0,
                    }}
                  >
                    <Breadcrumbs variant="object" elements={[
                      { label: t('Entities') },
                      { label: t('Sectors'), link: '/dashboard/entities/sectors' },
                      { label: sector.name, current: true },
                    ]}
                    />
                    <StixDomainObjectHeader
                      entityType="Sector"
                      disableSharing={true}
                      stixDomainObject={sector}
                      isOpenctiAlias={true}
                      enableQuickSubscription={true}
                      EditComponent={<Security needs={[KNOWLEDGE_KNUPDATE]}>
                        <SectorEdition sectorId={sector.id} />
                      </Security>}
                      RelateComponent={<CreateRelationshipButtonComponent
                        id={sector.id}
                        defaultStartTime={sector.created_at}
                        defaultStopTime={sector.updated_at}
                                       />}
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
                            `/dashboard/entities/sectors/${sector.id}/knowledge`,
                          )
                            ? `/dashboard/entities/sectors/${sector.id}/knowledge`
                            : location.pathname
                        }
                      >
                        <Tab
                          component={Link}
                          to={`/dashboard/entities/sectors/${sector.id}`}
                          value={`/dashboard/entities/sectors/${sector.id}`}
                          label={t('Overview')}
                        />
                        <Tab
                          component={Link}
                          to={`/dashboard/entities/sectors/${sector.id}/knowledge/overview`}
                          value={`/dashboard/entities/sectors/${sector.id}/knowledge`}
                          label={t('Knowledge')}
                        />
                        <Tab
                          component={Link}
                          to={`/dashboard/entities/sectors/${sector.id}/analyses`}
                          value={`/dashboard/entities/sectors/${sector.id}/analyses`}
                          label={t('Analyses')}
                        />
                        <Tab
                          component={Link}
                          to={`/dashboard/entities/sectors/${sector.id}/sightings`}
                          value={`/dashboard/entities/sectors/${sector.id}/sightings`}
                          label={t('Sightings')}
                        />
                        <Tab
                          component={Link}
                          to={`/dashboard/entities/sectors/${sector.id}/files`}
                          value={`/dashboard/entities/sectors/${sector.id}/files`}
                          label={t('Data')}
                        />
                        <Tab
                          component={Link}
                          to={`/dashboard/entities/sectors/${sector.id}/history`}
                          value={`/dashboard/entities/sectors/${sector.id}/history`}
                          label={t('History')}
                        />
                      </Tabs>
                    </Box>
                    <Routes>
                      <Route
                        path="/"
                        element={(
                          <Sector sector={sector} />
                        )}
                      />
                      <Route
                        path="/knowledge"
                        element={
                          <Navigate
                            to={`/dashboard/entities/sectors/${sectorId}/knowledge/overview`}
                          />
                        }
                      />
                      <Route
                        path="/knowledge/*"
                        element={(
                          <SectorKnowledge sector={sector} />
                        )}
                      />
                      <Route
                        path="/analyses"
                        element={ (
                          <StixCoreObjectOrStixCoreRelationshipContainers
                            stixDomainObjectOrStixCoreRelationship={sector}
                          />
                        )}
                      />
                      <Route
                        path="/sightings"
                        element={ (
                          <EntityStixSightingRelationships
                            entityId={sector.id}
                            entityLink={link}
                            noPadding={true}
                            isTo={true}
                          />
                        )}
                      />
                      <Route
                        path="/files"
                        element={(
                          <FileManager
                            id={sectorId}
                            connectorsImport={props.connectorsForImport}
                            connectorsExport={props.connectorsForExport}
                            entity={sector}
                          />
                        )}
                      />
                      <Route
                        path="/history"
                        element={(
                          <StixCoreObjectHistory
                            stixCoreObjectId={sectorId}
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

RootSector.propTypes = {
  children: PropTypes.node,
  params: PropTypes.object,
};

export default R.compose(inject18n, withRouter)(RootSector);
