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
import Sector from './Sector';
import SectorKnowledge from './SectorKnowledge';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';
import SectorPopover from './SectorPopover';
import FileManager from '../../common/files/FileManager';
import Loader from '../../../../components/Loader';
import StixCoreObjectHistory from '../../common/stix_core_objects/StixCoreObjectHistory';
import StixCoreObjectOrStixCoreRelationshipContainers from '../../common/containers/StixCoreObjectOrStixCoreRelationshipContainers';
import StixCoreObjectKnowledgeBar from '../../common/stix_core_objects/StixCoreObjectKnowledgeBar';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import EntityStixSightingRelationships from '../../events/stix_sighting_relationships/EntityStixSightingRelationships';
import inject18n from '../../../../components/i18n';
import Breadcrumbs from '../../../../components/Breadcrumbs';
import { getCurrentTab, getPaddingRight } from '../../../../utils/utils';

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
      stixCoreObjectsDistribution(field: "entity_type", operation: count) {
        label
        value
      }
      ...Sector_sector
      ...SectorKnowledge_sector
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
      <>
        <QueryRenderer
          query={sectorQuery}
          variables={{ id: sectorId }}
          render={({ props }) => {
            if (props) {
              if (props.sector) {
                const { sector } = props;
                const paddingRight = getPaddingRight(location.pathname, sector.id, '/dashboard/entities/sectors');
                return (
                  <>
                    <Routes>
                      <Route
                        path="/knowledge/*"
                        element={
                          <StixCoreObjectKnowledgeBar
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
                            stixCoreObjectsDistribution={sector.stixCoreObjectsDistribution}
                          />
                        }
                      />
                    </Routes>
                    <div style={{ paddingRight }}>
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
                        PopoverComponent={<SectorPopover />}
                      />
                      <Box
                        sx={{
                          borderBottom: 1,
                          borderColor: 'divider',
                          marginBottom: 4,
                        }}
                      >
                        <Tabs
                          value={getCurrentTab(location.pathname, sector.id, '/dashboard/entities/sectors')}
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
                            to={`/dashboard/entities/sectors/${sector.id}/content`}
                            value={`/dashboard/entities/sectors/${sector.id}/content`}
                            label={t('Content')}
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
                              replace={true}
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
                          path="/content/*"
                          element={
                            <StixCoreObjectContentRoot
                              stixCoreObject={sector}
                            />
                        }
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

RootSector.propTypes = {
  children: PropTypes.node,
  params: PropTypes.object,
};

export default R.compose(inject18n, withRouter)(RootSector);
