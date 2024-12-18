import React, { useMemo, Suspense } from 'react';
import { Route, Routes, Link, Navigate, useLocation, useParams } from 'react-router-dom';
import { graphql, useSubscription, usePreloadedQuery, PreloadedQuery } from 'react-relay';
import { GraphQLSubscriptionConfig } from 'relay-runtime';
import Box from '@mui/material/Box';
import Tabs from '@mui/material/Tabs';
import Tab from '@mui/material/Tab';
import { RootSectorQuery } from '@components/entities/sectors/__generated__/RootSectorQuery.graphql';
import { RootSectorSubscription } from '@components/entities/sectors/__generated__/RootSectorSubscription.graphql';
import useQueryLoading from 'src/utils/hooks/useQueryLoading';
import useForceUpdate from '@components/common/bulk/useForceUpdate';
import StixCoreObjectContentRoot from '../../common/stix_core_objects/StixCoreObjectContentRoot';
import Sector from './Sector';
import SectorKnowledge from './SectorKnowledge';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';
import SectorPopover from './SectorPopover';
import FileManager from '../../common/files/FileManager';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import StixCoreObjectHistory from '../../common/stix_core_objects/StixCoreObjectHistory';
import StixCoreObjectOrStixCoreRelationshipContainers from '../../common/containers/StixCoreObjectOrStixCoreRelationshipContainers';
import StixCoreObjectKnowledgeBar from '../../common/stix_core_objects/StixCoreObjectKnowledgeBar';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import EntityStixSightingRelationships from '../../events/stix_sighting_relationships/EntityStixSightingRelationships';
import { useFormatter } from '../../../../components/i18n';
import Breadcrumbs from '../../../../components/Breadcrumbs';
import { getCurrentTab, getPaddingRight } from '../../../../utils/utils';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../../utils/hooks/useGranted';
import SectorEdition from './SectorEdition';
import useHelper from '../../../../utils/hooks/useHelper';
import CreateRelationshipContextProvider from '../../common/menus/CreateRelationshipContextProvider';
import CreateRelationshipButtonComponent from '../../common/menus/CreateRelationshipButtonComponent';

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

type RootSectorProps = {
  sectorId: string;
  queryRef: PreloadedQuery<RootSectorQuery>;
};

const RootSector = ({ sectorId, queryRef }: RootSectorProps) => {
  const subConfig = useMemo<GraphQLSubscriptionConfig<RootSectorSubscription>>(() => ({
    subscription,
    variables: { id: sectorId },
  }), [sectorId]);

  const location = useLocation();
  const { isFeatureEnable } = useHelper();
  const isFABReplaced = isFeatureEnable('FAB_REPLACEMENT');
  const { t_i18n } = useFormatter();
  useSubscription<RootSectorSubscription>(subConfig);

  const {
    sector,
    connectorsForExport,
    connectorsForImport,
  } = usePreloadedQuery<RootSectorQuery>(sectorQuery, queryRef);

  const { forceUpdate } = useForceUpdate();

  const paddingRight = getPaddingRight(location.pathname, sectorId, '/dashboard/entities/sectors');
  const link = `/dashboard/entities/sectors/${sectorId}/knowledge`;
  return (
    <CreateRelationshipContextProvider>
      {sector ? (
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
            <Breadcrumbs elements={[
              { label: t_i18n('Entities') },
              { label: t_i18n('Sectors'), link: '/dashboard/entities/sectors' },
              { label: sector.name, current: true },
            ]}
            />
            <StixDomainObjectHeader
              entityType="Sector"
              disableSharing={true}
              stixDomainObject={sector}
              isOpenctiAlias={true}
              enableQuickSubscription={true}
              PopoverComponent={<SectorPopover id={sector.id}/>}
              EditComponent={isFABReplaced && (
                <Security needs={[KNOWLEDGE_KNUPDATE]}>
                  <SectorEdition sectorId={sector.id} />
                </Security>
              )}
              RelateComponent={CreateRelationshipButtonComponent}
            />
            <Box
              sx={{
                borderBottom: 1,
                borderColor: 'divider',
                marginBottom: 3,
              }}
            >
              <Tabs
                value={getCurrentTab(location.pathname, sector.id, '/dashboard/entities/sectors')}
              >
                <Tab
                  component={Link}
                  to={`/dashboard/entities/sectors/${sector.id}`}
                  value={`/dashboard/entities/sectors/${sector.id}`}
                  label={t_i18n('Overview')}
                />
                <Tab
                  component={Link}
                  to={`/dashboard/entities/sectors/${sector.id}/knowledge/overview`}
                  value={`/dashboard/entities/sectors/${sector.id}/knowledge`}
                  label={t_i18n('Knowledge')}
                />
                <Tab
                  component={Link}
                  to={`/dashboard/entities/sectors/${sector.id}/content`}
                  value={`/dashboard/entities/sectors/${sector.id}/content`}
                  label={t_i18n('Content')}
                />
                <Tab
                  component={Link}
                  to={`/dashboard/entities/sectors/${sector.id}/analyses`}
                  value={`/dashboard/entities/sectors/${sector.id}/analyses`}
                  label={t_i18n('Analyses')}
                />
                <Tab
                  component={Link}
                  to={`/dashboard/entities/sectors/${sector.id}/sightings`}
                  value={`/dashboard/entities/sectors/${sector.id}/sightings`}
                  label={t_i18n('Sightings')}
                />
                <Tab
                  component={Link}
                  to={`/dashboard/entities/sectors/${sector.id}/files`}
                  value={`/dashboard/entities/sectors/${sector.id}/files`}
                  label={t_i18n('Data')}
                />
                <Tab
                  component={Link}
                  to={`/dashboard/entities/sectors/${sector.id}/history`}
                  value={`/dashboard/entities/sectors/${sector.id}/history`}
                  label={t_i18n('History')}
                />
              </Tabs>
            </Box>
            <Routes>
              <Route
                path="/"
                element={(
                  <Sector sectorData={sector} />
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
                  <div key={forceUpdate}>
                    <SectorKnowledge sector={sector} />
                  </div>
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
                    stixCoreObjectTypes={[
                      'Region',
                      'Country',
                      'City',
                      'Position',
                      'Sector',
                      'Organization',
                      'Individual',
                      'System',
                    ]}
                  />
                )}
              />
              <Route
                path="/files"
                element={(
                  <FileManager
                    id={sectorId}
                    connectorsImport={connectorsForImport}
                    connectorsExport={connectorsForExport}
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
      ) : (
        <ErrorNotFound />
      )}
    </CreateRelationshipContextProvider>
  );
};
const Root = () => {
  const { sectorId } = useParams() as { sectorId: string; };
  const queryRef = useQueryLoading<RootSectorQuery>(sectorQuery, {
    id: sectorId,
  });

  return (
    <>
      {queryRef && (
        <Suspense fallback={<Loader variant={LoaderVariant.container} />}>
          <RootSector sectorId={sectorId} queryRef={queryRef} />
        </Suspense>
      )}
    </>
  );
};

export default Root;
