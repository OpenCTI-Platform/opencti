// TODO Remove this when V6
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-nocheck
import React, { useMemo } from 'react';
import { Link, Navigate, Route, Routes, useLocation, useParams } from 'react-router-dom';
import { graphql, usePreloadedQuery, useSubscription } from 'react-relay';
import { GraphQLSubscriptionConfig } from 'relay-runtime';
import Box from '@mui/material/Box';
import Tabs from '@mui/material/Tabs';
import Tab from '@mui/material/Tab';
import useForceUpdate from '@components/common/bulk/useForceUpdate';
import StixCoreObjectContentRoot from '../../common/stix_core_objects/StixCoreObjectContentRoot';
import AdministrativeArea from './AdministrativeArea';
import AdministrativeAreaKnowledge from './AdministrativeAreaKnowledge';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';
import FileManager from '../../common/files/FileManager';
import AdministrativeAreaPopover from './AdministrativeAreaPopover';
import StixCoreObjectHistory from '../../common/stix_core_objects/StixCoreObjectHistory';
import StixCoreObjectOrStixCoreRelationshipContainers from '../../common/containers/StixCoreObjectOrStixCoreRelationshipContainers';
import StixCoreObjectKnowledgeBar from '../../common/stix_core_objects/StixCoreObjectKnowledgeBar';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import EntityStixSightingRelationships from '../../events/stix_sighting_relationships/EntityStixSightingRelationships';
import { RootAdministrativeAreaQuery } from './__generated__/RootAdministrativeAreaQuery.graphql';
import { RootAdministrativeAreasSubscription } from './__generated__/RootAdministrativeAreasSubscription.graphql';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import { useFormatter } from '../../../../components/i18n';
import Breadcrumbs from '../../../../components/Breadcrumbs';
import { getCurrentTab, getPaddingRight } from '../../../../utils/utils';
import AdministrativeAreaEdition from './AdministrativeAreaEdition';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../../utils/hooks/useGranted';
import useHelper from '../../../../utils/hooks/useHelper';
import CreateRelationshipContextProvider from '../../common/menus/CreateRelationshipContextProvider';
import CreateRelationshipButtonComponent from '../../common/menus/CreateRelationshipButtonComponent';

const subscription = graphql`
  subscription RootAdministrativeAreasSubscription($id: ID!) {
    stixDomainObject(id: $id) {
      ... on AdministrativeArea {
        ...AdministrativeArea_administrativeArea
        ...AdministrativeAreaEditionOverview_administrativeArea
      }
      ...FileImportViewer_entity
      ...FileExportViewer_entity
      ...FileExternalReferencesViewer_entity
      ...WorkbenchFileViewer_entity
    }
  }
`;

const administrativeAreaQuery = graphql`
  query RootAdministrativeAreaQuery($id: String!) {
    administrativeArea(id: $id) {
      id
      name
      x_opencti_aliases
      x_opencti_graph_data
      stixCoreObjectsDistribution(field: "entity_type", operation: count) {
        label
        value
      }
      ...AdministrativeArea_administrativeArea
      ...AdministrativeAreaKnowledge_administrativeArea
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

const RootAdministrativeAreaComponent = ({ queryRef, administrativeAreaId }) => {
  const subConfig = useMemo<
  GraphQLSubscriptionConfig<RootAdministrativeAreasSubscription>
  >(
    () => ({
      subscription,
      variables: { id: administrativeAreaId },
    }),
    [administrativeAreaId],
  );
  useSubscription(subConfig);
  const location = useLocation();
  const { isFeatureEnable } = useHelper();
  const isFABReplaced = isFeatureEnable('FAB_REPLACEMENT');
  const { t_i18n } = useFormatter();
  const data = usePreloadedQuery(administrativeAreaQuery, queryRef);
  const { forceUpdate } = useForceUpdate();
  const { administrativeArea, connectorsForImport, connectorsForExport } = data;
  const link = `/dashboard/locations/administrative_areas/${administrativeAreaId}/knowledge`;
  const paddingRight = getPaddingRight(location.pathname, administrativeArea?.id, '/dashboard/locations/administrative_areas');
  return (
    <CreateRelationshipContextProvider>
      {administrativeArea ? (
        <>
          <Routes>
            <Route
              path="/knowledge/*"
              element={
                <StixCoreObjectKnowledgeBar
                  stixCoreObjectLink={link}
                  availableSections={[
                    'organizations',
                    'regions',
                    'countries',
                    'cities',
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
                  stixCoreObjectsDistribution={administrativeArea.stixCoreObjectsDistribution}
                />
              }
            />
          </Routes>
          <div style={{ paddingRight }}>
            <Breadcrumbs elements={[
              { label: t_i18n('Locations') },
              { label: t_i18n('Administrative areas'), link: '/dashboard/locations/administrative_areas' },
              { label: administrativeArea.name, current: true },
            ]}
            />
            <StixDomainObjectHeader
              entityType="Administrative-Area"
              disableSharing={true}
              stixDomainObject={administrativeArea}
              PopoverComponent={
                <AdministrativeAreaPopover id={administrativeArea.id} />
            }
              EditComponent={isFABReplaced && (
                <Security needs={[KNOWLEDGE_KNUPDATE]}>
                  <AdministrativeAreaEdition
                    administrativeAreaId={administrativeArea.id}
                  />
                </Security>
              )}
              RelateComponent={CreateRelationshipButtonComponent}
              enableQuickSubscription={true}
              isOpenctiAlias={true}
            />
            <Box
              sx={{
                borderBottom: 1,
                borderColor: 'divider',
                marginBottom: 3,
              }}
            >
              <Tabs
                value={getCurrentTab(location.pathname, administrativeArea.id, '/dashboard/locations/administrative_areas')}
              >
                <Tab
                  component={Link}
                  to={`/dashboard/locations/administrative_areas/${administrativeArea.id}`}
                  value={`/dashboard/locations/administrative_areas/${administrativeArea.id}`}
                  label={t_i18n('Overview')}
                />
                <Tab
                  component={Link}
                  to={`/dashboard/locations/administrative_areas/${administrativeArea.id}/knowledge/overview`}
                  value={`/dashboard/locations/administrative_areas/${administrativeArea.id}/knowledge`}
                  label={t_i18n('Knowledge')}
                />
                <Tab
                  component={Link}
                  to={`/dashboard/locations/administrative_areas/${administrativeArea.id}/content`}
                  value={`/dashboard/locations/administrative_areas/${administrativeArea.id}/content`}
                  label={t_i18n('Content')}
                />
                <Tab
                  component={Link}
                  to={`/dashboard/locations/administrative_areas/${administrativeArea.id}/analyses`}
                  value={`/dashboard/locations/administrative_areas/${administrativeArea.id}/analyses`}
                  label={t_i18n('Analyses')}
                />
                <Tab
                  component={Link}
                  to={`/dashboard/locations/administrative_areas/${administrativeArea.id}/sightings`}
                  value={`/dashboard/locations/administrative_areas/${administrativeArea.id}/sightings`}
                  label={t_i18n('Sightings')}
                />
                <Tab
                  component={Link}
                  to={`/dashboard/locations/administrative_areas/${administrativeArea.id}/files`}
                  value={`/dashboard/locations/administrative_areas/${administrativeArea.id}/files`}
                  label={t_i18n('Data')}
                />
                <Tab
                  component={Link}
                  to={`/dashboard/locations/administrative_areas/${administrativeArea.id}/history`}
                  value={`/dashboard/locations/administrative_areas/${administrativeArea.id}/history`}
                  label={t_i18n('History')}
                />
              </Tabs>
            </Box>
            <Routes>
              <Route
                path="/"
                element={
                  <AdministrativeArea administrativeAreaData={administrativeArea} />
              }
              />
              <Route
                path="/knowledge"
                element={
                  <Navigate to={`/dashboard/locations/administrative_areas/${administrativeArea.id}/knowledge/overview`} replace={true} />
              }
              />
              <Route
                path="/content/*"
                element={
                  <StixCoreObjectContentRoot
                    stixCoreObject={administrativeArea}
                  />
              }
              />
              <Route
                path="/knowledge/*"
                element={
                  <div key={forceUpdate}>
                    <AdministrativeAreaKnowledge administrativeAreaData={administrativeArea} />
                  </div>
                }
              />
              <Route
                path="/analyses"
                element={
                  <StixCoreObjectOrStixCoreRelationshipContainers stixDomainObjectOrStixCoreRelationship={administrativeArea} />
              }
              />
              <Route
                path="/sightings"
                element={
                  <EntityStixSightingRelationships
                    entityId={administrativeArea.id}
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
                    id={administrativeAreaId}
                    connectorsImport={connectorsForImport}
                    connectorsExport={connectorsForExport}
                    entity={administrativeArea}
                  />
              }
              />
              <Route
                path="/history"
                element={
                  <StixCoreObjectHistory stixCoreObjectId={administrativeAreaId} />
              }
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

const RootAdministrativeArea = () => {
  const { administrativeAreaId } = useParams() as {
    administrativeAreaId: string;
  };
  const queryRef = useQueryLoading<RootAdministrativeAreaQuery>(
    administrativeAreaQuery,
    { id: administrativeAreaId },
  );
  return (
    <>
      {queryRef && (
        <React.Suspense fallback={<Loader variant={LoaderVariant.container} />}>
          <RootAdministrativeAreaComponent queryRef={queryRef} administrativeAreaId={administrativeAreaId} />
        </React.Suspense>
      )}
    </>
  );
};

export default RootAdministrativeArea;
