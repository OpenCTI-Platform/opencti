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
import Security from 'src/utils/Security';
import { KNOWLEDGE_KNUPDATE } from 'src/utils/hooks/useGranted';
import CreateRelationshipButtonComponent from '@components/common/menus/RelateComponent';
import RelateComponentContextProvider from '@components/common/menus/RelateComponentProvider';
import AdministrativeArea from './AdministrativeArea';
import AdministrativeAreaKnowledge from './AdministrativeAreaKnowledge';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';
import FileManager from '../../common/files/FileManager';
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
import AdministrativeAreaEdition from './AdministrativeAreaEdition';

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
      created_at
      updated_at
      ...AdministrativeArea_administrativeArea
      ...AdministrativeAreaKnowledge_administrativeArea
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

const RootAdministrativeAreaComponent = ({
  queryRef,
  administrativeAreaId,
  link,
}) => {
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
  const { t_i18n } = useFormatter();
  const data = usePreloadedQuery(administrativeAreaQuery, queryRef);
  const { administrativeArea, connectorsForImport, connectorsForExport } = data;
  return (
    <RelateComponentContextProvider>
      {administrativeArea ? (
        <div
          style={{
            paddingRight: location.pathname.includes(
              `/dashboard/locations/administrative_areas/${administrativeArea.id}/knowledge`,
            )
              ? 200
              : 0,
          }}
        >
          <Breadcrumbs variant="object" elements={[
            { label: t_i18n('Locations') },
            { label: t_i18n('Administrative areas'), link: '/dashboard/locations/administrative_areas' },
            { label: administrativeArea.name, current: true },
          ]}
          />
          <StixDomainObjectHeader
            entityType="Administrative-Area"
            disableSharing={true}
            stixDomainObject={administrativeArea}
            EditComponent={<Security needs={[KNOWLEDGE_KNUPDATE]}>
              <AdministrativeAreaEdition
                administrativeAreaId={administrativeArea.id}
              />
            </Security>}
            RelateComponent={<CreateRelationshipButtonComponent
              id={administrativeArea.id}
              defaultStartTime={administrativeArea.created_at}
              defaultStopTime={administrativeArea.updated_at}
                             />}
            enableQuickSubscription={true}
            isOpenctiAlias={true}
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
                  `/dashboard/locations/administrative_areas/${administrativeArea.id}/knowledge`,
                )
                  ? `/dashboard/locations/administrative_areas/${administrativeArea.id}/knowledge`
                  : location.pathname
              }
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
                <Navigate to={`/dashboard/locations/administrative_areas/${administrativeArea.id}/knowledge/overview`} />
              }
            />
            <Route
              path="/knowledge/*"
              element={
                <AdministrativeAreaKnowledge administrativeAreaData={administrativeArea} />
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
      ) : (
        <ErrorNotFound />
      )}
    </RelateComponentContextProvider>
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
  const link = `/dashboard/locations/administrative_areas/${administrativeAreaId}/knowledge`;
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
            />
          }
        />
      </Routes>
      {queryRef && (
        <React.Suspense fallback={<Loader variant={LoaderVariant.container} />}>
          <RootAdministrativeAreaComponent
            queryRef={queryRef}
            administrativeAreaId={administrativeAreaId}
            link={link}
          />
        </React.Suspense>
      )}
    </>
  );
};

export default RootAdministrativeArea;
