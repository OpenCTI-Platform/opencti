/* eslint-disable @typescript-eslint/no-explicit-any */
// TODO Remove this when V6
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-nocheck
import React, { useMemo } from 'react';
import { Route, Routes, useParams, Link, useLocation, Navigate } from 'react-router-dom';
import { graphql, usePreloadedQuery, useSubscription } from 'react-relay';
import { GraphQLSubscriptionConfig } from 'relay-runtime';
import Box from '@mui/material/Box';
import Tabs from '@mui/material/Tabs';
import Tab from '@mui/material/Tab';
import StixCoreObjectContentRoot from '@components/common/stix_core_objects/StixCoreObjectContentRoot';
import Region from './Region';
import RegionKnowledge from './RegionKnowledge';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';
import FileManager from '../../common/files/FileManager';
import RegionPopover from './RegionPopover';
import StixCoreObjectHistory from '../../common/stix_core_objects/StixCoreObjectHistory';
import StixCoreObjectOrStixCoreRelationshipContainers from '../../common/containers/StixCoreObjectOrStixCoreRelationshipContainers';
import StixCoreObjectKnowledgeBar from '../../common/stix_core_objects/StixCoreObjectKnowledgeBar';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import EntityStixSightingRelationships from '../../events/stix_sighting_relationships/EntityStixSightingRelationships';
import { RootCountriesSubscription } from '../countries/__generated__/RootCountriesSubscription.graphql';
import { RootRegionQuery } from './__generated__/RootRegionQuery.graphql';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import { useFormatter } from '../../../../components/i18n';
import Breadcrumbs from '../../../../components/Breadcrumbs';
import { getCurrentTab, getPaddingRight } from '../../../../utils/utils';

const subscription = graphql`
  subscription RootRegionsSubscription($id: ID!) {
    stixDomainObject(id: $id) {
      ... on Region {
        ...Region_region
        ...RegionEditionOverview_region
      }
      ...FileImportViewer_entity
      ...FileExportViewer_entity
      ...FileExternalReferencesViewer_entity
      ...WorkbenchFileViewer_entity
    }
  }
`;

const regionQuery = graphql`
  query RootRegionQuery($id: String!) {
    region(id: $id) {
      id
      name
      x_opencti_aliases
      x_opencti_graph_data
      ...Region_region
      ...RegionKnowledge_region
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

const RootRegionComponent = ({ queryRef, regionId, link }) => {
  const subConfig = useMemo<
  GraphQLSubscriptionConfig<RootCountriesSubscription>
  >(
    () => ({
      subscription,
      variables: { id: regionId },
    }),
    [regionId],
  );
  useSubscription(subConfig);
  const location = useLocation();
  const { t_i18n } = useFormatter();
  const data = usePreloadedQuery(regionQuery, queryRef);
  const { region, connectorsForImport, connectorsForExport } = data;
  const paddingRight = getPaddingRight(location.pathname, region?.id, '/dashboard/locations/regions');
  return (
    <>
      {region ? (
        <div style={{ paddingRight }}>
          <Breadcrumbs variant="object" elements={[
            { label: t_i18n('Locations') },
            { label: t_i18n('Regions'), link: '/dashboard/locations/regions' },
            { label: region.name, current: true },
          ]}
          />
          <StixDomainObjectHeader
            entityType="Region"
            disableSharing={true}
            stixDomainObject={region}
            PopoverComponent={<RegionPopover id={region.id} />}
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
              value={getCurrentTab(location.pathname, region.id, '/dashboard/locations/regions')}
            >
              <Tab
                component={Link}
                to={`/dashboard/locations/regions/${region.id}`}
                value={`/dashboard/locations/regions/${region.id}`}
                label={t_i18n('Overview')}
              />
              <Tab
                component={Link}
                to={`/dashboard/locations/regions/${region.id}/knowledge/overview`}
                value={`/dashboard/locations/regions/${region.id}/knowledge`}
                label={t_i18n('Knowledge')}
              />
              <Tab
                component={Link}
                to={`/dashboard/locations/regions/${region.id}/content`}
                value={`/dashboard/locations/regions/${region.id}/content`}
                label={t_i18n('Content')}
              />
              <Tab
                component={Link}
                to={`/dashboard/locations/regions/${region.id}/analyses`}
                value={`/dashboard/locations/regions/${region.id}/analyses`}
                label={t_i18n('Analyses')}
              />
              <Tab
                component={Link}
                to={`/dashboard/locations/regions/${region.id}/sightings`}
                value={`/dashboard/locations/regions/${region.id}/sightings`}
                label={t_i18n('Sightings')}
              />
              <Tab
                component={Link}
                to={`/dashboard/locations/regions/${region.id}/files`}
                value={`/dashboard/locations/regions/${region.id}/files`}
                label={t_i18n('Data')}
              />
              <Tab
                component={Link}
                to={`/dashboard/locations/regions/${region.id}/history`}
                value={`/dashboard/locations/regions/${region.id}/history`}
                label={t_i18n('History')}
              />
            </Tabs>
          </Box>
          <Routes>
            <Route
              path="/"
              element={<Region regionData={region} />}
            />
            <Route
              path="/knowledge"
              element={
                <Navigate to={`/dashboard/locations/regions/${regionId}/knowledge/overview`} replace={true} />
              }
            />
            <Route
              path="/knowledge/*"
              element={<RegionKnowledge regionData={region} />}
            />
            <Route
              path="/content/*"
              element={
                <StixCoreObjectContentRoot
                  stixCoreObject={region}
                />
              }
            />
            <Route
              path="/analyses"
              element={
                <StixCoreObjectOrStixCoreRelationshipContainers stixDomainObjectOrStixCoreRelationship={region} />
              }
            />
            <Route
              path="/sightings"
              element={
                <EntityStixSightingRelationships
                  entityId={region.id}
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
                  id={regionId}
                  connectorsImport={connectorsForImport}
                  connectorsExport={connectorsForExport}
                  entity={region}
                />
              }
            />
            <Route
              path="/history"
              element={
                <StixCoreObjectHistory stixCoreObjectId={regionId} />
              }
            />
          </Routes>
        </div>
      ) : (
        <ErrorNotFound />
      )}
    </>
  );
};

const RootRegion = () => {
  const { regionId } = useParams() as { regionId: string };
  const queryRef = useQueryLoading<RootRegionQuery>(regionQuery, {
    id: regionId,
  });
  const link = `/dashboard/locations/regions/${regionId}/knowledge`;
  return (
    <div>
      <Routes>
        <Route
          path="/knowledge/*"
          element={
            <StixCoreObjectKnowledgeBar
              stixCoreObjectLink={link}
              availableSections={[
                'regions',
                'countries',
                'areas',
                'cities',
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
            />
          }
        />
      </Routes>
      {queryRef && (
        <React.Suspense fallback={<Loader variant={LoaderVariant.container} />}>
          <RootRegionComponent
            queryRef={queryRef}
            regionId={regionId}
            link={link}
          />
        </React.Suspense>
      )}
    </div>
  );
};

export default RootRegion;
