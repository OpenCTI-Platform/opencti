/* eslint-disable @typescript-eslint/no-explicit-any */
// TODO Remove this when V6
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-nocheck
import React, { useMemo } from 'react';
import { Route, Redirect, Switch, useParams, Link, useLocation } from 'react-router-dom';
import { graphql, usePreloadedQuery, useSubscription } from 'react-relay';
import { GraphQLSubscriptionConfig } from 'relay-runtime';
import Box from '@mui/material/Box';
import Tabs from '@mui/material/Tabs';
import Tab from '@mui/material/Tab';
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
  return (
    <>
      {region ? (
        <div
          style={{
            paddingRight: location.pathname.includes(
              `/dashboard/locations/regions/${region.id}/knowledge`,
            )
              ? 200
              : 0,
          }}
        >
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
              value={
                location.pathname.includes(
                  `/dashboard/locations/regions/${region.id}/knowledge`,
                )
                  ? `/dashboard/locations/regions/${region.id}/knowledge`
                  : location.pathname
              }
            >
              <Tab
                component={Link}
                to={`/dashboard/locations/regions/${region.id}`}
                value={`/dashboard/locations/regions/${region.id}`}
                label={t_i18n('Overview')}
              />
              <Tab
                component={Link}
                to={`/dashboard/locations/regions/${region.id}/knowledge`}
                value={`/dashboard/locations/regions/${region.id}/knowledge`}
                label={t_i18n('Knowledge')}
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
          <Switch>
            <Route
              exact
              path="/dashboard/locations/regions/:regionId"
              render={() => <Region regionData={region} />}
            />
            <Route
              exact
              path="/dashboard/locations/regions/:regionId/knowledge"
              render={() => (
                <Redirect
                  to={`/dashboard/locations/regions/${regionId}/knowledge/overview`}
                />
              )}
            />
            <Route
              path="/dashboard/locations/regions/:regionId/knowledge"
              render={() => <RegionKnowledge regionData={region} />}
            />
            <Route
              exact
              path="/dashboard/locations/regions/:regionId/analyses"
              render={(routeProps: any) => (
                <StixCoreObjectOrStixCoreRelationshipContainers
                  {...routeProps}
                  stixDomainObjectOrStixCoreRelationship={region}
                />
              )}
            />
            <Route
              exact
              path="/dashboard/locations/regions/:regionId/sightings"
              render={(routeProps: any) => (
                <EntityStixSightingRelationships
                  entityId={region.id}
                  entityLink={link}
                  noPadding={true}
                  isTo={true}
                  {...routeProps}
                />
              )}
            />
            <Route
              exact
              path="/dashboard/locations/regions/:regionId/files"
              render={(routeProps: any) => (
                <FileManager
                  {...routeProps}
                  id={regionId}
                  connectorsImport={connectorsForImport}
                  connectorsExport={connectorsForExport}
                  entity={region}
                />
              )}
            />
            <Route
              exact
              path="/dashboard/locations/regions/:regionId/history"
              render={(routeProps: any) => (
                <StixCoreObjectHistory
                  {...routeProps}
                  stixCoreObjectId={regionId}
                />
              )}
            />
          </Switch>
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
      <Route path="/dashboard/locations/regions/:regionId/knowledge">
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
      </Route>
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
