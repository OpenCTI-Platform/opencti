// TODO Remove this when V6
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-nocheck
import React, { useMemo } from 'react';
import { Link, Redirect, Route, Switch, useLocation, useParams } from 'react-router-dom';
import { graphql, usePreloadedQuery, useSubscription } from 'react-relay';
import { GraphQLSubscriptionConfig } from 'relay-runtime';
import Box from '@mui/material/Box';
import Tabs from '@mui/material/Tabs';
import Tab from '@mui/material/Tab';
import City from './City';
import CityKnowledge from './CityKnowledge';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';
import FileManager from '../../common/files/FileManager';
import StixCoreObjectHistory from '../../common/stix_core_objects/StixCoreObjectHistory';
import StixCoreObjectOrStixCoreRelationshipContainers from '../../common/containers/StixCoreObjectOrStixCoreRelationshipContainers';
import StixCoreObjectKnowledgeBar from '../../common/stix_core_objects/StixCoreObjectKnowledgeBar';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import EntityStixSightingRelationships from '../../events/stix_sighting_relationships/EntityStixSightingRelationships';
import { RootCityQuery } from './__generated__/RootCityQuery.graphql';
import { RootCitiesSubscription } from './__generated__/RootCitiesSubscription.graphql';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import { useFormatter } from '../../../../components/i18n';
import CityPopover from './CityPopover';
import Breadcrumbs from '../../../../components/Breadcrumbs';

const subscription = graphql`
  subscription RootCitiesSubscription($id: ID!) {
    stixDomainObject(id: $id) {
      ... on City {
        ...City_city
        ...CityEditionOverview_city
      }
      ...FileImportViewer_entity
      ...FileExportViewer_entity
      ...FileExternalReferencesViewer_entity
      ...WorkbenchFileViewer_entity
    }
  }
`;

const cityQuery = graphql`
  query RootCityQuery($id: String!) {
    city(id: $id) {
      id
      name
      x_opencti_aliases
      x_opencti_graph_data
      ...City_city
      ...CityKnowledge_city
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

const RootCityComponent = ({ queryRef, cityId, link }) => {
  const subConfig = useMemo<GraphQLSubscriptionConfig<RootCitiesSubscription>>(
    () => ({
      subscription,
      variables: { id: cityId },
    }),
    [cityId],
  );
  useSubscription(subConfig);
  const location = useLocation();
  const { t_i18n } = useFormatter();
  const data = usePreloadedQuery(cityQuery, queryRef);
  const { city, connectorsForImport, connectorsForExport } = data;
  return (
    <>
      {city ? (
        <div
          style={{
            paddingRight: location.pathname.includes(
              `/dashboard/locations/cities/${city.id}/knowledge`,
            )
              ? 200
              : 0,
          }}
        >
          <Breadcrumbs variant="object" elements={[
            { label: t_i18n('Locations') },
            { label: t_i18n('Cities'), link: '/dashboard/locations/cities' },
            { label: city.name, current: true },
          ]}
          />
          <StixDomainObjectHeader
            entityType="City"
            disableSharing={true}
            stixDomainObject={city}
            PopoverComponent={<CityPopover id={city.id} />}
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
                  `/dashboard/locations/cities/${city.id}/knowledge`,
                )
                  ? `/dashboard/locations/cities/${city.id}/knowledge`
                  : location.pathname
              }
            >
              <Tab
                component={Link}
                to={`/dashboard/locations/cities/${city.id}`}
                value={`/dashboard/locations/cities/${city.id}`}
                label={t_i18n('Overview')}
              />
              <Tab
                component={Link}
                to={`/dashboard/locations/cities/${city.id}/knowledge`}
                value={`/dashboard/locations/cities/${city.id}/knowledge`}
                label={t_i18n('Knowledge')}
              />
              <Tab
                component={Link}
                to={`/dashboard/locations/cities/${city.id}/analyses`}
                value={`/dashboard/locations/cities/${city.id}/analyses`}
                label={t_i18n('Analyses')}
              />
              <Tab
                component={Link}
                to={`/dashboard/locations/cities/${city.id}/sightings`}
                value={`/dashboard/locations/cities/${city.id}/sightings`}
                label={t_i18n('Sightings')}
              />
              <Tab
                component={Link}
                to={`/dashboard/locations/cities/${city.id}/files`}
                value={`/dashboard/locations/cities/${city.id}/files`}
                label={t_i18n('Data')}
              />
              <Tab
                component={Link}
                to={`/dashboard/locations/cities/${city.id}/history`}
                value={`/dashboard/locations/cities/${city.id}/history`}
                label={t_i18n('History')}
              />
            </Tabs>
          </Box>
          <Switch>
            <Route
              exact
              path="/dashboard/locations/cities/:cityId"
              render={() => <City cityData={city} />}
            />
            <Route
              exact
              path="/dashboard/locations/cities/:cityId/knowledge"
              render={() => (
                <Redirect
                  to={`/dashboard/locations/cities/${cityId}/knowledge/overview`}
                />
              )}
            />
            <Route
              path="/dashboard/locations/cities/:cityId/knowledge"
              render={() => <CityKnowledge cityData={city} />}
            />
            <Route
              exact
              path="/dashboard/locations/cities/:cityId/analyses"
              render={(routeProps) => (
                <StixCoreObjectOrStixCoreRelationshipContainers
                  {...routeProps}
                  stixDomainObjectOrStixCoreRelationship={city}
                />
              )}
            />
            <Route
              exact
              path="/dashboard/locations/cities/:cityId/sightings"
              render={(routeProps) => (
                <EntityStixSightingRelationships
                  entityId={city.id}
                  entityLink={link}
                  noPadding={true}
                  isTo={true}
                  {...routeProps}
                />
              )}
            />
            <Route
              exact
              path="/dashboard/locations/cities/:cityId/files"
              render={(routeProps) => (
                <FileManager
                  {...routeProps}
                  id={cityId}
                  connectorsImport={connectorsForImport}
                  connectorsExport={connectorsForExport}
                  entity={city}
                />
              )}
            />
            <Route
              exact
              path="/dashboard/locations/cities/:cityId/history"
              render={(routeProps) => (
                <StixCoreObjectHistory
                  {...routeProps}
                  stixCoreObjectId={cityId}
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

const RootCity = () => {
  const { cityId } = useParams() as { cityId: string };
  const queryRef = useQueryLoading<RootCityQuery>(cityQuery, { id: cityId });
  const link = `/dashboard/locations/cities/${cityId}/knowledge`;
  return (
    <>
      <Route path="/dashboard/locations/cities/:cityId/knowledge">
        <StixCoreObjectKnowledgeBar
          stixCoreObjectLink={link}
          availableSections={[
            'organizations',
            'regions',
            'countries',
            'areas',
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
          <RootCityComponent queryRef={queryRef} cityId={cityId} link={link} />
        </React.Suspense>
      )}
    </>
  );
};

export default RootCity;
