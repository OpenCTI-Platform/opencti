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
import Country from './Country';
import CountryKnowledge from './CountryKnowledge';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';
import FileManager from '../../common/files/FileManager';
import StixCoreObjectHistory from '../../common/stix_core_objects/StixCoreObjectHistory';
import StixCoreObjectOrStixCoreRelationshipContainers from '../../common/containers/StixCoreObjectOrStixCoreRelationshipContainers';
import StixCoreObjectKnowledgeBar from '../../common/stix_core_objects/StixCoreObjectKnowledgeBar';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import EntityStixSightingRelationships from '../../events/stix_sighting_relationships/EntityStixSightingRelationships';
import { RootCountriesSubscription } from './__generated__/RootCountriesSubscription.graphql';
import { RootCountryQuery } from './__generated__/RootCountryQuery.graphql';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import { useFormatter } from '../../../../components/i18n';
import CountryPopover from './CountryPopover';

const subscription = graphql`
  subscription RootCountriesSubscription($id: ID!) {
    stixDomainObject(id: $id) {
      ... on Country {
        ...Country_country
        ...CountryEditionOverview_country
      }
      ...FileImportViewer_entity
      ...FileExportViewer_entity
      ...FileExternalReferencesViewer_entity
      ...WorkbenchFileViewer_entity
    }
  }
`;

const countryQuery = graphql`
  query RootCountryQuery($id: String!) {
    country(id: $id) {
      id
      name
      x_opencti_aliases
      x_opencti_graph_data
      ...Country_country
      ...CountryKnowledge_country
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

const RootCountryComponent = ({ queryRef, countryId, link }) => {
  const subConfig = useMemo<
  GraphQLSubscriptionConfig<RootCountriesSubscription>
  >(
    () => ({
      subscription,
      variables: { id: countryId },
    }),
    [countryId],
  );
  useSubscription(subConfig);
  const location = useLocation();
  const { t } = useFormatter();
  const data = usePreloadedQuery(countryQuery, queryRef);
  const { country, connectorsForImport, connectorsForExport } = data;
  return (
    <>
      {country ? (
        <div
          style={{
            paddingRight: location.pathname.includes(
              `/dashboard/locations/countries/${country.id}/knowledge`,
            )
              ? 200
              : 0,
          }}
        >
          <StixDomainObjectHeader
            entityType="Country"
            disableSharing={true}
            stixDomainObject={country}
            PopoverComponent={<CountryPopover id={country.id} />}
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
              value={
                location.pathname.includes(
                  `/dashboard/locations/countries/${country.id}/knowledge`,
                )
                  ? `/dashboard/locations/countries/${country.id}/knowledge`
                  : location.pathname
              }
            >
              <Tab
                component={Link}
                to={`/dashboard/locations/countries/${country.id}`}
                value={`/dashboard/locations/countries/${country.id}`}
                label={t('Overview')}
              />
              <Tab
                component={Link}
                to={`/dashboard/locations/countries/${country.id}/knowledge`}
                value={`/dashboard/locations/countries/${country.id}/knowledge`}
                label={t('Knowledge')}
              />
              <Tab
                component={Link}
                to={`/dashboard/locations/countries/${country.id}/analyses`}
                value={`/dashboard/locations/countries/${country.id}/analyses`}
                label={t('Analyses')}
              />
              <Tab
                component={Link}
                to={`/dashboard/locations/countries/${country.id}/sightings`}
                value={`/dashboard/locations/countries/${country.id}/sightings`}
                label={t('Sightings')}
              />
              <Tab
                component={Link}
                to={`/dashboard/locations/countries/${country.id}/files`}
                value={`/dashboard/locations/countries/${country.id}/files`}
                label={t('Data')}
              />
              <Tab
                component={Link}
                to={`/dashboard/locations/countries/${country.id}/history`}
                value={`/dashboard/locations/countries/${country.id}/history`}
                label={t('History')}
              />
            </Tabs>
          </Box>
          <Switch>
            <Route
              exact
              path="/dashboard/locations/countries/:countryId"
              render={() => <Country countryData={country} />}
            />
            <Route
              exact
              path="/dashboard/locations/countries/:countryId/knowledge"
              render={() => (
                <Redirect
                  to={`/dashboard/locations/countries/${countryId}/knowledge/overview`}
                />
              )}
            />
            <Route
              path="/dashboard/locations/countries/:countryId/knowledge"
              render={() => <CountryKnowledge countryData={country} />}
            />
            <Route
              exact
              path="/dashboard/locations/countries/:countryId/analyses"
              render={(routeProps) => (
                <StixCoreObjectOrStixCoreRelationshipContainers
                  {...routeProps}
                  stixDomainObjectOrStixCoreRelationship={country}
                />
              )}
            />
            <Route
              exact
              path="/dashboard/locations/countries/:countryId/sightings"
              render={(routeProps) => (
                <EntityStixSightingRelationships
                  entityId={country.id}
                  entityLink={link}
                  noPadding={true}
                  isTo={true}
                  {...routeProps}
                />
              )}
            />
            <Route
              exact
              path="/dashboard/locations/countries/:countryId/files"
              render={(routeProps) => (
                <FileManager
                  {...routeProps}
                  id={countryId}
                  connectorsImport={connectorsForImport}
                  connectorsExport={connectorsForExport}
                  entity={country}
                />
              )}
            />
            <Route
              exact
              path="/dashboard/locations/countries/:countryId/history"
              render={(routeProps) => (
                <StixCoreObjectHistory
                  {...routeProps}
                  stixCoreObjectId={countryId}
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

const RootCountry = () => {
  const { countryId } = useParams() as { countryId: string };

  const queryRef = useQueryLoading<RootCountryQuery>(countryQuery, {
    id: countryId,
  });
  const link = `/dashboard/locations/countries/${countryId}/knowledge`;
  return (
    <div>
      <Route path="/dashboard/locations/countries/:countryId/knowledge">
        <StixCoreObjectKnowledgeBar
          stixCoreObjectLink={link}
          availableSections={[
            'regions',
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
          <RootCountryComponent
            queryRef={queryRef}
            countryId={countryId}
            link={link}
          />
        </React.Suspense>
      )}
    </div>
  );
};

export default RootCountry;
