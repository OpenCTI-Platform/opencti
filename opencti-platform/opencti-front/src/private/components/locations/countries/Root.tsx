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
import Breadcrumbs from '../../../../components/Breadcrumbs';
import { getCurrentTab, getPaddingRight } from '../../../../utils/utils';

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
      stixCoreObjectsDistribution(field: "entity_type", operation: count) {
        label
        value
      }
      ...Country_country
      ...CountryKnowledge_country
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

const RootCountryComponent = ({ queryRef, countryId }) => {
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
  const { t_i18n } = useFormatter();
  const data = usePreloadedQuery(countryQuery, queryRef);
  const { country, connectorsForImport, connectorsForExport } = data;
  const link = `/dashboard/locations/countries/${countryId}/knowledge`;
  const paddingRight = getPaddingRight(location.pathname, country?.id, '/dashboard/locations/countries');
  return (
    <>
      {country ? (
        <>
          <Routes>
            <Route
              path="/knowledge/*"
              element={
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
                  stixCoreObjectsDistribution={country.stixCoreObjectsDistribution}
                />
              }
            />
          </Routes>
          <div style={{ paddingRight }}>
            <Breadcrumbs variant="object" elements={[
              { label: t_i18n('Locations') },
              { label: t_i18n('Countries'), link: '/dashboard/locations/countries' },
              { label: country.name, current: true },
            ]}
            />
            <StixDomainObjectHeader
              entityType="Country"
              disableSharing={true}
              stixDomainObject={country}
              PopoverComponent={<CountryPopover id={country.id} />}
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
                value={getCurrentTab(location.pathname, country.id, '/dashboard/locations/countries')}
              >
                <Tab
                  component={Link}
                  to={`/dashboard/locations/countries/${country.id}`}
                  value={`/dashboard/locations/countries/${country.id}`}
                  label={t_i18n('Overview')}
                />
                <Tab
                  component={Link}
                  to={`/dashboard/locations/countries/${country.id}/knowledge/overview`}
                  value={`/dashboard/locations/countries/${country.id}/knowledge`}
                  label={t_i18n('Knowledge')}
                />
                <Tab
                  component={Link}
                  to={`/dashboard/locations/countries/${country.id}/content`}
                  value={`/dashboard/locations/countries/${country.id}/content`}
                  label={t_i18n('Content')}
                />
                <Tab
                  component={Link}
                  to={`/dashboard/locations/countries/${country.id}/analyses`}
                  value={`/dashboard/locations/countries/${country.id}/analyses`}
                  label={t_i18n('Analyses')}
                />
                <Tab
                  component={Link}
                  to={`/dashboard/locations/countries/${country.id}/sightings`}
                  value={`/dashboard/locations/countries/${country.id}/sightings`}
                  label={t_i18n('Sightings')}
                />
                <Tab
                  component={Link}
                  to={`/dashboard/locations/countries/${country.id}/files`}
                  value={`/dashboard/locations/countries/${country.id}/files`}
                  label={t_i18n('Data')}
                />
                <Tab
                  component={Link}
                  to={`/dashboard/locations/countries/${country.id}/history`}
                  value={`/dashboard/locations/countries/${country.id}/history`}
                  label={t_i18n('History')}
                />
              </Tabs>
            </Box>
            <Routes>
              <Route
                path="/"
                element={<Country countryData={country} />}
              />
              <Route
                path="/knowledge"
                element={
                  <Navigate to={`/dashboard/locations/countries/${countryId}/knowledge/overview`} replace={true} />
              }
              />
              <Route
                path="/knowledge/*"
                element={<CountryKnowledge countryData={country} />}
              />
              <Route
                path="/content/*"
                element={
                  <StixCoreObjectContentRoot
                    stixCoreObject={country}
                  />
              }
              />
              <Route
                path="/analyses"
                element={
                  <StixCoreObjectOrStixCoreRelationshipContainers
                    stixDomainObjectOrStixCoreRelationship={country}
                  />
              }
              />
              <Route
                path="/sightings"
                element={
                  <EntityStixSightingRelationships
                    entityId={country.id}
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
                    id={countryId}
                    connectorsImport={connectorsForImport}
                    connectorsExport={connectorsForExport}
                    entity={country}
                  />
              }
              />
              <Route
                path="/history"
                element={
                  <StixCoreObjectHistory stixCoreObjectId={countryId} />
              }
              />
            </Routes>
          </div>
        </>
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
  return (
    <>
      {queryRef && (
        <React.Suspense fallback={<Loader variant={LoaderVariant.container} />}>
          <RootCountryComponent queryRef={queryRef} countryId={countryId} />
        </React.Suspense>
      )}
    </>
  );
};

export default RootCountry;
