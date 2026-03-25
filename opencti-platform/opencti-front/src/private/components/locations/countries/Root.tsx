// TODO Remove this when V6
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-nocheck
import React, { useMemo } from 'react';
import { Route, Routes, useParams, useLocation, Navigate } from 'react-router-dom';
import { graphql, usePreloadedQuery, useSubscription } from 'react-relay';
import { GraphQLSubscriptionConfig } from 'relay-runtime';
import StixCoreObjectContentRoot from '@components/common/stix_core_objects/StixCoreObjectContentRoot';
import StixDomainObjectTabsBox from '@components/common/stix_domain_objects/StixDomainObjectTabsBox';
import useForceUpdate from '@components/common/bulk/useForceUpdate';
import AIInsights from '@components/common/ai/AIInsights';
import CreateRelationshipContextProvider from '@components/common/stix_core_relationships/CreateRelationshipContextProvider';
import StixCoreRelationshipCreationFromEntityHeader from '@components/common/stix_core_relationships/StixCoreRelationshipCreationFromEntityHeader';
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
import Breadcrumbs from '../../../../components/Breadcrumbs';
import { getPaddingRight } from '../../../../utils/utils';
import CountryEdition from './CountryEdition';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNUPDATE, KNOWLEDGE_KNUPDATE_KNDELETE } from '../../../../utils/hooks/useGranted';
import CountryDeletion from './CountryDeletion';
import { useEntityTypeDisplayName } from '../../../../utils/hooks/useEntityTypeDisplayName';

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
      draftVersion {
        draft_id
        draft_operation
      }
      name
      x_opencti_aliases
      x_opencti_graph_data
      currentUserAccessRight
      ...StixCoreRelationshipCreationFromEntityHeader_stixCoreObject
      ...StixCoreObjectKnowledgeBar_stixCoreObject
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
  const entityTypeDisplayName = useEntityTypeDisplayName();
  const data = usePreloadedQuery(countryQuery, queryRef);
  const { forceUpdate } = useForceUpdate();
  const { country, connectorsForImport, connectorsForExport } = data;
  const link = `/dashboard/locations/countries/${countryId}/knowledge`;
  const isOverview = location.pathname === `/dashboard/locations/countries/${countryId}`;
  const paddingRight = getPaddingRight(location.pathname, country?.id, '/dashboard/locations/countries');
  return (
    <CreateRelationshipContextProvider>
      {country ? (
        <>
          <Routes>
            <Route
              path="/knowledge/*"
              element={(
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
                  data={country}
                />
              )}
            />
          </Routes>
          <div style={{ paddingRight }}>
            <Breadcrumbs elements={[
              { label: t_i18n('Locations') },
              { label: entityTypeDisplayName('Country', t_i18n('Countries')), link: '/dashboard/locations/countries' },
              { label: country.name, current: true },
            ]}
            />
            <StixDomainObjectHeader
              entityType="Country"
              disableSharing={true}
              stixDomainObject={country}
              EditComponent={(
                <Security needs={[KNOWLEDGE_KNUPDATE]}>
                  <CountryEdition countryId={country.id} />
                </Security>
              )}
              RelateComponent={(
                <Security needs={[KNOWLEDGE_KNUPDATE]}>
                  <StixCoreRelationshipCreationFromEntityHeader
                    data={country}
                  />
                </Security>
              )}
              DeleteComponent={({ isOpen, onClose }: { isOpen: boolean; onClose: () => void }) => (
                <Security needs={[KNOWLEDGE_KNUPDATE_KNDELETE]}>
                  <CountryDeletion id={country.id} isOpen={isOpen} handleClose={onClose} />
                </Security>
              )}
              enableQuickSubscription={true}
              isOpenctiAlias={true}
              redirectToContent={true}
              enableEnrollPlaybook={true}
            />
            <StixDomainObjectTabsBox
              basePath="/dashboard/locations/countries"
              entity={country}
              tabs={[
                'overview',
                'knowledge-overview',
                'content',
                'analyses',
                'sightings',
                'files',
                'history',
              ]}
              extraActions={isOverview && <AIInsights id={country.id} />}
            />
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
                element={(
                  <div key={forceUpdate}>
                    <CountryKnowledge countryData={country} />
                  </div>
                )}
              />
              <Route
                path="/content/*"
                element={(
                  <StixCoreObjectContentRoot
                    stixCoreObject={country}
                  />
                )}
              />
              <Route
                path="/analyses"
                element={(
                  <StixCoreObjectOrStixCoreRelationshipContainers
                    stixDomainObjectOrStixCoreRelationship={country}
                  />
                )}
              />
              <Route
                path="/sightings"
                element={(
                  <EntityStixSightingRelationships
                    entityId={country.id}
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
                    id={countryId}
                    connectorsImport={connectorsForImport}
                    connectorsExport={connectorsForExport}
                    entity={country}
                  />
                )}
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
    </CreateRelationshipContextProvider>
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
