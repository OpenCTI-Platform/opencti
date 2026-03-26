// TODO Remove this when V6
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-nocheck
import React, { useMemo } from 'react';
import { Navigate, Route, Routes, useLocation, useParams } from 'react-router-dom';
import { graphql, usePreloadedQuery, useSubscription } from 'react-relay';
import { GraphQLSubscriptionConfig } from 'relay-runtime';
import StixDomainObjectTabsBox from '@components/common/stix_domain_objects/StixDomainObjectTabsBox';
import StixCoreObjectContentRoot from '@components/common/stix_core_objects/StixCoreObjectContentRoot';
import useForceUpdate from '@components/common/bulk/useForceUpdate';
import CreateRelationshipContextProvider from '@components/common/stix_core_relationships/CreateRelationshipContextProvider';
import StixCoreRelationshipCreationFromEntityHeader from '@components/common/stix_core_relationships/StixCoreRelationshipCreationFromEntityHeader';
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
import Breadcrumbs from '../../../../components/Breadcrumbs';
import { getPaddingRight } from '../../../../utils/utils';
import CityEdition from './CityEdition';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNUPDATE, KNOWLEDGE_KNUPDATE_KNDELETE } from '../../../../utils/hooks/useGranted';
import CityDeletion from './CityDeletion';
import useEntityTranslation from '../../../../utils/hooks/useEntityTranslation';

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
      ...City_city
      ...CityKnowledge_city
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

const RootCityComponent = ({ queryRef, cityId }) => {
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
  const { translateEntityType } = useEntityTranslation();
  const data = usePreloadedQuery(cityQuery, queryRef);
  const { forceUpdate } = useForceUpdate();
  const { city, connectorsForImport, connectorsForExport } = data;
  const link = `/dashboard/locations/cities/${cityId}/knowledge`;
  const paddingRight = getPaddingRight(location.pathname, city?.id, '/dashboard/locations/cities');
  return (
    <CreateRelationshipContextProvider>
      {city ? (
        <>
          <Routes>
            <Route
              path="/knowledge/*"
              element={(
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
                  data={city}
                />
              )}
            />
          </Routes>
          <div style={{ paddingRight }}>
            <Breadcrumbs elements={[
              { label: t_i18n('Locations') },
              { label: translateEntityType('City', { plural: true }), link: '/dashboard/locations/cities' },
              { label: city.name, current: true },
            ]}
            />
            <StixDomainObjectHeader
              entityType="City"
              disableSharing={true}
              stixDomainObject={city}
              EditComponent={(
                <Security needs={[KNOWLEDGE_KNUPDATE]}>
                  <CityEdition cityId={city.id} />
                </Security>
              )}
              RelateComponent={(
                <Security needs={[KNOWLEDGE_KNUPDATE]}>
                  <StixCoreRelationshipCreationFromEntityHeader
                    data={city}
                  />
                </Security>
              )}
              DeleteComponent={({ isOpen, onClose }: { isOpen: boolean; onClose: () => void }) => (
                <Security needs={[KNOWLEDGE_KNUPDATE_KNDELETE]}>
                  <CityDeletion id={city.id} isOpen={isOpen} handleClose={onClose} />
                </Security>
              )}
              enableQuickSubscription={true}
              isOpenctiAlias={true}
              enableEnrollPlaybook={true}
              redirectToContent={true}
            />
            <StixDomainObjectTabsBox
              basePath="/dashboard/locations/cities"
              entity={city}
              tabs={[
                'overview',
                'knowledge-overview',
                'content',
                'analyses',
                'sightings',
                'files',
                'history',
              ]}
            />
            <Routes>
              <Route
                path="/"
                element={<City cityData={city} />}
              />
              <Route
                path="/knowledge"
                element={
                  <Navigate to={`/dashboard/locations/cities/${cityId}/knowledge/overview`} replace={true} />
                }
              />
              <Route
                path="/knowledge/*"
                element={(
                  <div key={forceUpdate}>
                    <CityKnowledge cityData={city} />
                  </div>
                )}
              />
              <Route
                path="/content/*"
                element={(
                  <StixCoreObjectContentRoot
                    stixCoreObject={city}
                  />
                )}
              />
              <Route
                path="/analyses"
                element={
                  <StixCoreObjectOrStixCoreRelationshipContainers stixDomainObjectOrStixCoreRelationship={city} />
                }
              />
              <Route
                path="/sightings"
                element={(
                  <EntityStixSightingRelationships
                    entityId={city.id}
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
                    id={cityId}
                    connectorsImport={connectorsForImport}
                    connectorsExport={connectorsForExport}
                    entity={city}
                  />
                )}
              />
              <Route
                path="/history"
                element={
                  <StixCoreObjectHistory stixCoreObjectId={cityId} />
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

const RootCity = () => {
  const { cityId } = useParams() as { cityId: string };
  const queryRef = useQueryLoading<RootCityQuery>(cityQuery, { id: cityId });
  return (
    <>
      {queryRef && (
        <React.Suspense fallback={<Loader variant={LoaderVariant.container} />}>
          <RootCityComponent queryRef={queryRef} cityId={cityId} />
        </React.Suspense>
      )}
    </>
  );
};

export default RootCity;
