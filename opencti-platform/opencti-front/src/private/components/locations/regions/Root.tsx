/* eslint-disable @typescript-eslint/no-explicit-any */
// TODO Remove this when V6
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-nocheck
import React, { useMemo } from 'react';
import { Route, Redirect, Switch, useParams } from 'react-router-dom';
import { graphql, usePreloadedQuery, useSubscription } from 'react-relay';
import { GraphQLSubscriptionConfig } from 'relay-runtime';
import TopBar from '../../nav/TopBar';
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
import useAuth from '../../../../utils/hooks/useAuth';
import { RootCountriesSubscription } from '../countries/__generated__/RootCountriesSubscription.graphql';
import { RootRegionQuery } from './__generated__/RootRegionQuery.graphql';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import Loader, { LoaderVariant } from '../../../../components/Loader';

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
    connectorsForExport {
      ...FileManager_connectorsExport
    }
    settings {
      platform_enable_reference
    }
  }
`;

const RootRegionComponent = ({ queryRef }) => {
  const { me } = useAuth();
  const { regionId } = useParams() as { regionId: string };

  const link = `/dashboard/locations/regions/${regionId}/knowledge`;
  const subConfig = useMemo<GraphQLSubscriptionConfig<RootCountriesSubscription>>(() => ({
    subscription,
    variables: { id: regionId },
  }), [regionId]);
  useSubscription(subConfig);

  const data = usePreloadedQuery(regionQuery, queryRef);
  const { region, connectorsForExport } = data;

  return (
      <div>
        <TopBar me={me} />
        <Route path="/dashboard/locations/regions/:regionId/knowledge">
          <StixCoreObjectKnowledgeBar
            stixCoreObjectLink={link}
            availableSections={[
              'countries',
              'cities',
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
        <>
          {region ? (
             <Switch>
                    <Route
                      exact
                      path="/dashboard/locations/regions/:regionId"
                      render={() => (<Region regionData={region} />)}
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
                      render={() => (<RegionKnowledge regionData={region} />)}
                    />
                    <Route
                      exact
                      path="/dashboard/locations/regions/:regionId/analysis"
                      render={(routeProps: any) => (
                        <React.Fragment>
                          <StixDomainObjectHeader
                            disableSharing={true}
                            stixDomainObject={region}
                            PopoverComponent={<RegionPopover id={region.id} />}
                          />
                          <StixCoreObjectOrStixCoreRelationshipContainers
                            {...routeProps}
                            stixDomainObjectOrStixCoreRelationship={region}
                          />
                        </React.Fragment>
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
                        <React.Fragment>
                          <StixDomainObjectHeader
                            disableSharing={true}
                            stixDomainObject={region}
                            PopoverComponent={<RegionPopover id={region.id} />}
                          />
                          <FileManager
                            {...routeProps}
                            id={regionId}
                            connectorsImport={[]}
                            connectorsExport={connectorsForExport}
                            entity={region}
                          />
                        </React.Fragment>
                      )}
                    />
                    <Route
                      exact
                      path="/dashboard/locations/regions/:regionId/history"
                      render={(routeProps: any) => (
                        <React.Fragment>
                          <StixDomainObjectHeader
                            disableSharing={true}
                            stixDomainObject={region}
                            PopoverComponent={<RegionPopover id={region.id} />}
                          />
                          <StixCoreObjectHistory
                            {...routeProps}
                            stixCoreObjectId={regionId}
                          />
                        </React.Fragment>
                      )}
                    />
                  </Switch>
          ) : <ErrorNotFound />}
        </>
      </div>
  );
};

const RootRegion = () => {
  const { regionId } = useParams() as { regionId: string };

  const queryRef = useQueryLoading<RootRegionQuery>(regionQuery, { id: regionId });
  return queryRef ? (
    <React.Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
      <RootRegionComponent queryRef={queryRef} />
    </React.Suspense>
  ) : <Loader variant={LoaderVariant.inElement} />;
};

export default RootRegion;
