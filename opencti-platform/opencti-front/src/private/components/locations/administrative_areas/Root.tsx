// TODO Remove this when V6
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-nocheck
import React, { useMemo } from 'react';
import { Redirect, Route, Switch, useParams } from 'react-router-dom';
import { graphql, usePreloadedQuery, useSubscription } from 'react-relay';
import { GraphQLSubscriptionConfig } from 'relay-runtime';
import TopBar from '../../nav/TopBar';
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
  const data = usePreloadedQuery(administrativeAreaQuery, queryRef);
  const { administrativeArea, connectorsForImport, connectorsForExport } = data;
  return (
      <>
        {administrativeArea ? (
          <Switch>
            <Route
              exact
              path="/dashboard/locations/administrative_areas/:administrativeArea"
              render={() => (
                <AdministrativeArea
                  administrativeAreaData={administrativeArea}
                />
              )}
            />
            <Route
              exact
              path="/dashboard/locations/administrative_areas/:administrativeArea/knowledge"
              render={() => (
                <Redirect
                  to={`/dashboard/locations/administrative_areas/${administrativeArea.id}/knowledge/overview`}
                />
              )}
            />
            <Route
              path="/dashboard/locations/administrative_areas/:administrativeArea/knowledge"
              render={() => (
                <AdministrativeAreaKnowledge
                  administrativeAreaData={administrativeArea}
                />
              )}
            />
            <Route
              exact
              path="/dashboard/locations/administrative_areas/:administrativeArea/analysis"
              render={(routeProps) => (
                <React.Fragment>
                  <StixDomainObjectHeader
                    disableSharing={true}
                    stixDomainObject={administrativeArea}
                    PopoverComponent={AdministrativeAreaPopover}
                  />
                  <StixCoreObjectOrStixCoreRelationshipContainers
                    {...routeProps}
                    stixDomainObjectOrStixCoreRelationship={administrativeArea}
                  />
                </React.Fragment>
              )}
            />
            <Route
              exact
              path="/dashboard/locations/administrative_areas/:administrativeArea/sightings"
              render={(routeProps) => (
                <React.Fragment>
                  <StixDomainObjectHeader
                    disableSharing={true}
                    stixDomainObject={administrativeArea}
                    PopoverComponent={AdministrativeAreaPopover}
                  />
                  <EntityStixSightingRelationships
                    entityId={administrativeArea.id}
                    entityLink={link}
                    noPadding={true}
                    isTo={true}
                    {...routeProps}
                  />
                </React.Fragment>
              )}
            />
            <Route
              exact
              path="/dashboard/locations/administrative_areas/:administrativeArea/files"
              render={(routeProps) => (
                <React.Fragment>
                  <StixDomainObjectHeader
                    disableSharing={true}
                    stixDomainObject={administrativeArea}
                    PopoverComponent={AdministrativeAreaPopover}
                  />
                  <FileManager
                    {...routeProps}
                    id={administrativeAreaId}
                    connectorsImport={connectorsForImport}
                    connectorsExport={connectorsForExport}
                    entity={administrativeArea}
                  />
                </React.Fragment>
              )}
            />
            <Route
              exact
              path="/dashboard/locations/administrative_areas/:administrativeArea/history"
              render={(routeProps) => (
                <React.Fragment>
                  <StixDomainObjectHeader
                    disableSharing={true}
                    stixDomainObject={administrativeArea}
                    PopoverComponent={AdministrativeAreaPopover}
                  />
                  <StixCoreObjectHistory
                    {...routeProps}
                    stixCoreObjectId={administrativeAreaId}
                  />
                </React.Fragment>
              )}
            />
          </Switch>
        ) : (
          <ErrorNotFound />
        )}
      </>
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
    <div>
      <TopBar />
      <Route path="/dashboard/locations/administrative_areas/:administrativeArea/knowledge">
        <StixCoreObjectKnowledgeBar
          stixCoreObjectLink={link}
          availableSections={[
            'organizations',
            'countries',
            'regions',
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
      {
        queryRef ? (
          <React.Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
            <RootAdministrativeAreaComponent queryRef={queryRef} administrativeAreaId={administrativeAreaId}/>
          </React.Suspense>
        ) : (
          <Loader variant={LoaderVariant.inElement} />
        )
      }
    </div>
  );
};

export default RootAdministrativeArea;
