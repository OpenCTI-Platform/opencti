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
import { useFormatter } from '../../../../components/i18n';

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
    <>
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
          <StixDomainObjectHeader
            entityType="administrativeArea"
            disableSharing={true}
            stixDomainObject={administrativeArea}
            PopoverComponent={
              <AdministrativeAreaPopover id={administrativeArea.id} />
            }
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
                to={`/dashboard/locations/administrative_areas/${administrativeArea.id}/knowledge`}
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
              path="/dashboard/locations/administrative_areas/:administrativeArea/analyses"
              render={(routeProps) => (
                <StixCoreObjectOrStixCoreRelationshipContainers
                  {...routeProps}
                  stixDomainObjectOrStixCoreRelationship={administrativeArea}
                />
              )}
            />
            <Route
              exact
              path="/dashboard/locations/administrative_areas/:administrativeArea/sightings"
              render={(routeProps) => (
                <EntityStixSightingRelationships
                  entityId={administrativeArea.id}
                  entityLink={link}
                  noPadding={true}
                  isTo={true}
                  {...routeProps}
                />
              )}
            />
            <Route
              exact
              path="/dashboard/locations/administrative_areas/:administrativeArea/files"
              render={(routeProps) => (
                <FileManager
                  {...routeProps}
                  id={administrativeAreaId}
                  connectorsImport={connectorsForImport}
                  connectorsExport={connectorsForExport}
                  entity={administrativeArea}
                />
              )}
            />
            <Route
              exact
              path="/dashboard/locations/administrative_areas/:administrativeArea/history"
              render={(routeProps) => (
                <StixCoreObjectHistory
                  {...routeProps}
                  stixCoreObjectId={administrativeAreaId}
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
      <Route path="/dashboard/locations/administrative_areas/:administrativeArea/knowledge">
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
      </Route>
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
