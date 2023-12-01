// TODO Remove this when V6
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-nocheck
import React, { useMemo } from 'react';
import { Link, Redirect, Route, Switch, useParams } from 'react-router-dom';
import { graphql, usePreloadedQuery, useSubscription } from 'react-relay';
import { GraphQLSubscriptionConfig } from 'relay-runtime';
import { useLocation } from 'react-router-dom-v5-compat';
import Box from '@mui/material/Box';
import Tabs from '@mui/material/Tabs';
import Tab from '@mui/material/Tab';
import Incident from './Incident';
import IncidentKnowledge from './IncidentKnowledge';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';
import FileManager from '../../common/files/FileManager';
import IncidentPopover from './IncidentPopover';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import StixCoreObjectHistory from '../../common/stix_core_objects/StixCoreObjectHistory';
import StixCoreObjectOrStixCoreRelationshipContainers from '../../common/containers/StixCoreObjectOrStixCoreRelationshipContainers';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import StixCoreObjectKnowledgeBar from '../../common/stix_core_objects/StixCoreObjectKnowledgeBar';
import StixDomainObjectContent from '../../common/stix_domain_objects/StixDomainObjectContent';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';

import { RootIncidentQuery } from './__generated__/RootIncidentQuery.graphql';
import { RootIncidentSubscription } from './__generated__/RootIncidentSubscription.graphql';
import { useFormatter } from '../../../../components/i18n';

const subscription = graphql`
  subscription RootIncidentSubscription($id: ID!) {
    stixDomainObject(id: $id) {
      ... on Incident {
        ...Incident_incident
        ...IncidentEditionContainer_incident
      }
      ...FileImportViewer_entity
      ...FileExportViewer_entity
      ...FileExternalReferencesViewer_entity
      ...WorkbenchFileViewer_entity
    }
  }
`;

const incidentQuery = graphql`
  query RootIncidentQuery($id: String!) {
    incident(id: $id) {
      id
      standard_id
      entity_type
      name
      aliases
      x_opencti_graph_data
      ...Incident_incident
      ...IncidentKnowledge_incident
      ...StixDomainObjectContent_stixDomainObject
      ...FileImportViewer_entity
      ...FileExportViewer_entity
      ...FileExternalReferencesViewer_entity
      ...WorkbenchFileViewer_entity
    }
    connectorsForExport {
      ...FileManager_connectorsExport
    }
    connectorsForImport {
      ...FileManager_connectorsImport
    }
  }
`;

const RootIncidentComponent = ({ queryRef }) => {
  const { incidentId } = useParams() as { incidentId: string };
  const subConfig = useMemo<
  GraphQLSubscriptionConfig<RootIncidentSubscription>
  >(
    () => ({
      subscription,
      variables: { id: incidentId },
    }),
    [incidentId],
  );
  const location = useLocation();
  const { t } = useFormatter();
  useSubscription(subConfig);
  const data = usePreloadedQuery(incidentQuery, queryRef);
  const { incident, connectorsForImport, connectorsForExport } = data;
  return (
    <>
      {incident ? (
        <div
          style={{
            paddingRight: location.pathname.includes(
              `/dashboard/events/incidents/${incident.id}/knowledge`,
            )
              ? 200
              : 0,
          }}
        >
          <StixDomainObjectHeader
            entityType="Incident"
            stixDomainObject={incident}
            PopoverComponent={IncidentPopover}
            enableQuickSubscription={true}
          />
          <Box
            sx={{ borderBottom: 1, borderColor: 'divider', marginBottom: 4 }}
          >
            <Tabs
              value={
                location.pathname.includes(
                  `/dashboard/events/incidents/${incident.id}/knowledge`,
                )
                  ? `/dashboard/events/incidents/${incident.id}/knowledge`
                  : location.pathname
              }
            >
              <Tab
                component={Link}
                to={`/dashboard/events/incidents/${incident.id}`}
                value={`/dashboard/events/incidents/${incident.id}`}
                label={t('Overview')}
              />
              <Tab
                component={Link}
                to={`/dashboard/events/incidents/${incident.id}/knowledge`}
                value={`/dashboard/events/incidents/${incident.id}/knowledge`}
                label={t('Knowledge')}
              />
              <Tab
                component={Link}
                to={`/dashboard/events/incidents/${incident.id}/analyses`}
                value={`/dashboard/events/incidents/${incident.id}/analyses`}
                label={t('Analyses')}
              />
              <Tab
                component={Link}
                to={`/dashboard/events/incidents/${incident.id}/files`}
                value={`/dashboard/events/incidents/${incident.id}/files`}
                label={t('Data')}
              />
              <Tab
                component={Link}
                to={`/dashboard/events/incidents/${incident.id}/history`}
                value={`/dashboard/events/incidents/${incident.id}/history`}
                label={t('History')}
              />
            </Tabs>
          </Box>
          <Switch>
            <Route
              exact
              path="/dashboard/events/incidents/:incidentId"
              render={() => <Incident incidentData={incident} />}
            />
            <Route
              exact
              path="/dashboard/events/incidents/:incidentId/knowledge"
              render={() => (
                <Redirect
                  to={`/dashboard/events/incidents/${incidentId}/knowledge/overview`}
                />
              )}
            />
            <Route
              path="/dashboard/events/incidents/:incidentId/knowledge"
              render={() => <IncidentKnowledge incidentData={incident} />}
            />
            <Route
              exact
              path="/dashboard/events/incidents/:incidentId/content"
              render={(routeProps) => (
                  <StixDomainObjectContent
                    {...routeProps}
                    stixDomainObject={incident}
                  />
              )}
            />
            <Route
              exact
              path="/dashboard/events/incidents/:incidentId/analyses"
              render={(routeProps) => (
                  <StixCoreObjectOrStixCoreRelationshipContainers
                    {...routeProps}
                    stixDomainObjectOrStixCoreRelationship={incident}
                  />
              )}
            />
            <Route
              exact
              path="/dashboard/events/incidents/:incidentId/files"
              render={(routeProps) => (
                  <FileManager
                    {...routeProps}
                    id={incidentId}
                    connectorsImport={connectorsForImport}
                    connectorsExport={connectorsForExport}
                    entity={incident}
                  />
              )}
            />
            <Route
              exact
              path="/dashboard/events/incidents/:incidentId/history"
              render={(routeProps) => (
                  <StixCoreObjectHistory
                    {...routeProps}
                    stixCoreObjectId={incidentId}
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

const RootIncident = () => {
  const { incidentId } = useParams() as { incidentId: string };
  const queryRef = useQueryLoading<RootIncidentQuery>(incidentQuery, {
    id: incidentId,
  });
  const link = `/dashboard/events/incidents/${incidentId}/knowledge`;
  return (
    <div>
      <Route path="/dashboard/events/incidents/:incidentId/knowledge">
        <StixCoreObjectKnowledgeBar
          stixCoreObjectLink={link}
          availableSections={[
            'attribution',
            'victimology',
            'attack_patterns',
            'malwares',
            'channels',
            'narratives',
            'tools',
            'vulnerabilities',
            'observables',
          ]}
        />
      </Route>
      {queryRef ? (
        <React.Suspense fallback={<Loader variant={LoaderVariant.container} />}>
          <RootIncidentComponent queryRef={queryRef} />
        </React.Suspense>
      ) : (
        <Loader variant={LoaderVariant.container} />
      )}
    </div>
  );
};
export default RootIncident;
