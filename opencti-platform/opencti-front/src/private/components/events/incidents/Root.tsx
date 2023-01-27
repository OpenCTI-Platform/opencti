// TODO Remove this when V6
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-nocheck
import React, { useMemo } from 'react';
import { Route, Redirect, Switch, useParams } from 'react-router-dom';
import { graphql, usePreloadedQuery, useSubscription } from 'react-relay';
import { GraphQLSubscriptionConfig } from 'relay-runtime';
import TopBar from '../../nav/TopBar';
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
  const link = `/dashboard/events/incidents/${incidentId}/knowledge`;
  const subConfig = useMemo<GraphQLSubscriptionConfig<RootIncidentSubscription>>(
    () => ({
      subscription,
      variables: { id: incidentId },
    }),
    [incidentId],
  );
  useSubscription(subConfig);
  const data = usePreloadedQuery(incidentQuery, queryRef);
  const { incident, connectorsForImport, connectorsForExport } = data;
  return (
      <div>
        <TopBar />
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
        <>
          {incident ? (
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
                      render={() => (
                        <IncidentKnowledge
                          incidentData={incident}
                        />
                      )}
                    />
                    <Route
                      exact
                      path="/dashboard/events/incidents/:incidentId/content"
                      render={(routeProps) => (
                        <React.Fragment>
                          <StixDomainObjectHeader
                            entityType={'Incident'}
                            stixDomainObject={incident}
                            PopoverComponent={IncidentPopover}
                            disableSharing={true}
                          />
                          <StixDomainObjectContent
                            {...routeProps}
                            stixDomainObject={incident}
                          />
                        </React.Fragment>
                      )}
                    />
                    <Route
                      exact
                      path="/dashboard/events/incidents/:incidentId/analysis"
                      render={(routeProps) => (
                        <React.Fragment>
                          <StixDomainObjectHeader
                            entityType={'Incident'}
                            stixDomainObject={incident}
                            PopoverComponent={IncidentPopover}
                          />
                          <StixCoreObjectOrStixCoreRelationshipContainers
                            {...routeProps}
                            stixDomainObjectOrStixCoreRelationship={
                              incident
                            }
                          />
                        </React.Fragment>
                      )}
                    />
                    <Route
                      exact
                      path="/dashboard/events/incidents/:incidentId/files"
                      render={(routeProps) => (
                        <React.Fragment>
                          <StixDomainObjectHeader
                            entityType={'Incident'}
                            stixDomainObject={incident}
                            PopoverComponent={IncidentPopover}
                          />
                          <FileManager
                            {...routeProps}
                            id={incidentId}
                            connectorsImport={connectorsForImport}
                            connectorsExport={connectorsForExport}
                            entity={incident}
                          />
                        </React.Fragment>
                      )}
                    />
                    <Route
                      exact
                      path="/dashboard/events/incidents/:incidentId/history"
                      render={(routeProps) => (
                        <React.Fragment>
                          <StixDomainObjectHeader
                            entityType={'Incident'}
                            stixDomainObject={incident}
                            PopoverComponent={IncidentPopover}
                          />
                          <StixCoreObjectHistory
                            {...routeProps}
                            stixCoreObjectId={incidentId}
                          />
                        </React.Fragment>
                      )}
                    />
                  </Switch>
          ) : (
            <ErrorNotFound />
          )}
        </>
      </div>
  );
};

const RootIncident = () => {
  const { incidentId } = useParams() as { incidentId: string };
  const queryRef = useQueryLoading < RootIncidentQuery >(incidentQuery, { id: incidentId });
  return queryRef ? (
    <React.Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
      <RootIncidentComponent queryRef={queryRef} />
    </React.Suspense>
  ) : (
    <Loader variant={LoaderVariant.inElement} />
  );
};
export default RootIncident;
