/* eslint-disable @typescript-eslint/no-explicit-any */
// TODO Remove this when V6
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-nocheck
import React, { useMemo } from 'react';
import { Route, Switch, useParams } from 'react-router-dom';
import { graphql, usePreloadedQuery, useSubscription } from 'react-relay';
import { GraphQLSubscriptionConfig } from 'relay-runtime';
import TopBar from '../../nav/TopBar';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import useAuth from '../../../../utils/hooks/useAuth';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import ContainerHeader from '../../common/containers/ContainerHeader';
import StixDomainObjectContent from '../../common/stix_domain_objects/StixDomainObjectContent';
import StixCoreObjectFilesAndHistory from '../../common/stix_core_objects/StixCoreObjectFilesAndHistory';
import StixCoreObjectHistory from '../../common/stix_core_objects/StixCoreObjectHistory';
import { RootThreatActorIndividualQuery } from './__generated__/RootThreatActorIndividualQuery.graphql';
import { RootThreatActorIndividualSubscription } from './__generated__/RootThreatActorIndividualSubscription.graphql';
import ThreatActorIndividualPopover from './ThreatActorIndividualPopover';
import ThreatActorIndividual from './ThreatActorIndividual';

const subscription = graphql`
  subscription RootThreatActorIndividualSubscription($id: ID!) {
    stixDomainObject(id: $id) {
      ... on ThreatActorIndividual {
        ...ThreatActorIndividual_ThreatActorIndividual
      }
      ...FileImportViewer_entity
      ...FileExportViewer_entity
      ...FileExternalReferencesViewer_entity
      ...WorkbenchFileViewer_entity
    }
  }
`;

const ThreatActorIndividualQuery = graphql`
  query RootThreatActorIndividualQuery($id: String!) {
    threatActorIndividual(id: $id) {
      id
      standard_id
      name
      x_opencti_graph_data
      ...FileImportViewer_entity
      ...FileExportViewer_entity
      ...FileExternalReferencesViewer_entity
      ...WorkbenchFileViewer_entity
      ...StixDomainObjectContent_stixDomainObject
    }
    connectorsForExport {
      ...StixCoreObjectFilesAndHistory_connectorsExport
    }
    connectorsForImport {
      ...StixCoreObjectFilesAndHistory_connectorsImport
    }
  }
`;

const RootThreatActorIndividualComponent = ({ queryRef, threatActorIndividualId }) => {
  const { me } = useAuth();
  const subConfig = useMemo<GraphQLSubscriptionConfig<RootThreatActorIndividualSubscription>>(
    () => ({
      subscription,
      variables: { id: threatActorIndividualId },
    }),
    [threatActorIndividualId],
  );
  useSubscription(subConfig);
  const {
    threatActorIndividual: data,
    connectorsForExport,
    connectorsForImport,
  } = usePreloadedQuery<RootThreatActorIndividualQuery>(ThreatActorIndividualQuery, queryRef);
  return (
    <div>
      <TopBar me={me} />
      <>
        {data ? (
          <Switch>
            <Route
              exact
              path="/dashboard/threat_actors/threat_actors_individual/:threatActorIndividualId"
              render={() => <ThreatActorIndividual data={data} />}
            />
            <Route
              exact
              path="/dashboard/threat_actors/threat_actors_individual/:threatActorIndividualId/content"
              render={(routeProps) => (
                <React.Fragment>
                  <ContainerHeader
                    container={data}
                    PopoverComponent={<ThreatActorIndividualPopover id={data.id} />}
                    enableSuggestions={false}
                  />
                  <StixDomainObjectContent
                    {...routeProps}
                    stixDomainObject={data}
                  />
                </React.Fragment>
              )}
            />
            <Route
              exact
              path="/dashboard/threat_actors/threat_actors_individual/:threatActorIndividualId/files"
              render={(routeProps) => (
                <React.Fragment>
                  <ContainerHeader
                    container={data}
                    PopoverComponent={<ThreatActorIndividualPopover id={data.id} />}
                    enableSuggestions={false}
                  />
                  <StixCoreObjectFilesAndHistory
                    {...routeProps}
                    id={threatActorIndividualId}
                    connectorsExport={connectorsForExport}
                    connectorsImport={connectorsForImport}
                    entity={data}
                    withoutRelations={true}
                    bypassEntityId={true}
                  />
                </React.Fragment>
              )}
            />
            <Route
              exact
              path="/dashboard/threat_actors/threat_actors_individual/:threatActorIndividualId/history"
              render={(routeProps: any) => (
                <React.Fragment>
                  <ContainerHeader
                    container={data}
                    PopoverComponent={<ThreatActorIndividualPopover id={data.id} />}
                    enableSuggestions={false}
                    disableSharing={true}
                  />
                  <StixCoreObjectHistory
                    {...routeProps}
                    stixCoreObjectId={threatActorIndividualId}
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

const Root = () => {
  const { threatActorIndividualId } = useParams() as { threatActorIndividualId: string };
  const queryRef = useQueryLoading<RootThreatActorIndividualQuery>(ThreatActorIndividualQuery, {
    id: threatActorIndividualId,
  });
  return queryRef ? (
    <React.Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
      <RootThreatActorIndividualComponent queryRef={queryRef} threatActorIndividualId={threatActorIndividualId}/>
    </React.Suspense>
  ) : (
    <Loader variant={LoaderVariant.inElement} />
  );
};

export default Root;
