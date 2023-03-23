/* eslint-disable @typescript-eslint/no-explicit-any */
// TODO Remove this when V6
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-nocheck
import React, { useMemo } from 'react';
import { Redirect, Route, Switch, useParams } from 'react-router-dom';
import { graphql, usePreloadedQuery, useSubscription } from 'react-relay';
import { GraphQLSubscriptionConfig } from 'relay-runtime';
import TopBar from '../../nav/TopBar';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import useAuth from '../../../../utils/hooks/useAuth';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import CaseIncident from './CaseIncident';
import { RootIncidentSubscription } from './__generated__/RootIncidentSubscription.graphql';
import { RootIncidentQuery } from './__generated__/RootIncidentQuery.graphql';
import ContainerHeader from '../../common/containers/ContainerHeader';
import CaseIncidentPopover from './CaseIncidentPopover';
import StixDomainObjectContent from '../../common/stix_domain_objects/StixDomainObjectContent';
import ContainerStixDomainObjects from '../../common/containers/ContainerStixDomainObjects';
import ContainerStixCyberObservables from '../../common/containers/ContainerStixCyberObservables';
import StixCoreObjectFilesAndHistory from '../../common/stix_core_objects/StixCoreObjectFilesAndHistory';
import IncidentKnowledge from './IncidentKnowledge';
import { RootIncidentCaseQuery } from './__generated__/RootIncidentCaseQuery.graphql';

const subscription = graphql`
  subscription RootIncidentCaseSubscription($id: ID!) {
    stixDomainObject(id: $id) {
      ... on CaseIncident {
        ...CaseIncident_case
      }
      ...FileImportViewer_entity
      ...FileExportViewer_entity
      ...FileExternalReferencesViewer_entity
      ...WorkbenchFileViewer_entity
    }
  }
`;

const caseIncidentQuery = graphql`
  query RootIncidentCaseQuery($id: String!) {
    caseIncident(id: $id) {
      id
      name
      ...CaseIncident_case
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

const RootCaseIncidentComponent = ({ queryRef, caseId }) => {
  const { me } = useAuth();
  const subConfig = useMemo<
  GraphQLSubscriptionConfig<RootIncidentSubscription>
  >(
    () => ({
      subscription,
      variables: { id: caseId },
    }),
    [caseId],
  );
  useSubscription(subConfig);
  const {
    caseIncident: caseData,
    connectorsForExport,
    connectorsForImport,
  } = usePreloadedQuery<RootIncidentCaseQuery>(caseIncidentQuery, queryRef);
  return (
    <div>
      <TopBar me={me} />
      <>
        {caseData ? (
          <Switch>
            <Route
              exact
              path="/dashboard/cases/incidents/:caseId"
              render={() => <CaseIncident data={caseData} />}
            />
            <Route
              exact
              path="/dashboard/cases/incidents/:caseId/entities"
              render={(routeProps) => (
                <React.Fragment>
                  <ContainerHeader
                    container={caseData}
                    PopoverComponent={<CaseIncidentPopover id={caseData.id} />}
                    enableSuggestions={false}
                  />
                  <ContainerStixDomainObjects
                    {...routeProps}
                    container={caseData}
                  />
                </React.Fragment>
              )}
            />
            <Route
              exact
              path="/dashboard/cases/incidents/:caseId/observables"
              render={(routeProps) => (
                <React.Fragment>
                  <ContainerHeader
                    container={caseData}
                    PopoverComponent={<CaseIncidentPopover id={caseData.id} />}
                    enableSuggestions={false}
                  />
                  <ContainerStixCyberObservables
                    {...routeProps}
                    container={caseData}
                  />
                </React.Fragment>
              )}
            />
            <Route
              exact
              path="/dashboard/cases/incidents/:caseId/knowledge"
              render={() => (
                <Redirect
                  to={`/dashboard/cases/incidents/${caseId}/knowledge/graph`}
                />
              )}
            />
            <Route
              exact
              path="/dashboard/cases/incidents/:caseId/content"
              render={(routeProps) => (
                <React.Fragment>
                  <ContainerHeader
                    container={caseData}
                    PopoverComponent={<CaseIncidentPopover id={caseData.id} />}
                    enableSuggestions={false}
                  />
                  <StixDomainObjectContent
                    {...routeProps}
                    stixDomainObject={caseData}
                  />
                </React.Fragment>
              )}
            />
            <Route
              exact
              path="/dashboard/cases/incidents/:caseId/knowledge/:mode"
              render={(routeProps) => (
                <IncidentKnowledge {...routeProps} caseData={caseData} />
              )}
            />
            <Route
              exact
              path="/dashboard/cases/incidents/:caseId/files"
              render={(routeProps) => (
                <React.Fragment>
                  <ContainerHeader
                    container={caseData}
                    PopoverComponent={<CaseIncidentPopover id={caseData.id} />}
                    enableSuggestions={false}
                  />
                  <StixCoreObjectFilesAndHistory
                    {...routeProps}
                    id={caseId}
                    connectorsExport={connectorsForExport}
                    connectorsImport={connectorsForImport}
                    entity={caseData}
                    withoutRelations={true}
                    bypassEntityId={true}
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
  const { caseId } = useParams() as { caseId: string };
  const queryRef = useQueryLoading<RootIncidentQuery>(caseIncidentQuery, {
    id: caseId,
  });
  return queryRef ? (
    <React.Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
      <RootCaseIncidentComponent queryRef={queryRef} caseId={caseId}/>
    </React.Suspense>
  ) : (
    <Loader variant={LoaderVariant.inElement} />
  );
};

export default Root;
