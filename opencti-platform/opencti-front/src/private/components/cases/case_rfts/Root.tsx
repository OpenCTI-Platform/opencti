/* eslint-disable @typescript-eslint/no-explicit-any */
// TODO Remove this when V6
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-nocheck
import React, { useMemo } from 'react';
import { Redirect, Route, Switch, useParams } from 'react-router-dom';
import { graphql, usePreloadedQuery, useSubscription } from 'react-relay';
import { GraphQLSubscriptionConfig } from 'relay-runtime';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import ContainerHeader from '../../common/containers/ContainerHeader';
import StixDomainObjectContent from '../../common/stix_domain_objects/StixDomainObjectContent';
import StixCoreObjectFilesAndHistory from '../../common/stix_core_objects/StixCoreObjectFilesAndHistory';
import StixCoreObjectHistory from '../../common/stix_core_objects/StixCoreObjectHistory';
import CaseRft from './CaseRft';
import CaseRftPopover from './CaseRftPopover';
import CaseRftKnowledge from './CaseRftKnowledge';
import ContainerStixCyberObservables from '../../common/containers/ContainerStixCyberObservables';
import ContainerStixDomainObjects from '../../common/containers/ContainerStixDomainObjects';
import { RootCaseRftCaseQuery } from './__generated__/RootCaseRftCaseQuery.graphql';
import { KNOWLEDGE_KNCASES_KNDELETE, KNOWLEDGE_KNUPDATE_KNDELETE } from '../../../../utils/hooks/useGranted';

const subscription = graphql`
  subscription RootCaseRftCaseSubscription($id: ID!) {
    stixDomainObject(id: $id) {
      ... on Case {
        ...CaseUtils_case
      }
      ...FileImportViewer_entity
      ...FileExportViewer_entity
      ...FileExternalReferencesViewer_entity
      ...WorkbenchFileViewer_entity
    }
  }
`;

const caseRftQuery = graphql`
  query RootCaseRftCaseQuery($id: String!) {
    caseRft(id: $id) {
      id
      standard_id
      name
      x_opencti_graph_data
      ...CaseUtils_case
      ...CaseRftKnowledge_case
      ...FileImportViewer_entity
      ...FileExportViewer_entity
      ...FileExternalReferencesViewer_entity
      ...WorkbenchFileViewer_entity
      ...StixDomainObjectContent_stixDomainObject
      ...ContainerHeader_container
      ...ContainerStixDomainObjects_container
      ...ContainerStixCyberObservables_container
    }
    connectorsForExport {
      ...StixCoreObjectFilesAndHistory_connectorsExport
    }
    connectorsForImport {
      ...StixCoreObjectFilesAndHistory_connectorsImport
    }
  }
`;

const RootCaseRftComponent = ({ queryRef, caseId }) => {
  const subConfig = useMemo<GraphQLSubscriptionConfig<RootCaseRftCaseSubscription>>(
    () => ({
      subscription,
      variables: { id: caseId },
    }),
    [caseId],
  );
  useSubscription(subConfig);
  const {
    caseRft: caseData,
    connectorsForExport,
    connectorsForImport,
  } = usePreloadedQuery<RootCaseRftCaseQuery>(caseRftQuery, queryRef);
  return (
    <div>
      {caseData ? (
        <Switch>
          <Route
            exact
            path="/dashboard/cases/rfts/:caseId"
            render={() => <CaseRft data={caseData} />}
          />
          <Route
            exact
            path="/dashboard/cases/rfts/:caseId/entities"
            render={(routeProps) => (
              <React.Fragment>
                <ContainerHeader
                  container={caseData}
                  PopoverComponent={<CaseRftPopover id={caseData.id} />}
                  popoverSecurity={[KNOWLEDGE_KNCASES_KNDELETE, KNOWLEDGE_KNUPDATE_KNDELETE]}
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
            path="/dashboard/cases/rfts/:caseId/observables"
            render={(routeProps) => (
              <React.Fragment>
                <ContainerHeader
                  container={caseData}
                  PopoverComponent={<CaseRftPopover id={caseData.id} />}
                  popoverSecurity={[KNOWLEDGE_KNCASES_KNDELETE, KNOWLEDGE_KNUPDATE_KNDELETE]}
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
            path="/dashboard/cases/rfts/:caseId/knowledge"
            render={() => (
              <Redirect
                to={`/dashboard/cases/rfts/${caseId}/knowledge/graph`}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/cases/rfts/:caseId/content"
            render={(routeProps) => (
              <React.Fragment>
                <ContainerHeader
                  container={caseData}
                  PopoverComponent={<CaseRftPopover id={caseData.id} />}
                  popoverSecurity={[KNOWLEDGE_KNCASES_KNDELETE, KNOWLEDGE_KNUPDATE_KNDELETE]}
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
            path="/dashboard/cases/rfts/:caseId/knowledge/:mode"
            render={(routeProps) => (
              <CaseRftKnowledge {...routeProps} caseData={caseData} />
            )}
          />
          <Route
            exact
            path="/dashboard/cases/rfts/:caseId/files"
            render={(routeProps) => (
              <React.Fragment>
                <ContainerHeader
                  container={caseData}
                  PopoverComponent={<CaseRftPopover id={caseData.id} />}
                  popoverSecurity={[KNOWLEDGE_KNCASES_KNDELETE, KNOWLEDGE_KNUPDATE_KNDELETE]}
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
          <Route
            exact
            path="/dashboard/cases/rfts/:caseId/history"
            render={(routeProps: any) => (
              <React.Fragment>
                <ContainerHeader
                  container={caseData}
                  PopoverComponent={<CaseRftPopover id={caseData.id} />}
                  popoverSecurity={[KNOWLEDGE_KNCASES_KNDELETE, KNOWLEDGE_KNUPDATE_KNDELETE]}
                  enableSuggestions={false}
                  disableSharing={true}
                />
                <StixCoreObjectHistory
                  {...routeProps}
                  stixCoreObjectId={caseId}
                />
              </React.Fragment>
            )}
          />
        </Switch>
      ) : (
        <ErrorNotFound />
      )}
    </div>
  );
};

const Root = () => {
  const { caseId } = useParams() as { caseId: string };
  const queryRef = useQueryLoading<RootCaseRftCaseQuery>(caseRftQuery, {
    id: caseId,
  });
  return (
    <>
      {queryRef && (
        <React.Suspense fallback={<Loader variant={LoaderVariant.container} />}>
          <RootCaseRftComponent queryRef={queryRef} caseId={caseId} />
        </React.Suspense>
      )}
    </>
  );
};

export default Root;
