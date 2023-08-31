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
import CaseRfiPopover from './CaseRfiPopover';
import CaseRfi from './CaseRfi';
import { RootCaseRfiCaseQuery } from './__generated__/RootCaseRfiCaseQuery.graphql';
import { RootCaseRfiCaseSubscription } from './__generated__/RootCaseRfiCaseSubscription.graphql';
import StixCoreObjectHistory from '../../common/stix_core_objects/StixCoreObjectHistory';
import ContainerStixDomainObjects from '../../common/containers/ContainerStixDomainObjects';
import ContainerStixCyberObservables from '../../common/containers/ContainerStixCyberObservables';
import CaseRfiKnowledge from './CaseRfiKnowledge';
import { KNOWLEDGE_KNCASES_KNDELETE, KNOWLEDGE_KNUPDATE_KNDELETE } from '../../../../utils/hooks/useGranted';

const subscription = graphql`
  subscription RootCaseRfiCaseSubscription($id: ID!) {
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

const caseRfiQuery = graphql`
  query RootCaseRfiCaseQuery($id: String!) {
    caseRfi(id: $id) {
      id
      standard_id
      name
      x_opencti_graph_data
      ...CaseUtils_case
      ...CaseRfiKnowledge_case
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

const RootCaseRfiComponent = ({ queryRef, caseId }) => {
  const subConfig = useMemo<GraphQLSubscriptionConfig<RootCaseRfiCaseSubscription>>(
    () => ({
      subscription,
      variables: { id: caseId },
    }),
    [caseId],
  );
  useSubscription(subConfig);
  const {
    caseRfi: caseData,
    connectorsForExport,
    connectorsForImport,
  } = usePreloadedQuery<RootCaseRfiCaseQuery>(caseRfiQuery, queryRef);
  return (
    <div>
      {caseData ? (
        <Switch>
          <Route
            exact
            path="/dashboard/cases/rfis/:caseId"
            render={() => <CaseRfi data={caseData} />}
          />
          <Route
            exact
            path="/dashboard/cases/rfis/:caseId/entities"
            render={(routeProps) => (
              <React.Fragment>
                <ContainerHeader
                  container={caseData}
                  PopoverComponent={<CaseRfiPopover id={caseData.id} />}
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
            path="/dashboard/cases/rfis/:caseId/observables"
            render={(routeProps) => (
              <React.Fragment>
                <ContainerHeader
                  container={caseData}
                  PopoverComponent={<CaseRfiPopover id={caseData.id} />}
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
            path="/dashboard/cases/rfis/:caseId/knowledge"
            render={() => (
              <Redirect
                to={`/dashboard/cases/rfis/${caseId}/knowledge/graph`}
              />
            )}
          />
          <Route
            exact
            path="/dashboard/cases/rfis/:caseId/content"
            render={(routeProps) => (
              <React.Fragment>
                <ContainerHeader
                  container={caseData}
                  PopoverComponent={<CaseRfiPopover id={caseData.id} />}
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
            path="/dashboard/cases/rfis/:caseId/knowledge/:mode"
            render={(routeProps) => (
              <CaseRfiKnowledge {...routeProps} caseData={caseData} />
            )}
          />
          <Route
            exact
            path="/dashboard/cases/rfis/:caseId/files"
            render={(routeProps) => (
              <React.Fragment>
                <ContainerHeader
                  container={caseData}
                  PopoverComponent={<CaseRfiPopover id={caseData.id} />}
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
            path="/dashboard/cases/rfis/:caseId/history"
            render={(routeProps: any) => (
              <React.Fragment>
                <ContainerHeader
                  container={caseData}
                  PopoverComponent={<CaseRfiPopover id={caseData.id} />}
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
  const queryRef = useQueryLoading<RootCaseRfiCaseQuery>(caseRfiQuery, {
    id: caseId,
  });
  return (
    <>
      {queryRef && (
        <React.Suspense fallback={<Loader variant={LoaderVariant.container} />}>
          <RootCaseRfiComponent queryRef={queryRef} caseId={caseId} />
        </React.Suspense>
      )}
    </>
  );
};

export default Root;
