/* eslint-disable @typescript-eslint/no-explicit-any */
// TODO Remove this when V6
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-nocheck
import React, { useMemo } from 'react';
import { Route, Redirect, Switch, useParams } from 'react-router-dom';
import { graphql, usePreloadedQuery, useSubscription } from 'react-relay';
import { GraphQLSubscriptionConfig } from 'relay-runtime';
import TopBar from '../../nav/TopBar';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import useAuth from '../../../../utils/hooks/useAuth';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import Case from './Case';
import { RootCasesSubscription } from './__generated__/RootCasesSubscription.graphql';
import { RootCaseQuery } from './__generated__/RootCaseQuery.graphql';
import ContainerHeader from '../../common/containers/ContainerHeader';
import FileManager from '../../common/files/FileManager';
import CasePopover from './CasePopover';
import StixCoreObjectHistory from '../../common/stix_core_objects/StixCoreObjectHistory';

const subscription = graphql`
  subscription RootCasesSubscription($id: ID!) {
    stixDomainObject(id: $id) {
      ... on Case {
        ...Case_case
      }
      ...FileImportViewer_entity
      ...FileExportViewer_entity
      ...FileExternalReferencesViewer_entity
      ...WorkbenchFileViewer_entity
    }
  }
`;

const caseQuery = graphql`
  query RootCaseQuery($id: String!) {
    case(id: $id) {
      id
      name
      ...Case_case
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

const RootCaseComponent = ({ queryRef }) => {
  const { me } = useAuth();
  const { caseId } = useParams() as { caseId: string };

  const subConfig = useMemo<GraphQLSubscriptionConfig<RootCasesSubscription>>(() => ({
    subscription,
    variables: { id: caseId },
  }), [caseId]);
  useSubscription(subConfig);

  const { case: caseData, connectorsForExport, connectorsForImport } = usePreloadedQuery<RootCaseQuery>(caseQuery, queryRef);

  return (
    <div>
      <TopBar me={me} />
      <>
        {caseData ? (
          <Switch>
            <Route
              exact
              path="/dashboard/settings/managements/feedback/:caseId"
              render={() => (<Case data={caseData} />)}
            />
            <Route
              exact
              path="/dashboard/settings/managements/feedback/:caseId/knowledge"
              render={() => (
                <Redirect
                  to={`/dashboard/settings/managements/feedback/${caseId}/knowledge/overview`}
                />
              )}
            />
            <Route
              exact
              path="/dashboard/settings/managements/feedback/:caseId/files"
              render={(routeProps: any) => (
                <React.Fragment>
                  <ContainerHeader
                    container={caseData}
                    PopoverComponent={<CasePopover id={caseData.id} />}
                    enableSuggestions={false}
                    disableSharing={true}
                  />
                  <FileManager
                    {...routeProps}
                    id={caseId}
                    connectorsExport={connectorsForExport}
                    connectorsImport={connectorsForImport}
                    entity={caseData}
                  />
                </React.Fragment>
              )}
            />
            <Route
              exact
              path="/dashboard/settings/managements/feedback/:caseId/history"
              render={(routeProps: any) => (
                <React.Fragment>
                  <ContainerHeader
                    container={caseData}
                    PopoverComponent={<CasePopover id={caseData.id} />}
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
        ) : <ErrorNotFound />}
      </>
    </div>
  );
};

const RootCase = () => {
  const { caseId } = useParams() as { caseId: string };

  const queryRef = useQueryLoading<RootCaseQuery>(caseQuery, { id: caseId });
  return queryRef ? (
    <React.Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
      <RootCaseComponent queryRef={queryRef} />
    </React.Suspense>
  ) : <Loader variant={LoaderVariant.inElement} />;
};

export default RootCase;
