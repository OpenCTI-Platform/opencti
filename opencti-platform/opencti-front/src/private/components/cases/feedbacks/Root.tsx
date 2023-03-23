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
import { RootFeedbackSubscription } from './__generated__/RootFeedbackSubscription.graphql';
import { RootFeedbackQuery } from './__generated__/RootFeedbackQuery.graphql';
import ContainerHeader from '../../common/containers/ContainerHeader';
import FileManager from '../../common/files/FileManager';
import FeedbackPopover from './FeedbackPopover';
import StixCoreObjectHistory from '../../common/stix_core_objects/StixCoreObjectHistory';
import StixDomainObjectContent from '../../common/stix_domain_objects/StixDomainObjectContent';
import Feedback from './Feedback';

const subscription = graphql`
  subscription RootFeedbackSubscription($id: ID!) {
    stixDomainObject(id: $id) {
      ... on Feedback {
        ...Feedback_case
      }
      ...FileImportViewer_entity
      ...FileExportViewer_entity
      ...FileExternalReferencesViewer_entity
      ...WorkbenchFileViewer_entity
    }
  }
`;

const feedbackQuery = graphql`
  query RootFeedbackQuery($id: String!) {
    feedback(id: $id) {
      id
      name
      x_opencti_graph_data
      ...Feedback_case
      ...FileImportViewer_entity
      ...FileExportViewer_entity
      ...FileExternalReferencesViewer_entity
      ...WorkbenchFileViewer_entity
      ...StixDomainObjectContent_stixDomainObject
    }
    connectorsForExport {
      ...FileManager_connectorsExport
    }
    connectorsForImport {
      ...FileManager_connectorsImport
    }
  }
`;

const RootFeedbackComponent = ({ queryRef, caseId }) => {
  const { me } = useAuth();
  const subConfig = useMemo<GraphQLSubscriptionConfig<RootFeedbackSubscription>>(
    () => ({
      subscription,
      variables: { id: caseId },
    }),
    [caseId],
  );
  useSubscription(subConfig);
  const {
    feedback: feedbackData,
    connectorsForExport,
    connectorsForImport,
  } = usePreloadedQuery<RootFeedbackQuery>(feedbackQuery, queryRef);
  return (
    <div>
      <TopBar me={me} />
      <>
        {feedbackData ? (
          <Switch>
            <Route
              exact
              path="/dashboard/cases/feedbacks/:caseId"
              render={() => <Feedback data={feedbackData} />}
            />
            <Route
              exact
              path="/dashboard/cases/feedbacks/:caseId/content"
              render={(routeProps) => (
                <React.Fragment>
                  <ContainerHeader
                    container={feedbackData}
                    PopoverComponent={<FeedbackPopover id={feedbackData.id} />}
                    disableSharing={true}
                  />
                  <StixDomainObjectContent
                    {...routeProps}
                    stixDomainObject={feedbackData}
                  />
                </React.Fragment>
              )}
            />
            <Route
              exact
              path="/dashboard/cases/feedbacks/:caseId/files"
              render={(routeProps: any) => (
                <React.Fragment>
                  <ContainerHeader
                    container={feedbackData}
                    PopoverComponent={<FeedbackPopover id={feedbackData.id} />}
                    enableSuggestions={false}
                    disableSharing={true}
                  />
                  <FileManager
                    {...routeProps}
                    id={caseId}
                    connectorsExport={connectorsForExport}
                    connectorsImport={connectorsForImport}
                    entity={feedbackData}
                  />
                </React.Fragment>
              )}
            />
            <Route
              exact
              path="/dashboard/cases/feedbacks/:caseId/history"
              render={(routeProps: any) => (
                <React.Fragment>
                  <ContainerHeader
                    container={feedbackData}
                    PopoverComponent={<FeedbackPopover id={feedbackData.id} />}
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
      </>
    </div>
  );
};

const Root = () => {
  const { caseId } = useParams() as { caseId: string };
  const queryRef = useQueryLoading<RootFeedbackQuery>(feedbackQuery, { id: caseId });
  return queryRef ? (
    <React.Suspense fallback={<Loader variant={LoaderVariant.inElement} />}>
      <RootFeedbackComponent queryRef={queryRef} caseId={caseId}/>
    </React.Suspense>
  ) : (
    <Loader variant={LoaderVariant.inElement} />
  );
};

export default Root;
