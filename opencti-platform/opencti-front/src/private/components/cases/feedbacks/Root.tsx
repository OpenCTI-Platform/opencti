/* eslint-disable @typescript-eslint/no-explicit-any */
// TODO Remove this when V6
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-nocheck
import Box from '@mui/material/Box';
import React, { useMemo } from 'react';
import { Link, Route, Switch, useParams } from 'react-router-dom';
import { graphql, usePreloadedQuery, useSubscription } from 'react-relay';
import { GraphQLSubscriptionConfig } from 'relay-runtime';
import Tabs from '@mui/material/Tabs';
import Tab from '@mui/material/Tab';
import { useLocation } from 'react-router-dom-v5-compat';
import ErrorNotFound from '../../../../components/ErrorNotFound';
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
import { useFormatter } from '../../../../components/i18n';
import { authorizedMembersToOptions } from '../../../../utils/authorizedMembers';

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
      currentUserAccessRight
      authorized_members {
        id
        name
        entity_type
        access_right
      }
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

// Mutation to edit authorized members of a feedback
const feedbackAuthorizedMembersMutation = graphql`
  mutation RootFeedbackAuthorizedMembersMutation(
    $id: ID!
    $input: [MemberAccessInput!]
  ) {
    feedbackEditAuthorizedMembers(id: $id, input: $input) {
      authorized_members {
        id
        name
        entity_type
        access_right
      }
    }
  }
`;

const RootFeedbackComponent = ({ queryRef, caseId }) => {
  const subConfig = useMemo<
  GraphQLSubscriptionConfig<RootFeedbackSubscription>
  >(
    () => ({
      subscription,
      variables: { id: caseId },
    }),
    [caseId],
  );
  const location = useLocation();
  const { t } = useFormatter();
  useSubscription(subConfig);
  const {
    feedback: feedbackData,
    connectorsForExport,
    connectorsForImport,
  } = usePreloadedQuery<RootFeedbackQuery>(feedbackQuery, queryRef);
  let paddingRight = 0;
  if (feedbackData) {
    if (
      location.pathname.includes(
        `/dashboard/cases/feedbacks/${feedbackData.id}/content`,
      )
    ) {
      paddingRight = 350;
    }
  }

  const canManage = feedbackData?.currentUserAccessRight === 'admin';

  return (
    <>
      {feedbackData ? (
        <div style={{ paddingRight }}>
          <ContainerHeader
            container={feedbackData}
            PopoverComponent={<FeedbackPopover id={feedbackData.id} />}
            enableSuggestions={false}
            disableSharing
            enableQuickSubscription
            enableManageAuthorizedMembers={canManage}
            authorizedMembersMutation={feedbackAuthorizedMembersMutation}
            authorizedMembers={authorizedMembersToOptions(feedbackData.authorized_members)}
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
                  `/dashboard/cases/feedbacks/${feedbackData.id}/knowledge`,
                )
                  ? `/dashboard/cases/feedbacks/${feedbackData.id}/knowledge`
                  : location.pathname
              }
            >
              <Tab
                component={Link}
                to={`/dashboard/cases/feedbacks/${feedbackData.id}`}
                value={`/dashboard/cases/feedbacks/${feedbackData.id}`}
                label={t('Overview')}
              />
              <Tab
                component={Link}
                to={`/dashboard/cases/feedbacks/${feedbackData.id}/content`}
                value={`/dashboard/cases/feedbacks/${feedbackData.id}/content`}
                label={t('Content')}
              />
              <Tab
                component={Link}
                to={`/dashboard/cases/feedbacks/${feedbackData.id}/files`}
                value={`/dashboard/cases/feedbacks/${feedbackData.id}/files`}
                label={t('Data')}
              />
              <Tab
                component={Link}
                to={`/dashboard/cases/feedbacks/${feedbackData.id}/history`}
                value={`/dashboard/cases/feedbacks/${feedbackData.id}/history`}
                label={t('History')}
              />
            </Tabs>
          </Box>
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
                <StixDomainObjectContent
                  {...routeProps}
                  stixDomainObject={feedbackData}
                />
              )}
            />
            <Route
              exact
              path="/dashboard/cases/feedbacks/:caseId/files"
              render={(routeProps) => (
                <FileManager
                  {...routeProps}
                  id={caseId}
                  connectorsExport={connectorsForExport}
                  connectorsImport={connectorsForImport}
                  entity={feedbackData}
                />
              )}
            />
            <Route
              exact
              path="/dashboard/cases/feedbacks/:caseId/history"
              render={(routeProps) => (
                <StixCoreObjectHistory
                  {...routeProps}
                  stixCoreObjectId={caseId}
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

const Root = () => {
  const { caseId } = useParams();
  const queryRef = useQueryLoading<RootFeedbackQuery>(feedbackQuery, {
    id: caseId,
  });
  return (
    <>
      {queryRef && (
        <React.Suspense fallback={<Loader variant={LoaderVariant.container} />}>
          <RootFeedbackComponent queryRef={queryRef} caseId={caseId} />
        </React.Suspense>
      )}
    </>
  );
};

export default Root;
