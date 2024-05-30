/* eslint-disable @typescript-eslint/no-explicit-any */
// TODO Remove this when V6
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-nocheck
import Box from '@mui/material/Box';
import React, { useMemo } from 'react';
import { Link, Route, Routes, useLocation, useParams } from 'react-router-dom';
import { graphql, usePreloadedQuery, useSubscription } from 'react-relay';
import { GraphQLSubscriptionConfig } from 'relay-runtime';
import Tabs from '@mui/material/Tabs';
import Tab from '@mui/material/Tab';
import StixCoreRelationship from '@components/common/stix_core_relationships/StixCoreRelationship';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import { RootFeedbackSubscription } from './__generated__/RootFeedbackSubscription.graphql';
import { RootFeedbackQuery } from './__generated__/RootFeedbackQuery.graphql';
import ContainerHeader from '../../common/containers/ContainerHeader';
import FileManager from '../../common/files/FileManager';
import FeedbackPopover from './FeedbackPopover';
import StixCoreObjectHistory from '../../common/stix_core_objects/StixCoreObjectHistory';
import StixCoreObjectContent from '../../common/stix_core_objects/StixCoreObjectContent';
import Feedback from './Feedback';
import { useFormatter } from '../../../../components/i18n';
import Breadcrumbs from '../../../../components/Breadcrumbs';

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
      entity_type
      currentUserAccessRight
      authorized_members {
        id
        name
        entity_type
        access_right
      }
      creators {
        id
        name
        entity_type
      }
      x_opencti_graph_data
      ...Feedback_case
      ...FileImportViewer_entity
      ...FileExportViewer_entity
      ...FileExternalReferencesViewer_entity
      ...WorkbenchFileViewer_entity
      ...StixCoreObjectContent_stixCoreObject
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
  const { t_i18n } = useFormatter();
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
          <Breadcrumbs variant="object" elements={[
            { label: t_i18n('Cases') },
            { label: t_i18n('Feedbacks'), link: '/dashboard/cases/feedbacks' },
            { label: feedbackData.name, current: true },
          ]}
          />
          <ContainerHeader
            container={feedbackData}
            PopoverComponent={<FeedbackPopover id={feedbackData.id} />}
            enableSuggestions={false}
            disableSharing
            enableQuickSubscription
            enableManageAuthorizedMembers={canManage}
            authorizedMembersMutation={feedbackAuthorizedMembersMutation}
            redirectToContent={true}
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
                label={t_i18n('Overview')}
              />
              <Tab
                component={Link}
                to={`/dashboard/cases/feedbacks/${feedbackData.id}/content`}
                value={`/dashboard/cases/feedbacks/${feedbackData.id}/content`}
                label={t_i18n('Content')}
              />
              <Tab
                component={Link}
                to={`/dashboard/cases/feedbacks/${feedbackData.id}/files`}
                value={`/dashboard/cases/feedbacks/${feedbackData.id}/files`}
                label={t_i18n('Data')}
              />
              <Tab
                component={Link}
                to={`/dashboard/cases/feedbacks/${feedbackData.id}/history`}
                value={`/dashboard/cases/feedbacks/${feedbackData.id}/history`}
                label={t_i18n('History')}
              />
            </Tabs>
          </Box>
          <Routes>
            <Route
              path="/"
              element={
                <Feedback
                  data={feedbackData}
                />}
            />
            <Route
              path="/content"
              element={
                <StixCoreObjectContent
                  stixCoreObject={feedbackData}
                />
              }
            />
            <Route
              path="/files"
              element={
                <FileManager
                  id={caseId}
                  connectorsExport={connectorsForExport}
                  connectorsImport={connectorsForImport}
                  entity={feedbackData}
                />
              }
            />
            <Route
              path="/history"
              element={
                <StixCoreObjectHistory
                  stixCoreObjectId={caseId}
                />
              }
            />
            <Route
              path="/knowledge/relations/:relationId"
              element={
                <StixCoreRelationship
                  entityId={feedbackData.id}
                />
              }
            />
          </Routes>
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
