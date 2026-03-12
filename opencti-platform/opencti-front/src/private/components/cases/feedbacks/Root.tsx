// TODO Remove this when V6
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-nocheck
import React, { useMemo } from 'react';
import { Route, Routes, useLocation, useParams } from 'react-router-dom';
import { graphql, usePreloadedQuery, useSubscription } from 'react-relay';
import { GraphQLSubscriptionConfig } from 'relay-runtime';
import StixCoreRelationship from '@components/common/stix_core_relationships/StixCoreRelationship';
import StixCoreObjectContentRoot from '@components/common/stix_core_objects/StixCoreObjectContentRoot';
import StixDomainObjectTabsBox from '@components/common/stix_domain_objects/StixDomainObjectTabsBox';
import Security from 'src/utils/Security';
import useGranted, { KNOWLEDGE_KNUPDATE, KNOWLEDGE_KNUPDATE_KNDELETE, KNOWLEDGE_KNUPDATE_KNBYPASSREFERENCE } from 'src/utils/hooks/useGranted';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import { RootFeedbackSubscription } from './__generated__/RootFeedbackSubscription.graphql';
import { RootFeedbackQuery } from './__generated__/RootFeedbackQuery.graphql';
import ContainerHeader from '../../common/containers/ContainerHeader';
import FileManager from '../../common/files/FileManager';
import StixCoreObjectHistory from '../../common/stix_core_objects/StixCoreObjectHistory';
import Feedback from './Feedback';
import { useFormatter } from '../../../../components/i18n';
import Breadcrumbs from '../../../../components/Breadcrumbs';
import { useIsEnforceReference } from '../../../../utils/hooks/useEntitySettings';
import { getPaddingRight } from '../../../../utils/utils';
import FeedbackEdition from './FeedbackEdition';
import { useGetCurrentUserAccessRight } from '../../../../utils/authorizedMembers';
import FeedbackDeletion from './FeedbackDeletion';

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
        member_id
        name
        entity_type
        access_right
        groups_restriction {
          id
          name
        }
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
      ...ContainerHeader_container
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
  const enableReferences = useIsEnforceReference('Feedback') && !useGranted([KNOWLEDGE_KNUPDATE_KNBYPASSREFERENCE]);
  const { t_i18n } = useFormatter();
  useSubscription(subConfig);

  const {
    feedback: feedbackData,
    connectorsForExport,
    connectorsForImport,
  } = usePreloadedQuery<RootFeedbackQuery>(feedbackQuery, queryRef);
  if (!feedbackData) {
    return <ErrorNotFound />;
  }
  const paddingRight = getPaddingRight(location.pathname, feedbackData.id, '/dashboard/cases/feedbacks');
  const { canEdit } = useGetCurrentUserAccessRight(feedbackData.currentUserAccessRight);
  return (
    <div style={{ paddingRight }}>
      <Breadcrumbs elements={[
        { label: t_i18n('Cases') },
        { label: t_i18n('Feedbacks'), link: '/dashboard/cases/feedbacks' },
        { label: feedbackData.name, current: true },
      ]}
      />
      <ContainerHeader
        container={feedbackData}
        EditComponent={(
          <Security needs={[KNOWLEDGE_KNUPDATE]} hasAccess={canEdit}>
            <FeedbackEdition feedbackId={feedbackData.id} />
          </Security>
        )}
        DeleteComponent={({ isOpen, onClose }: { isOpen: boolean; onClose: () => void }) => (
          <Security needs={[KNOWLEDGE_KNUPDATE_KNDELETE]}>
            <FeedbackDeletion id={feedbackData.id} isOpen={isOpen} handleClose={onClose} />
          </Security>
        )}
        enableSuggestions={false}
        disableSharing={true}
        enableQuickSubscription
        redirectToContent={true}
      />
      <StixDomainObjectTabsBox
        basePath="/dashboard/cases/feedbacks"
        entity={feedbackData}
        tabs={[
          'overview',
          'content',
          'files',
          'history',
        ]}
      />
      <Routes>
        <Route
          path="/"
          element={(
            <Feedback
              feedbackData={feedbackData}
              enableReferences={enableReferences}
            />
          )}
        />
        <Route
          path="/content/*"
          element={(
            <StixCoreObjectContentRoot
              stixCoreObject={feedbackData}
            />
          )}
        />
        <Route
          path="/files"
          element={(
            <FileManager
              id={caseId}
              connectorsExport={connectorsForExport}
              connectorsImport={connectorsForImport}
              entity={feedbackData}
            />
          )}
        />
        <Route
          path="/history"
          element={(
            <StixCoreObjectHistory
              stixCoreObjectId={caseId}
            />
          )}
        />
        <Route
          path="/knowledge/relations/:relationId"
          element={(
            <StixCoreRelationship
              entityId={feedbackData.id}
            />
          )}
        />
      </Routes>
    </div>
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
