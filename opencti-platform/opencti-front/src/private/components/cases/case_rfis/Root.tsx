// TODO Remove this when V6
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-nocheck
import React, { useMemo } from 'react';
import { Link, Navigate, Route, Routes, useLocation, useParams } from 'react-router-dom';
import { graphql, usePreloadedQuery, useSubscription } from 'react-relay';
import { GraphQLSubscriptionConfig } from 'relay-runtime';
import Box from '@mui/material/Box';
import Tabs from '@mui/material/Tabs';
import Tab from '@mui/material/Tab';
import StixCoreObjectContentRoot from '@components/common/stix_core_objects/StixCoreObjectContentRoot';
import Security from 'src/utils/Security';
import AIInsights from '@components/common/ai/AIInsights';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import ContainerHeader from '../../common/containers/ContainerHeader';
import StixCoreObjectFilesAndHistory from '../../common/stix_core_objects/StixCoreObjectFilesAndHistory';
import CaseRfi from './CaseRfi';
import { RootCaseRfiCaseQuery } from './__generated__/RootCaseRfiCaseQuery.graphql';
import { RootCaseRfiCaseSubscription } from './__generated__/RootCaseRfiCaseSubscription.graphql';
import StixCoreObjectHistory from '../../common/stix_core_objects/StixCoreObjectHistory';
import ContainerStixDomainObjects from '../../common/containers/ContainerStixDomainObjects';
import ContainerStixCyberObservables from '../../common/containers/ContainerStixCyberObservables';
import CaseRfiKnowledge from './CaseRfiKnowledge';
import { useFormatter } from '../../../../components/i18n';
import Breadcrumbs from '../../../../components/Breadcrumbs';
import { useIsEnforceReference } from '../../../../utils/hooks/useEntitySettings';
import useGranted, { KNOWLEDGE_KNUPDATE, KNOWLEDGE_KNUPDATE_KNBYPASSREFERENCE, KNOWLEDGE_KNUPDATE_KNDELETE } from '../../../../utils/hooks/useGranted';
import { getCurrentTab, getPaddingRight } from '../../../../utils/utils';
import CaseRfiEdition from './CaseRfiEdition';
import { useGetCurrentUserAccessRight } from '../../../../utils/authorizedMembers';
import CaseRfiDeletion from './CaseRfiDeletion';

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
      entity_type
      currentUserAccessRight
      name
      x_opencti_graph_data
      ...CaseUtils_case
      ...CaseRfi_caseRfi
      ...CaseRfiKnowledge_case
      ...FileImportViewer_entity
      ...FileExportViewer_entity
      ...FileExternalReferencesViewer_entity
      ...WorkbenchFileViewer_entity
      ...StixCoreObjectContent_stixCoreObject
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
  const subConfig = useMemo<
    GraphQLSubscriptionConfig<RootCaseRfiCaseSubscription>
  >(
    () => ({
      subscription,
      variables: { id: caseId },
    }),
    [caseId],
  );
  const location = useLocation();
  const enableReferences = useIsEnforceReference('Case-Rfi') && !useGranted([KNOWLEDGE_KNUPDATE_KNBYPASSREFERENCE]);
  const { t_i18n } = useFormatter();
  useSubscription(subConfig);

  const {
    caseRfi: caseData,
    connectorsForExport,
    connectorsForImport,
  } = usePreloadedQuery<RootCaseRfiCaseQuery>(caseRfiQuery, queryRef);
  if (!caseData) {
    return <ErrorNotFound />;
  }
  const paddingRight = getPaddingRight(location.pathname, caseData.id, '/dashboard/cases/rfis', false);
  const isKnowledgeOrContent = location.pathname.includes('knowledge') || location.pathname.includes('content');
  const currentAccessRight = useGetCurrentUserAccessRight(caseData.currentUserAccessRight);
  return (
    <div style={{ paddingRight }}>
      <Breadcrumbs elements={[
        { label: t_i18n('Cases') },
        { label: t_i18n('Requests for information'), link: '/dashboard/cases/rfis' },
        { label: caseData.name, current: true },
      ]}
      />
      <ContainerHeader
        container={caseData}
        EditComponent={(
          <Security needs={[KNOWLEDGE_KNUPDATE]} hasAccess={currentAccessRight.canEdit}>
            <CaseRfiEdition caseId={caseData.id} />
          </Security>
        )}
        DeleteComponent={({ isOpen, onClose }: { isOpen: boolean; onClose: () => void }) => (
          <Security needs={[KNOWLEDGE_KNUPDATE_KNDELETE]}>
            <CaseRfiDeletion id={caseData.id} isOpen={isOpen} handleClose={onClose} />
          </Security>
        )}
        enableQuickSubscription={true}
        enableEnrollPlaybook={true}
        redirectToContent={true}
        enableEnricher={true}
      />
      <Box
        sx={{
          borderBottom: 1,
          borderColor: 'divider',
          marginBottom: 3,
          display: 'flex',
          justifyContent: 'space-between',
          alignItem: 'center',
        }}
      >
        <Tabs
          value={getCurrentTab(location.pathname, caseData.id, '/dashboard/cases/rfis')}
        >
          <Tab
            component={Link}
            to={`/dashboard/cases/rfis/${caseData.id}`}
            value={`/dashboard/cases/rfis/${caseData.id}`}
            label={t_i18n('Overview')}
          />
          <Tab
            component={Link}
            to={`/dashboard/cases/rfis/${caseData.id}/knowledge/graph`}
            value={`/dashboard/cases/rfis/${caseData.id}/knowledge`}
            label={t_i18n('Knowledge')}
          />
          <Tab
            component={Link}
            to={`/dashboard/cases/rfis/${caseData.id}/content`}
            value={`/dashboard/cases/rfis/${caseData.id}/content`}
            label={t_i18n('Content')}
          />
          <Tab
            component={Link}
            to={`/dashboard/cases/rfis/${caseData.id}/entities`}
            value={`/dashboard/cases/rfis/${caseData.id}/entities`}
            label={t_i18n('Entities')}
          />
          <Tab
            component={Link}
            to={`/dashboard/cases/rfis/${caseData.id}/observables`}
            value={`/dashboard/cases/rfis/${caseData.id}/observables`}
            label={t_i18n('Observables')}
          />
          <Tab
            component={Link}
            to={`/dashboard/cases/rfis/${caseData.id}/files`}
            value={`/dashboard/cases/rfis/${caseData.id}/files`}
            label={t_i18n('Data')}
          />
        </Tabs>
        {!isKnowledgeOrContent && (
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '10px' }}>
            <AIInsights id={caseData.id} tabs={['containers']} defaultTab="containers" isContainer={true} />
          </div>
        )}
      </Box>
      <Routes>
        <Route
          path="/"
          element={<CaseRfi caseRfiData={caseData} enableReferences={enableReferences} />}
        />
        <Route
          path="/entities"
          element={(
            <ContainerStixDomainObjects
              container={caseData}
              enableReferences={enableReferences}
            />
          )}
        />
        <Route
          path="/observables"
          element={(
            <ContainerStixCyberObservables
              container={caseData}
              enableReferences={enableReferences}
            />
          )}
        />
        <Route
          path="/knowledge"
          element={
            <Navigate to={`/dashboard/cases/rfis/${caseId}/knowledge/graph`} replace={true} />
          }
        />
        <Route
          path="/content/*"
          element={(
            <StixCoreObjectContentRoot
              stixCoreObject={caseData}
              isContainer={true}
            />
          )}
        />
        <Route
          path="/knowledge/*"
          element={(
            <CaseRfiKnowledge
              caseData={caseData}
              enableReferences={enableReferences}
            />
          )}
        />
        <Route
          path="/files"
          element={(
            <StixCoreObjectFilesAndHistory
              id={caseId}
              connectorsExport={connectorsForExport}
              connectorsImport={connectorsForImport}
              entity={caseData}
              withoutRelations={true}
              bypassEntityId={true}
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
      </Routes>
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
