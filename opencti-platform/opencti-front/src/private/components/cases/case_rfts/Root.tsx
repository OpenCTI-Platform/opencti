// TODO Remove this when V6
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-nocheck
import React, { useMemo } from 'react';
import { Navigate, Route, Routes, useLocation, useParams } from 'react-router-dom';
import { graphql, usePreloadedQuery, useSubscription } from 'react-relay';
import { GraphQLSubscriptionConfig } from 'relay-runtime';
import StixDomainObjectTabsBox from '@components/common/stix_domain_objects/StixDomainObjectTabsBox';
import StixCoreObjectContentRoot from '@components/common/stix_core_objects/StixCoreObjectContentRoot';
import Security from 'src/utils/Security';
import AIInsights from '@components/common/ai/AIInsights';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import ContainerHeader from '../../common/containers/ContainerHeader';
import StixCoreObjectFilesAndHistory from '../../common/stix_core_objects/StixCoreObjectFilesAndHistory';
import StixCoreObjectHistory from '../../common/stix_core_objects/StixCoreObjectHistory';
import CaseRft from './CaseRft';
import CaseRftKnowledge from './CaseRftKnowledge';
import ContainerStixCyberObservables from '../../common/containers/ContainerStixCyberObservables';
import ContainerStixDomainObjects from '../../common/containers/ContainerStixDomainObjects';
import { RootCaseRftCaseQuery } from './__generated__/RootCaseRftCaseQuery.graphql';
import { useFormatter } from '../../../../components/i18n';
import { useEntityLabelResolver } from '../../../../utils/hooks/useEntityLabel';
import Breadcrumbs from '../../../../components/Breadcrumbs';
import { useIsEnforceReference } from '../../../../utils/hooks/useEntitySettings';
import useGranted, { KNOWLEDGE_KNUPDATE, KNOWLEDGE_KNUPDATE_KNBYPASSREFERENCE, KNOWLEDGE_KNUPDATE_KNDELETE } from '../../../../utils/hooks/useGranted';
import { getPaddingRight } from '../../../../utils/utils';
import CaseRftEdition from './CaseRftEdition';
import { useGetCurrentUserAccessRight } from '../../../../utils/authorizedMembers';
import CaseRftDeletion from './CaseRftDeletion';

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
      entity_type
      currentUserAccessRight
      name
      x_opencti_graph_data
      ...CaseUtils_case
      ...CaseRftKnowledge_case
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

const RootCaseRftComponent = ({ queryRef, caseId }) => {
  const subConfig = useMemo<
    GraphQLSubscriptionConfig<RootCaseRftCaseSubscription>
  >(
    () => ({
      subscription,
      variables: { id: caseId },
    }),
    [caseId],
  );
  const location = useLocation();
  const enableReferences = useIsEnforceReference('Case-Rft') && !useGranted([KNOWLEDGE_KNUPDATE_KNBYPASSREFERENCE]);
  const { t_i18n } = useFormatter();
  const entityLabel = useEntityLabelResolver();
  useSubscription(subConfig);

  const {
    caseRft: caseData,
    connectorsForExport,
    connectorsForImport,
  } = usePreloadedQuery<RootCaseRftCaseQuery>(caseRftQuery, queryRef);
  if (!caseData) {
    return <ErrorNotFound />;
  }
  const paddingRight = getPaddingRight(location.pathname, caseData.id, '/dashboard/cases/rfts', false);
  const isKnowledgeOrContent = location.pathname.includes('knowledge') || location.pathname.includes('content');
  const currentAccessRight = useGetCurrentUserAccessRight(caseData.currentUserAccessRight);
  return (
    <div style={{ paddingRight }}>
      <Breadcrumbs elements={[
        { label: t_i18n('Cases') },
        { label: entityLabel('Case-Rft', t_i18n('Requests for takedown')), link: '/dashboard/cases/rfts' },
        { label: caseData.name, current: true },
      ]}
      />
      <ContainerHeader
        container={caseData}
        EditComponent={(
          <Security needs={[KNOWLEDGE_KNUPDATE]} hasAccess={currentAccessRight.canEdit}>
            <CaseRftEdition caseId={caseData.id} />
          </Security>
        )}
        DeleteComponent={({ isOpen, onClose }: { isOpen: boolean; onClose: () => void }) => (
          <Security needs={[KNOWLEDGE_KNUPDATE_KNDELETE]}>
            <CaseRftDeletion id={caseData.id} isOpen={isOpen} handleClose={onClose} />
          </Security>
        )}
        enableQuickSubscription={true}
        enableEnrollPlaybook={true}
        redirectToContent={true}
        enableEnricher={true}
      />
      <StixDomainObjectTabsBox
        basePath="/dashboard/cases/rfts"
        entity={caseData}
        tabs={[
          'overview',
          'knowledge-graph',
          'content',
          'entities',
          'observables',
          'files',
        ]}
        extraActions={!isKnowledgeOrContent && <AIInsights id={caseData.id} tabs={['containers']} defaultTab="containers" isContainer={true} />}
      />
      <Routes>
        <Route
          path="/"
          element={<CaseRft caseRftData={caseData} enableReferences={enableReferences} />}
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
          path="/content/*"
          element={(
            <StixCoreObjectContentRoot
              stixCoreObject={caseData}
              isContainer={true}
            />
          )}
        />
        <Route
          path="/knowledge"
          element={(
            <Navigate
              replace={true}
              to={`/dashboard/cases/rfts/${caseId}/knowledge/graph`}
            />
          )}
        />
        <Route
          path="/knowledge/*"
          element={(
            <CaseRftKnowledge
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
