import React, { useMemo } from 'react';
import { useLocation, useParams } from 'react-router-dom';
import { graphql, PreloadedQuery, usePreloadedQuery, useSubscription } from 'react-relay';
import { FragmentRef, GraphQLSubscriptionConfig } from 'relay-runtime';
import StixCoreObjectContentRoot from '@components/common/stix_core_objects/StixCoreObjectContentRoot';
import StixDomainObjectMain from '@components/common/stix_domain_objects/StixDomainObjectMain';
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
import ContainerStixDomainObjects from '../../common/containers/ContainerStixDomainObjects';
import ContainerStixCyberObservables from '../../common/containers/ContainerStixCyberObservables';
import CaseRfiKnowledge from './CaseRfiKnowledge';
import { useFormatter } from '../../../../components/i18n';
import Breadcrumbs from '../../../../components/Breadcrumbs';
import { useIsEnforceReference } from '../../../../utils/hooks/useEntitySettings';
import useGranted, { KNOWLEDGE_KNUPDATE, KNOWLEDGE_KNUPDATE_KNBYPASSREFERENCE, KNOWLEDGE_KNUPDATE_KNDELETE } from '../../../../utils/hooks/useGranted';
import { getPaddingRight } from '../../../../utils/utils';
import CaseRfiEdition from './CaseRfiEdition';
import { useGetCurrentUserAccessRight } from '../../../../utils/authorizedMembers';
import CaseRfiDeletion from './CaseRfiDeletion';
import { PATH_RFI, PATH_RFIS } from '@components/common/routes/paths';
import { CaseRfiKnowledge_case$data } from './__generated__/CaseRfiKnowledge_case.graphql';

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
      objectMarking {
        id
        definition_type
        definition
        x_opencti_order
        x_opencti_color
      }
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

interface RootCaseRfiComponentProps {
  queryRef: PreloadedQuery<RootCaseRfiCaseQuery>;
  caseId: string;
}

const RootCaseRfiComponent = ({ queryRef, caseId }: RootCaseRfiComponentProps) => {
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
  const basePath = PATH_RFI(caseId);
  const paddingRight = getPaddingRight(location.pathname, basePath, false);
  const isKnowledgeOrContent = location.pathname.includes('knowledge') || location.pathname.includes('content');
  const currentAccessRight = useGetCurrentUserAccessRight(caseData.currentUserAccessRight);
  const CaseRfiKnowledgeComponent = CaseRfiKnowledge as React.ComponentType<{
    caseData: FragmentRef<CaseRfiKnowledge_case$data>;
    enableReferences: boolean;
  }>;
  return (
    <div style={{ paddingRight }}>
      <Breadcrumbs elements={[
        { label: t_i18n('Cases') },
        { label: t_i18n('Requests for information'), link: PATH_RFIS },
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
      <StixDomainObjectMain
        entity={caseData}
        basePath={basePath}
        pages={{
          overview: <CaseRfi caseRfiData={caseData} enableReferences={enableReferences} />,
          knowledge: (
            <CaseRfiKnowledgeComponent
              caseData={caseData}
              enableReferences={enableReferences}
            />
          ),
          content: (
            <StixCoreObjectContentRoot
              stixCoreObject={caseData}
              isContainer={true}
            />
          ),
          entities: (
            <ContainerStixDomainObjects
              container={caseData}
              enableReferences={enableReferences}
            />
          ),
          observables: (
            <ContainerStixCyberObservables
              container={caseData}
              enableReferences={enableReferences}
            />
          ),
          files: (
            <StixCoreObjectFilesAndHistory
              id={caseId}
              connectorsExport={connectorsForExport}
              connectorsImport={connectorsForImport}
              entity={caseData}
              withoutRelations={true}
              bypassEntityId={true}
            />
          ),
        }}
        extraActions={!isKnowledgeOrContent && <AIInsights id={caseData.id} tabs={['containers']} defaultTab="containers" isContainer={true} />}
      />
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
