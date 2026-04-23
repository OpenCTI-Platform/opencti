// TODO Remove this when V6
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-nocheck
import React, { useMemo } from 'react';
import { graphql, usePreloadedQuery, useSubscription } from 'react-relay';
import { useLocation, useParams } from 'react-router-dom';
import { GraphQLSubscriptionConfig } from 'relay-runtime';
import StixDomainObjectMain from '@components/common/stix_domain_objects/StixDomainObjectMain';
import StixCoreObjectContentRoot from '@components/common/stix_core_objects/StixCoreObjectContentRoot';
import StixCoreObjectSecurityCoverage from '@components/common/stix_core_objects/StixCoreObjectSecurityCoverage';
import Security from 'src/utils/Security';
import AIInsights from '@components/common/ai/AIInsights';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import ContainerHeader from '../../common/containers/ContainerHeader';
import ContainerStixCyberObservables from '../../common/containers/ContainerStixCyberObservables';
import ContainerStixDomainObjects from '../../common/containers/ContainerStixDomainObjects';
import StixCoreObjectFilesAndHistory from '../../common/stix_core_objects/StixCoreObjectFilesAndHistory';
import { RootIncidentCaseQuery } from './__generated__/RootIncidentCaseQuery.graphql';
import CaseIncident from './CaseIncident';
import IncidentKnowledge from './IncidentKnowledge';
import { RootIncidentQuery } from '../../events/incidents/__generated__/RootIncidentQuery.graphql';
import { RootIncidentSubscription } from '../../events/incidents/__generated__/RootIncidentSubscription.graphql';
import { useFormatter } from '../../../../components/i18n';
import Breadcrumbs from '../../../../components/Breadcrumbs';
import { useIsEnforceReference } from '../../../../utils/hooks/useEntitySettings';
import useGranted, { KNOWLEDGE_KNUPDATE, KNOWLEDGE_KNUPDATE_KNBYPASSREFERENCE, KNOWLEDGE_KNUPDATE_KNDELETE } from '../../../../utils/hooks/useGranted';
import { getPaddingRight } from '../../../../utils/utils';
import CaseIncidentEdition from './CaseIncidentEdition';
import { useGetCurrentUserAccessRight } from '../../../../utils/authorizedMembers';
import CaseIncidentDeletion from './CaseIncidentDeletion';
import { PATH_CASE_INCIDENT, PATH_CASE_INCIDENTS } from '@components/common/routes/paths';

const subscription = graphql`
  subscription RootIncidentCaseSubscription($id: ID!) {
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

const caseIncidentQuery = graphql`
  query RootIncidentCaseQuery($id: String!) {
    caseIncident(id: $id) {
      id
      standard_id
      entity_type
      currentUserAccessRight
      objectMarking {
        id
        definition_type
        definition
        x_opencti_order
        x_opencti_color
      }
      creators {
        id
        name
        entity_type
      }
      name
      securityCoverage {
        id
        coverage_information {
          coverage_name
          coverage_score
        }
      }
      ...CaseUtils_case
      ...IncidentKnowledge_case
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

const RootCaseIncidentComponent = ({ queryRef, caseId }) => {
  const subConfig = useMemo<GraphQLSubscriptionConfig<RootIncidentSubscription>>(
    () => ({
      subscription,
      variables: { id: caseId },
    }),
    [caseId],
  );
  const location = useLocation();
  const enableReferences = useIsEnforceReference('Case-Incident') && !useGranted([KNOWLEDGE_KNUPDATE_KNBYPASSREFERENCE]);
  const { t_i18n } = useFormatter();
  useSubscription(subConfig);
  const {
    caseIncident: caseData,
    connectorsForExport,
    connectorsForImport,
  } = usePreloadedQuery<RootIncidentCaseQuery>(caseIncidentQuery, queryRef);
  if (!caseData) {
    return <ErrorNotFound />;
  }
  const basePath = PATH_CASE_INCIDENT(caseId);
  const paddingRight = getPaddingRight(location.pathname, basePath, false);
  const isKnowledgeOrContent = location.pathname.includes('knowledge') || location.pathname.includes('content');
  const currentAccessRight = useGetCurrentUserAccessRight(caseData.currentUserAccessRight);
  return (
    <div style={{ paddingRight }} data-testid="incident-details-page">
      <Breadcrumbs elements={[
        { label: t_i18n('Cases') },
        { label: t_i18n('Incident responses'), link: PATH_CASE_INCIDENTS },
        { label: caseData.name, current: true },
      ]}
      />
      <ContainerHeader
        container={caseData}
        EditComponent={(
          <Security needs={[KNOWLEDGE_KNUPDATE]} hasAccess={currentAccessRight.canEdit}>
            <CaseIncidentEdition caseId={caseData.id} />
          </Security>
        )}
        DeleteComponent={({ isOpen, onClose }: { isOpen: boolean; onClose: () => void }) => (
          <Security needs={[KNOWLEDGE_KNUPDATE_KNDELETE]}>
            <CaseIncidentDeletion id={caseData.id} isOpen={isOpen} handleClose={onClose} />
          </Security>
        )}
        enableQuickSubscription={true}
        enableEnrollPlaybook={true}
        redirectToContent={true}
        enableEnricher={true}
      />
      <StixDomainObjectMain
        basePath={basePath}
        pages={{
          overview: <CaseIncident caseIncidentData={caseData} enableReferences={enableReferences} />,
          knowledge: (
            <IncidentKnowledge
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
        extraActions={!isKnowledgeOrContent && (
          <>
            <AIInsights id={caseData.id} tabs={['containers']} defaultTab="containers" isContainer={true} />
            <StixCoreObjectSecurityCoverage id={caseData.id} coverage={caseData.securityCoverage} />
          </>
        )}
      />
    </div>
  );
};

const Root = () => {
  const { caseId } = useParams();
  const queryRef = useQueryLoading<RootIncidentQuery>(caseIncidentQuery, {
    id: caseId,
  });
  return (
    <>
      {queryRef && (
        <React.Suspense fallback={<Loader variant={LoaderVariant.container} />}>
          <RootCaseIncidentComponent queryRef={queryRef} caseId={caseId} />
        </React.Suspense>
      )}
    </>
  );
};

export default Root;
