import { useMemo } from 'react';
import { graphql, useSubscription } from 'react-relay';
import { useLocation, useParams } from 'react-router-dom';
import { GraphQLSubscriptionConfig } from 'relay-runtime';
import StixCoreObjectContentRoot from '@components/common/stix_core_objects/StixCoreObjectContentRoot';
import StixDomainObjectMain from '@components/common/stix_domain_objects/StixDomainObjectMain';
import Security from 'src/utils/Security';
import StixCoreObjectSecurityCoverage from '@components/common/stix_core_objects/StixCoreObjectSecurityCoverage';
import { QueryRenderer } from '../../../../relay/environment';
import Report from './Report';
import { RootReportSubscription } from './__generated__/RootReportSubscription.graphql';
import { RootReportQuery$data } from './__generated__/RootReportQuery.graphql';
import ReportKnowledge from './ReportKnowledge';
import ContainerHeader from '../../common/containers/ContainerHeader';
import Loader from '../../../../components/Loader';
import ContainerStixDomainObjects from '../../common/containers/ContainerStixDomainObjects';
import ContainerStixCyberObservables from '../../common/containers/ContainerStixCyberObservables';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import StixCoreObjectFilesAndHistory from '../../common/stix_core_objects/StixCoreObjectFilesAndHistory';
import Breadcrumbs from '../../../../components/Breadcrumbs';
import { useFormatter } from '../../../../components/i18n';
import { useIsEnforceReference } from '../../../../utils/hooks/useEntitySettings';
import useGranted, { KNOWLEDGE_KNUPDATE, KNOWLEDGE_KNUPDATE_KNDELETE, KNOWLEDGE_KNUPDATE_KNBYPASSREFERENCE } from '../../../../utils/hooks/useGranted';
import { getPaddingRight } from '../../../../utils/utils';
import ReportEdition from './ReportEdition';
import ReportDeletion from './ReportDeletion';
import { useGetCurrentUserAccessRight } from '../../../../utils/authorizedMembers';
import AIInsights from '@components/common/ai/AIInsights';
import { PATH_REPORT, PATH_REPORTS } from '@components/common/routes/paths';

const subscription = graphql`
  subscription RootReportSubscription($id: ID!) {
    stixDomainObject(id: $id) {
      ... on Report {
        ...Report_report
        ...ReportEditionContainer_report
        ...StixCoreObjectContent_stixCoreObject
      }
      ...FileImportViewer_entity
      ...FileExportViewer_entity
      ...FileExternalReferencesViewer_entity
      ...WorkbenchFileViewer_entity
    }
  }
`;

const reportQuery = graphql`
  query RootReportQuery($id: String!) {
    report(id: $id) {
      id
      standard_id
      entity_type
      name
      currentUserAccessRight
      objectMarking {
        id
        definition_type
        definition
        x_opencti_order
        x_opencti_color
      }
      securityCoverage {
          id
          coverage_information {
              coverage_name
              coverage_score
          }
      }
      ...Report_report
      ...ReportDetails_report
      ...ReportKnowledge_report
      ...ContainerHeader_container
      ...ContainerStixDomainObjects_container
      ...ContainerStixCyberObservables_container
      ...StixCoreObjectContent_stixCoreObject
      ...FileImportViewer_entity
      ...FileExportViewer_entity
      ...FileExternalReferencesViewer_entity
      ...WorkbenchFileViewer_entity
    }
    connectorsForExport {
      ...StixCoreObjectFilesAndHistory_connectorsExport
    }
    connectorsForImport {
      ...StixCoreObjectFilesAndHistory_connectorsImport
    }
  }
`;

const RootReport = () => {
  const { reportId } = useParams() as { reportId: string };
  const subConfig = useMemo<GraphQLSubscriptionConfig<RootReportSubscription>>(
    () => ({
      subscription,
      variables: { id: reportId },
    }),
    [reportId],
  );
  const location = useLocation();
  const enableReferences = useIsEnforceReference('Report') && !useGranted([KNOWLEDGE_KNUPDATE_KNBYPASSREFERENCE]);
  const { t_i18n } = useFormatter();
  useSubscription(subConfig);
  const basePath = PATH_REPORT(reportId);
  return (
    <>
      <QueryRenderer
        query={reportQuery}
        variables={{ id: reportId }}
        render={({ props }: { props: RootReportQuery$data }) => {
          if (props) {
            if (props.report) {
              const { report } = props;
              const isOverview = location.pathname === basePath;
              const paddingRight = getPaddingRight(location.pathname, basePath, false);
              const isKnowledgeOrContent = location.pathname.includes('knowledge') || location.pathname.includes('content');
              const currentAccessRight = useGetCurrentUserAccessRight(report.currentUserAccessRight);
              return (
                <div style={{ paddingRight }} data-testid="report-details-page">
                  <Breadcrumbs elements={[
                    { label: t_i18n('Analyses') },
                    { label: t_i18n('Reports'), link: PATH_REPORTS },
                    { label: report.name, current: true },
                  ]}
                  />
                  <ContainerHeader
                    container={report}
                    EditComponent={(
                      <Security needs={[KNOWLEDGE_KNUPDATE]} hasAccess={currentAccessRight.canEdit}>
                        <ReportEdition reportId={report.id} />
                      </Security>
                    )}
                    DeleteComponent={({ isOpen, onClose }: { isOpen: boolean; onClose: () => void }) => (
                      <Security needs={[KNOWLEDGE_KNUPDATE_KNDELETE]}>
                        <ReportDeletion reportId={report.id} isOpen={isOpen} handleClose={onClose} />
                      </Security>
                    )}
                    enableQuickSubscription={true}
                    enableQuickExport={true}
                    enableEnrollPlaybook={true}
                    overview={isOverview}
                    redirectToContent={true}
                    enableEnricher={true}
                  />
                  <StixDomainObjectMain
                    basePath={basePath}
                    pages={{
                      overview:
                        <Report reportFragment={report} />,
                      knowledge: (
                        <ReportKnowledge
                          report={report}
                          enableReferences={enableReferences}
                        />
                      ),
                      content: (
                        <StixCoreObjectContentRoot
                          stixCoreObject={report}
                          isContainer={true}
                        />
                      ),
                      entities: (
                        <ContainerStixDomainObjects
                          container={report}
                          enableReferences={enableReferences}
                        />
                      ),
                      observables: (
                        <ContainerStixCyberObservables
                          container={report}
                          enableReferences={enableReferences}
                        />
                      ),
                      files: (
                        <StixCoreObjectFilesAndHistory
                          id={reportId}
                          connectorsExport={props.connectorsForExport}
                          connectorsImport={props.connectorsForImport}
                          entity={report}
                          withoutRelations={true}
                          bypassEntityId={true}
                        />
                      ),
                    }}
                    extraActions={!isKnowledgeOrContent && (
                      <>
                        <AIInsights id={report.id} tabs={['containers']} defaultTab="containers" isContainer={true} />
                        <StixCoreObjectSecurityCoverage id={report.id} coverage={report.securityCoverage} />
                      </>
                    )}
                  />
                </div>
              );
            }
            return <ErrorNotFound />;
          }
          return <Loader />;
        }}
      />
    </>
  );
};

export default RootReport;
