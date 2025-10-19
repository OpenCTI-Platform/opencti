import React from 'react';
import { graphql } from 'react-relay';
import { Link, Route, Routes, useLocation, useParams } from 'react-router-dom';
import Box from '@mui/material/Box';
import Tabs from '@mui/material/Tabs';
import Tab from '@mui/material/Tab';
import StixCoreObjectContentRoot from '@components/common/stix_core_objects/StixCoreObjectContentRoot';
import Security from 'src/utils/Security';
import { QueryRenderer } from '../../../../relay/environment';
import SecurityCoverage from './SecurityCoverage';
import { RootSecurityCoverageQuery$data } from './__generated__/RootSecurityCoverageQuery.graphql';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';
import Loader from '../../../../components/Loader';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import StixCoreObjectFilesAndHistory from '../../common/stix_core_objects/StixCoreObjectFilesAndHistory';
import Breadcrumbs from '../../../../components/Breadcrumbs';
import { useFormatter } from '../../../../components/i18n';
import { KNOWLEDGE_KNUPDATE, KNOWLEDGE_KNUPDATE_KNDELETE } from '../../../../utils/hooks/useGranted';
import { getCurrentTab, getPaddingRight } from '../../../../utils/utils';
import SecurityCoverageEdition from './SecurityCoverageEdition';
import SecurityCoverageDeletion from './SecurityCoverageDeletion';

const securityCoverageQuery = graphql`
  query RootSecurityCoverageQuery($id: String!) {
    securityCoverage(id: $id) {
      id
      standard_id
      entity_type
      name
      description
      x_opencti_graph_data
      coverage_last_result
      coverage_valid_from
      coverage_valid_to
      coverage_information {
        coverage_name
        coverage_score
      }
      objectMarking {
        id
      }
      ...SecurityCoverage_securityCoverage
      ...StixCoreObjectContent_stixCoreObject
      ...FileImportViewer_entity
      ...FileExportViewer_entity
      ...FileExternalReferencesViewer_entity
      ...WorkbenchFileViewer_entity
      ...StixCoreObjectSharingListFragment
    }
    connectorsForExport {
      ...StixCoreObjectFilesAndHistory_connectorsExport
    }
    connectorsForImport {
      ...StixCoreObjectFilesAndHistory_connectorsImport
    }
  }
`;

const RootSecurityCoverage = () => {
  const { securityCoverageId } = useParams() as { securityCoverageId: string };
  const location = useLocation();
  const { t_i18n } = useFormatter();

  return (
    <>
      <QueryRenderer
        query={securityCoverageQuery}
        variables={{ id: securityCoverageId }}
        render={({ props }: { props: RootSecurityCoverageQuery$data }) => {
          if (props) {
            if (props.securityCoverage) {
              const { securityCoverage } = props;
              const paddingRight = getPaddingRight(location.pathname, securityCoverageId, '/dashboard/analyses/security_coverages', false);

              return (
                <div style={{ paddingRight }}>
                  <Breadcrumbs elements={[
                    { label: t_i18n('Analyses') },
                    { label: t_i18n('Security Coverages'), link: '/dashboard/analyses/security_coverages' },
                    { label: securityCoverage.name, current: true },
                  ]}
                  />
                  <StixDomainObjectHeader
                    entityType="Security-Coverage"
                    stixDomainObject={securityCoverage}
                    EditComponent={(
                      <Security needs={[KNOWLEDGE_KNUPDATE]}>
                        <SecurityCoverageEdition securityCoverageId={securityCoverage.id} />
                      </Security>
                    )}
                    DeleteComponent={({ isOpen, onClose }: { isOpen: boolean, onClose: () => void }) => (
                      <Security needs={[KNOWLEDGE_KNUPDATE_KNDELETE]}>
                        <SecurityCoverageDeletion securityCoverageId={securityCoverage.id} isOpen={isOpen} handleClose={onClose} />
                      </Security>
                    )}
                    enableQuickSubscription={true}
                    enableQuickExport={true}
                    enableAskAi={false}
                    enableEnricher={true}
                    redirectToContent={true}
                  />
                  <Box
                    sx={{
                      borderBottom: 1,
                      borderColor: 'divider',
                      marginBottom: 3,
                    }}
                  >
                    <Tabs value={getCurrentTab(location.pathname, securityCoverage.id, '/dashboard/analyses/security_coverages')}>
                      <Tab
                        component={Link}
                        to={`/dashboard/analyses/security_coverages/${securityCoverage.id}`}
                        value={`/dashboard/analyses/security_coverages/${securityCoverage.id}`}
                        label={t_i18n('Overview')}
                      />
                      <Tab
                        component={Link}
                        to={`/dashboard/analyses/security_coverages/${securityCoverage.id}/content`}
                        value={`/dashboard/analyses/security_coverages/${securityCoverage.id}/content`}
                        label={t_i18n('Content')}
                      />
                      <Tab
                        component={Link}
                        to={`/dashboard/analyses/security_coverages/${securityCoverage.id}/files`}
                        value={`/dashboard/analyses/security_coverages/${securityCoverage.id}/files`}
                        label={t_i18n('Data')}
                      />
                    </Tabs>
                  </Box>
                  <Routes>
                    <Route
                      path="/"
                      element={
                        <SecurityCoverage data={securityCoverage} />
                      }
                    />
                    <Route
                      path="/content/*"
                      element={
                        <StixCoreObjectContentRoot
                          stixCoreObject={securityCoverage}
                          isContainer={false}
                        />
                      }
                    />
                    <Route
                      path="/files"
                      element={
                        <StixCoreObjectFilesAndHistory
                          id={securityCoverageId}
                          connectorsExport={props.connectorsForExport}
                          connectorsImport={props.connectorsForImport}
                          entity={securityCoverage}
                          withoutRelations={true}
                          bypassEntityId={true}
                        />
                      }
                    />
                  </Routes>
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

export default RootSecurityCoverage;
