import { graphql, useSubscription } from 'react-relay';
import { Link, Route, Routes, useParams, useLocation } from 'react-router-dom';
import React, { useMemo } from 'react';
import { GraphQLSubscriptionConfig } from 'relay-runtime';
import Box from '@mui/material/Box';
import Tabs from '@mui/material/Tabs';
import Tab from '@mui/material/Tab';
import Security from 'src/utils/Security';
import { KNOWLEDGE_KNUPDATE, KNOWLEDGE_KNUPDATE_KNDELETE } from 'src/utils/hooks/useGranted';
import SecurityCoverageDeletion from './SecurityCoverageDeletion';
import SecurityCoverageEdition from './SecurityCoverageEdition';
import SecurityCoverage from './SecurityCoverage';
import { QueryRenderer } from '../../../../relay/environment';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import Loader from '../../../../components/Loader';
import { RootSecurityCoverageSubscription } from './__generated__/RootSecurityCoverageSubscription.graphql';
import { RootSecurityCoverageQuery$data } from './__generated__/RootSecurityCoverageQuery.graphql';
import ContainerHeader from '../../common/containers/ContainerHeader';
import FileManager from '../../common/files/FileManager';
import StixCoreObjectHistory from '../../common/stix_core_objects/StixCoreObjectHistory';
import StixCoreRelationship from '../../common/stix_core_relationships/StixCoreRelationship';
import { useFormatter } from '../../../../components/i18n';
import Breadcrumbs from '../../../../components/Breadcrumbs';
import { getMainRepresentative } from '../../../../utils/defaultRepresentatives';
import { getCurrentTab, getPaddingRight } from '../../../../utils/utils';

const subscription = graphql`
  subscription RootSecurityCoverageSubscription($id: ID!) {
    stixDomainObject(id: $id) {
      ... on SecurityCoverage {
        ...SecurityCoverage_securityCoverage
      }
      ...FileImportViewer_entity
      ...FileExportViewer_entity
      ...FileExternalReferencesViewer_entity
      ...WorkbenchFileViewer_entity
    }
  }
`;

const securityCoverageQuery = graphql`
  query RootSecurityCoverageQuery($id: String!) {
    securityCoverage(id: $id) {
      id
      draftVersion {
        draft_id
        draft_operation
      }
      standard_id
      name
      description
      x_opencti_graph_data
      coverage_last_result
      coverage_valid_from
      coverage_valid_to
      ...SecurityCoverage_securityCoverage
      ...FileImportViewer_entity
      ...FileExportViewer_entity
      ...FileExternalReferencesViewer_entity
      ...WorkbenchFileViewer_entity
      ...StixCoreObjectSharingListFragment
    }
    connectorsForImport {
      ...FileManager_connectorsImport
    }
    connectorsForExport {
      ...FileManager_connectorsExport
    }
  }
`;

const SecurityCoverageRoot = () => {
  const { securityCoverageId } = useParams() as { securityCoverageId: string };
  const subConfig = useMemo<
  GraphQLSubscriptionConfig<RootSecurityCoverageSubscription>
  >(
    () => ({
      subscription,
      variables: { id: securityCoverageId },
    }),
    [securityCoverageId],
  );
  const location = useLocation();
  const { t_i18n } = useFormatter();
  useSubscription(subConfig);
  return (
    <>
      <QueryRenderer
        query={securityCoverageQuery}
        variables={{ id: securityCoverageId }}
        render={({ props }: { props: RootSecurityCoverageQuery$data }) => {
          if (props) {
            if (props.securityCoverage) {
              const { securityCoverage } = props;
              const paddingRight = getPaddingRight(location.pathname, securityCoverage.id, '/dashboard/analyses/security_coverages', false);
              return (
                <div style={{ paddingRight }}>
                  <Breadcrumbs elements={[
                    { label: t_i18n('Analyses') },
                    { label: t_i18n('Security coverages'), link: '/dashboard/analyses/security_coverages' },
                    { label: getMainRepresentative(securityCoverage), current: true },
                  ]}
                  />
                  <ContainerHeader
                    container={securityCoverage}
                    EditComponent={(
                      <Security needs={[KNOWLEDGE_KNUPDATE]}>
                        <SecurityCoverageEdition securityCoverageId={securityCoverage.id} />
                      </Security>
                    )}
                    DeleteComponent={({ isOpen, onClose }: { isOpen: boolean, onClose: () => void }) => (
                      <Security needs={[KNOWLEDGE_KNUPDATE_KNDELETE]}>
                        <SecurityCoverageDeletion id={securityCoverage.id} isOpen={isOpen} handleClose={onClose} />
                      </Security>
                    )}
                    enableQuickSubscription={true}
                    enableQuickExport={true}
                    enableEnrollPlaybook={true}
                    enableAskAi={false}
                    disableSharing={false}
                    overview={location.pathname === `/dashboard/analyses/security_coverages/${securityCoverage.id}`}
                    redirectToContent={true}
                    enableEnricher={true}
                  />
                  <Box
                    sx={{
                      borderBottom: 1,
                      borderColor: 'divider',
                      marginBottom: 3,
                    }}
                  >
                    <Tabs
                      value={getCurrentTab(location.pathname, securityCoverage.id, '/dashboard/analyses/security_coverages')}
                    >
                      <Tab
                        component={Link}
                        to={`/dashboard/analyses/security_coverages/${securityCoverage.id}`}
                        value={`/dashboard/analyses/security_coverages/${securityCoverage.id}`}
                        label={t_i18n('Overview')}
                      />
                      <Tab
                        component={Link}
                        to={`/dashboard/analyses/security_coverages/${securityCoverage.id}/files`}
                        value={`/dashboard/analyses/security_coverages/${securityCoverage.id}/files`}
                        label={t_i18n('Data')}
                      />
                      <Tab
                        component={Link}
                        to={`/dashboard/analyses/security_coverages/${securityCoverage.id}/history`}
                        value={`/dashboard/analyses/security_coverages/${securityCoverage.id}/history`}
                        label={t_i18n('History')}
                      />
                    </Tabs>
                  </Box>
                  <Routes>
                    <Route
                      path="/"
                      element={<SecurityCoverage data={securityCoverage}/>}
                    />
                    <Route
                      path="/knowledge/relations/:relationId"
                      element={
                        <StixCoreRelationship
                          entityId={securityCoverageId}
                        />}
                    />
                    <Route
                      path="/files"
                      element={
                        <FileManager
                          id={securityCoverageId}
                          connectorsImport={props.connectorsForImport}
                          connectorsExport={props.connectorsForExport}
                          entity={securityCoverage}
                        />}
                    />
                    <Route
                      path="/history"
                      element={
                        <StixCoreObjectHistory
                          stixCoreObjectId={securityCoverageId}
                        />}
                    />
                  </Routes>
                </div>
              );
            }
            return <ErrorNotFound/>;
          }
          return <Loader />;
        }}
      />
    </>
  );
};
export default SecurityCoverageRoot;
