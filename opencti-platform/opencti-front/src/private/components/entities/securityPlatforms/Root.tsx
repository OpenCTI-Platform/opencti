import React, { useMemo, Suspense } from 'react';
import { Route, Routes, Link, Navigate, useLocation, useParams } from 'react-router-dom';
import { graphql, useSubscription, usePreloadedQuery, PreloadedQuery } from 'react-relay';
import { GraphQLSubscriptionConfig } from 'relay-runtime';
import Box from '@mui/material/Box';
import Tabs from '@mui/material/Tabs';
import Tab from '@mui/material/Tab';
import useQueryLoading from 'src/utils/hooks/useQueryLoading';
import useForceUpdate from '@components/common/bulk/useForceUpdate';
import { RootSecurityPlatformSubscription } from '@components/entities/securityPlatforms/__generated__/RootSecurityPlatformSubscription.graphql';
import { RootSecurityPlatformQuery } from '@components/entities/securityPlatforms/__generated__/RootSecurityPlatformQuery.graphql';
import SecurityPlatformKnowledge from '@components/entities/securityPlatforms/SecurityPlatformKnowledge';
import SecurityPlatformEdition from '@components/entities/securityPlatforms/SecurityPlatformEdition';
import SecurityPlatformAnalysis from '@components/entities/securityPlatforms/SecurityPlatformAnalysis';
import StixCoreObjectContentRoot from '../../common/stix_core_objects/StixCoreObjectContentRoot';
import SecurityPlatform from './SecurityPlatform';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';
import FileManager from '../../common/files/FileManager';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import StixCoreObjectHistory from '../../common/stix_core_objects/StixCoreObjectHistory';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import StixCoreObjectKnowledgeBar from '../../common/stix_core_objects/StixCoreObjectKnowledgeBar';
import { useFormatter } from '../../../../components/i18n';
import Breadcrumbs from '../../../../components/Breadcrumbs';
import { getCurrentTab, getPaddingRight } from '../../../../utils/utils';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNUPDATE, KNOWLEDGE_KNUPDATE_KNDELETE } from '../../../../utils/hooks/useGranted';
import SecurityPlatformDeletion from './SecurityPlatformDeletion';

const subscription = graphql`
  subscription RootSecurityPlatformSubscription($id: ID!) {
    stixDomainObject(id: $id) {
      ... on SecurityPlatform {
        ...SecurityPlatform_securityPlatform
        ...SecurityPlatformEditionContainer_securityPlatform
        ...SecurityPlatformDetails_securityPlatform
        ...SecurityPlatformAnalysis_securityPlatform
      }
      ...FileImportViewer_entity
      ...FileExportViewer_entity
      ...FileExternalReferencesViewer_entity
      ...WorkbenchFileViewer_entity
      ...PictureManagementViewer_entity
    }
  }
`;

const securityPlatformQuery = graphql`
  query RootSecurityPlatformQuery($id: String!) {
    securityPlatform(id: $id) {
      id
      draftVersion {
        draft_id
        draft_operation
      }
      standard_id
      entity_type
      name
      x_opencti_aliases
      security_platform_type
      ...StixCoreObjectKnowledgeBar_stixCoreObject
      ...SecurityPlatform_securityPlatform
      ...SecurityPlatformKnowledge_securityPlatform
      ...FileImportViewer_entity
      ...FileExportViewer_entity
      ...FileExternalReferencesViewer_entity
      ...WorkbenchFileViewer_entity
      ...PictureManagementViewer_entity
      ...StixCoreObjectContent_stixCoreObject
      ...SecurityPlatformAnalysis_securityPlatform
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

type RootSecurityPlatformProps = {
  securityPlatformId: string;
  queryRef: PreloadedQuery<RootSecurityPlatformQuery>;
};

const RootSecurityPlatform = ({ securityPlatformId, queryRef }: RootSecurityPlatformProps) => {
  const subConfig = useMemo<GraphQLSubscriptionConfig<RootSecurityPlatformSubscription>>(() => ({
    subscription,
    variables: { id: securityPlatformId },
  }), [securityPlatformId]);
  const location = useLocation();

  const { t_i18n } = useFormatter();
  useSubscription<RootSecurityPlatformSubscription>(subConfig);

  const {
    securityPlatform,
    connectorsForExport,
    connectorsForImport,
  } = usePreloadedQuery<RootSecurityPlatformQuery>(securityPlatformQuery, queryRef);

  const { forceUpdate } = useForceUpdate();

  const link = `/dashboard/entities/security_platforms/${securityPlatformId}/knowledge`;
  const paddingRight = getPaddingRight(location.pathname, securityPlatformId, '/dashboard/entities/security_platforms');
  return (
    <>
      {securityPlatform ? (
        <>
          <Routes>
            <Route
              path="/knowledge/*"
              element={
                <StixCoreObjectKnowledgeBar
                  stixCoreObjectLink={link}
                  availableSections={[
                    'attack_patterns',
                  ]}
                  data={securityPlatform}
                />
              }
            />
          </Routes>
          <div style={{ paddingRight }}>
            <Breadcrumbs elements={[
              { label: t_i18n('Entities') },
              { label: t_i18n('Security platforms'), link: '/dashboard/entities/security_platforms' },
              { label: securityPlatform.name, current: true },
            ]}
            />
            <StixDomainObjectHeader
              entityType="SecurityPlatform"
              stixDomainObject={securityPlatform}
              noAliases
              EditComponent={(
                <Security needs={[KNOWLEDGE_KNUPDATE]}>
                  <SecurityPlatformEdition securityPlatformId={securityPlatform.id} />
                </Security>
              )}
              DeleteComponent={({ isOpen, onClose }: { isOpen: boolean, onClose: () => void }) => (
                <Security needs={[KNOWLEDGE_KNUPDATE_KNDELETE]}>
                  <SecurityPlatformDeletion id={securityPlatform.id} isOpen={isOpen} handleClose={onClose} />
                </Security>
              )}
              enableQuickSubscription={true}
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
                value={getCurrentTab(location.pathname, securityPlatform.id, '/dashboard/entities/security_platforms')}
              >
                <Tab
                  component={Link}
                  to={`/dashboard/entities/security_platforms/${securityPlatform.id}`}
                  value={`/dashboard/entities/security_platforms/${securityPlatform.id}`}
                  label={t_i18n('Overview')}
                />
                <Tab
                  component={Link}
                  to={`/dashboard/entities/security_platforms/${securityPlatform.id}/knowledge/overview`}
                  value={`/dashboard/entities/security_platforms/${securityPlatform.id}/knowledge`}
                  label={t_i18n('Knowledge')}
                />
                <Tab
                  component={Link}
                  to={`/dashboard/entities/security_platforms/${securityPlatform.id}/content`}
                  value={`/dashboard/entities/security_platforms/${securityPlatform.id}/content`}
                  label={t_i18n('Content')}
                />
                <Tab
                  component={Link}
                  to={`/dashboard/entities/security_platforms/${securityPlatform.id}/analyses`}
                  value={`/dashboard/entities/security_platforms/${securityPlatform.id}/analyses`}
                  label={t_i18n('Analyses')}
                />
                <Tab
                  component={Link}
                  to={`/dashboard/entities/security_platforms/${securityPlatform.id}/files`}
                  value={`/dashboard/entities/security_platforms/${securityPlatform.id}/files`}
                  label={t_i18n('Data')}
                />
                <Tab
                  component={Link}
                  to={`/dashboard/entities/security_platforms/${securityPlatform.id}/history`}
                  value={`/dashboard/entities/security_platforms/${securityPlatform.id}/history`}
                  label={t_i18n('History')}
                />
              </Tabs>
            </Box>
            <Routes>
              <Route
                path="/"
                element={
                  <SecurityPlatform
                    securityPlatformData={securityPlatform}
                  />
                }
              />
              <Route
                path="/knowledge"
                element={
                  <Navigate
                    replace={true}
                    to={`/dashboard/entities/security_platforms/${securityPlatformId}/knowledge/overview`}
                  />
                }
              />
              <Route
                path="/knowledge/*"
                element={
                  <div key={forceUpdate}>
                    <SecurityPlatformKnowledge
                      securityPlatformData={securityPlatform}
                      relatedRelationshipTypes={['should-cover']}
                    />
                  </div>
                }
              />
              <Route
                path="/content/*"
                element={
                  <StixCoreObjectContentRoot
                    stixCoreObject={securityPlatform}
                  />
                }
              />
              <Route
                path="/analyses"
                element={
                  <SecurityPlatformAnalysis
                    securityPlatform={securityPlatform}
                  />
                }
              />
              <Route
                path="/files"
                element={
                  <FileManager
                    id={securityPlatformId}
                    connectorsImport={connectorsForImport}
                    connectorsExport={connectorsForExport}
                    entity={securityPlatform}
                  />
                }
              />
              <Route
                path="/history"
                element={
                  <StixCoreObjectHistory
                    stixCoreObjectId={securityPlatformId}
                  />
                }
              />
            </Routes>
          </div>
        </>
      ) : (
        <ErrorNotFound />
      )}
    </>
  );
};
const Root = () => {
  const { securityPlatformId } = useParams() as { securityPlatformId: string; };
  const queryRef = useQueryLoading<RootSecurityPlatformQuery>(securityPlatformQuery, {
    id: securityPlatformId,
  });

  return (
    <>
      {queryRef && (
        <Suspense fallback={<Loader variant={LoaderVariant.container} />}>
          <RootSecurityPlatform securityPlatformId={securityPlatformId} queryRef={queryRef} />
        </Suspense>
      )}
    </>
  );
};

export default Root;
