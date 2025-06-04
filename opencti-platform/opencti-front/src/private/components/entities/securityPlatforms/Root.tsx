import React, { useMemo, Suspense, useState } from 'react';
import { Route, Routes, Link, Navigate, useLocation, useParams, useNavigate } from 'react-router-dom';
import { graphql, useSubscription, usePreloadedQuery, PreloadedQuery } from 'react-relay';
import { GraphQLSubscriptionConfig } from 'relay-runtime';
import Box from '@mui/material/Box';
import Tabs from '@mui/material/Tabs';
import Tab from '@mui/material/Tab';
import useQueryLoading from 'src/utils/hooks/useQueryLoading';
import useForceUpdate from '@components/common/bulk/useForceUpdate';
import { propOr } from 'ramda';
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
import { buildViewParamsFromUrlAndStorage, saveViewParameters } from '../../../../utils/ListParameters';
import StixCoreObjectKnowledgeBar from '../../common/stix_core_objects/StixCoreObjectKnowledgeBar';
import { useFormatter } from '../../../../components/i18n';
import Breadcrumbs from '../../../../components/Breadcrumbs';
import { getCurrentTab, getPaddingRight } from '../../../../utils/utils';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNUPDATE } from '../../../../utils/hooks/useGranted';

const subscription = graphql`
  subscription RootSecurityPlatformSubscription($id: ID!) {
    stixDomainObject(id: $id) {
      ... on SecurityPlatform {
        ...SecurityPlatform_securityPlatform
#                ...SecurityPlatformEditionContainer_securityPlatform
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
  const navigate = useNavigate();
  const LOCAL_STORAGE_KEY = `securityPlatform-${securityPlatformId}`;
  const params = buildViewParamsFromUrlAndStorage(
    navigate,
    location,
    LOCAL_STORAGE_KEY,
  );

  const [viewAs, setViewAs] = useState<string>(propOr('knowledge', 'viewAs', params));

  const saveView = () => {
    saveViewParameters(
      navigate,
      location,
      LOCAL_STORAGE_KEY,
      viewAs,
    );
  };

  const handleChangeViewAs = (event: React.ChangeEvent<{ value: string }>) => {
    setViewAs(event.target.value);
    saveView();
  };

  const { t_i18n } = useFormatter();
  useSubscription<RootSecurityPlatformSubscription>(subConfig);

  const {
    securityPlatform,
    connectorsForExport,
    connectorsForImport,
  } = usePreloadedQuery<RootSecurityPlatformQuery>(securityPlatformQuery, queryRef);

  const { forceUpdate } = useForceUpdate();

  const link = `/dashboard/entities/security_platforms/${securityPlatformId}/knowledge`;
  const paddingRight = getPaddingRight(location.pathname, securityPlatformId, '/dashboard/entities/security_platforms', viewAs === 'knowledge');
  return (
    <>
      {securityPlatform ? (
        <>
          <Routes>
            <Route
              path="/knowledge/*"
              element={viewAs === 'knowledge' && (
                <StixCoreObjectKnowledgeBar
                  stixCoreObjectLink={link}
                  availableSections={[
                    'systems',
                    'infrastructures',
                    'indicators',
                    'tools',
                    'attack_patterns',
                  ]}
                  data={securityPlatform}
                />
              )}
            />
          </Routes>
          <div style={{ paddingRight }}>
            <Breadcrumbs elements={[
              { label: t_i18n('Entities') },
              { label: t_i18n('Security Platforms'), link: '/dashboard/entities/security_platforms' },
              { label: securityPlatform.name, current: true },
            ]}
            />
            <StixDomainObjectHeader
              entityType="securityPlatform"
              stixDomainObject={securityPlatform}
              EditComponent={(
                <Security needs={[KNOWLEDGE_KNUPDATE]}>
                  <SecurityPlatformEdition securityPlatformId={securityPlatform.id} />
                </Security>
              )}
              onViewAs={handleChangeViewAs}
              viewAs={viewAs}
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
                    viewAs={viewAs}
                    onViewAs={handleChangeViewAs}
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
