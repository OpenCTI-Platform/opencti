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
import StixCoreObjectContentRoot from '../../common/stix_core_objects/StixCoreObjectContentRoot';
import SecurityPlatform from './SecurityPlatform';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';
import FileManager from '../../common/files/FileManager';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import StixCoreObjectHistory from '../../common/stix_core_objects/StixCoreObjectHistory';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import { buildViewParamsFromUrlAndStorage, saveViewParameters } from '../../../../utils/ListParameters';
import StixCoreObjectKnowledgeBar from '../../common/stix_core_objects/StixCoreObjectKnowledgeBar';
import EntityStixSightingRelationships from '../../events/stix_sighting_relationships/EntityStixSightingRelationships';
import { useFormatter } from '../../../../components/i18n';
import Breadcrumbs from '../../../../components/Breadcrumbs';
import { getCurrentTab, getPaddingRight } from '../../../../utils/utils';

const subscription = graphql`
    subscription SecurityPlatformSubscription($id: ID!) {
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
    query RootSecurityPlatformnQuery($id: String!) {
        securityPlatform(id: $id) {
            id
            draftVersion {
                draft_id
                draft_operation
            }
            entity_type
            name
            x_opencti_aliases
            security_platform_type
            ...StixCoreObjectKnowledgeBar_stixCoreObject
            ...SecurityPlatform_securityPlatform
#            ...SecurityPlatformKnowledge_securityPlatform
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

  const link = `/dashboard/entities/securityPlatform/${securityPlatformId}/knowledge`;
  const paddingRight = getPaddingRight(location.pathname, securityPlatformId, '/dashboard/entities/securityPlatform', viewAs === 'knowledge');
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
                    'sectors',
                    'organizations',
                    'individuals',
                    'locations',
                    'used_tools',
                    'threats',
                    'threat_actors',
                    'intrusion_sets',
                    'campaigns',
                    'incidents',
                    'malwares',
                    'attack_patterns',
                    'tools',
                    'vulnerabilities',
                    'observables',
                  ]}
                  data={securityPlatform}
                />
              )}
            />
          </Routes>
          <div style={{ paddingRight }}>
            <Breadcrumbs elements={[
              { label: t_i18n('Entities') },
              { label: t_i18n('Security Platform'), link: '/dashboard/entities/securityPlatform' },
              { label: securityPlatform.name, current: true },
            ]}
            />
            <StixDomainObjectHeader
              entityType="securityPlatform"
              disableSharing={true}
              stixDomainObject={securityPlatform}
              isOpenctiAlias={true}
              enableQuickSubscription={true}
              // EditComponent={(
              //   <Security needs={[KNOWLEDGE_KNUPDATE]}>
              //     <SecurityPlatformEdition securityPlatformId={securityPlatform.id} />
              //   </Security>
              // )}
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
                value={getCurrentTab(location.pathname, securityPlatform.id, '/dashboard/entities/securityPlatforms')}
              >
                <Tab
                  component={Link}
                  to={`/dashboard/entities/securityPlatform/${securityPlatform.id}`}
                  value={`/dashboard/entities/securityPlatform/${securityPlatform.id}`}
                  label={t_i18n('Overview')}
                />
                <Tab
                  component={Link}
                  to={`/dashboard/entities/securityPlatform/${securityPlatform.id}/knowledge/overview`}
                  value={`/dashboard/entities/securityPlatform/${securityPlatform.id}/knowledge`}
                  label={t_i18n('Knowledge')}
                />
                <Tab
                  component={Link}
                  to={`/dashboard/entities/securityPlatform/${securityPlatform.id}/content`}
                  value={`/dashboard/entities/securityPlatform/${securityPlatform.id}/content`}
                  label={t_i18n('Content')}
                />
                <Tab
                  component={Link}
                  to={`/dashboard/entities/securityPlatform/${securityPlatform.id}/analyses`}
                  value={`/dashboard/entities/securityPlatform/${securityPlatform.id}/analyses`}
                  label={t_i18n('Analyses')}
                />
                <Tab
                  component={Link}
                  to={`/dashboard/entities/securityPlatform/${securityPlatform.id}/sightings`}
                  value={`/dashboard/entities/securityPlatform/${securityPlatform.id}/sightings`}
                  label={t_i18n('Sightings')}
                />
                <Tab
                  component={Link}
                  to={`/dashboard/entities/securityPlatform/${securityPlatform.id}/files`}
                  value={`/dashboard/entities/securityPlatform/${securityPlatform.id}/files`}
                  label={t_i18n('Data')}
                />
                <Tab
                  component={Link}
                  to={`/dashboard/entities/securityPlatform/${securityPlatform.id}/history`}
                  value={`/dashboard/entities/securityPlatform/${securityPlatform.id}/history`}
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
                    viewAs={viewAs}
                  />
                }
              />
              <Route
                path="/knowledge"
                element={
                  <Navigate
                    replace={true}
                    to={`/dashboard/entities/securityPlatform/${securityPlatformId}/knowledge/overview`}
                  />
                }
              />
              <Route
                path="/knowledge/*"
                element={
                  <div key={forceUpdate}>
                    {/* <securityPlatformKnowledge */}
                    {/*  securityPlatformData={securityPlatform} */}
                    {/*  viewAs={viewAs} */}
                    {/* /> */}
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
              {/* <Route */}
              {/*  path="/analyses" */}
              {/*  element={ */}
              {/*    <SecurityPlatformAnalysis */}
              {/*      organization={securityPlatform} */}
              {/*      viewAs={viewAs} */}
              {/*      onViewAs={handleChangeViewAs} */}
              {/*    /> */}
              {/*  } */}
              {/* /> */}
              <Route
                path="/sightings"
                element={
                  <EntityStixSightingRelationships
                    entityId={securityPlatform.id}
                    entityLink={link}
                    noPadding={true}
                    isTo={true}
                    stixCoreObjectTypes={[
                      'Region',
                      'Country',
                      'City',
                      'Position',
                      'Sector',
                      'Organization',
                      'Individual',
                      'System',
                    ]}
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
