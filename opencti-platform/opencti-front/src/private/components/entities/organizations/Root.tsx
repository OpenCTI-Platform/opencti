import React, { useMemo, Suspense, useState } from 'react';
import { Route, Routes, Link, Navigate, useLocation, useParams, useNavigate } from 'react-router-dom';
import { graphql, useSubscription, usePreloadedQuery, PreloadedQuery } from 'react-relay';
import { GraphQLSubscriptionConfig } from 'relay-runtime';
import Box from '@mui/material/Box';
import Tabs from '@mui/material/Tabs';
import Tab from '@mui/material/Tab';
import { RootOrganizationQuery } from '@components/entities/organizations/__generated__/RootOrganizationQuery.graphql';
import useQueryLoading from 'src/utils/hooks/useQueryLoading';
import useForceUpdate from '@components/common/bulk/useForceUpdate';
import { RootOrganizationSubscription } from '@components/entities/organizations/__generated__/RootOrganizationSubscription.graphql';
import { propOr } from 'ramda';
import StixCoreRelationshipCreationFromEntityHeader from '@components/common/stix_core_relationships/StixCoreRelationshipCreationFromEntityHeader';
import CreateRelationshipContextProvider from '@components/common/stix_core_relationships/CreateRelationshipContextProvider';
import StixCoreObjectContentRoot from '../../common/stix_core_objects/StixCoreObjectContentRoot';
import Organization from './Organization';
import OrganizationKnowledge from './OrganizationKnowledge';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';
import FileManager from '../../common/files/FileManager';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import StixCoreObjectHistory from '../../common/stix_core_objects/StixCoreObjectHistory';
import OrganizationAnalysis from './OrganizationAnalysis';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import { buildViewParamsFromUrlAndStorage, saveViewParameters } from '../../../../utils/ListParameters';
import StixCoreObjectKnowledgeBar from '../../common/stix_core_objects/StixCoreObjectKnowledgeBar';
import EntityStixSightingRelationships from '../../events/stix_sighting_relationships/EntityStixSightingRelationships';
import { useFormatter } from '../../../../components/i18n';
import Breadcrumbs from '../../../../components/Breadcrumbs';
import { getCurrentTab, getPaddingRight } from '../../../../utils/utils';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNUPDATE, KNOWLEDGE_KNUPDATE_KNDELETE } from '../../../../utils/hooks/useGranted';
import OrganizationEdition from './OrganizationEdition';
import OrganizationDeletion from './OrganizationDeletion';

const subscription = graphql`
  subscription RootOrganizationSubscription($id: ID!) {
    stixDomainObject(id: $id) {
      ... on Organization {
        ...Organization_organization
        ...OrganizationEditionOverview_organization
      }
      ...FileImportViewer_entity
      ...FileExportViewer_entity
      ...FileExternalReferencesViewer_entity
      ...WorkbenchFileViewer_entity
      ...PictureManagementViewer_entity
    }
  }
`;

const organizationQuery = graphql`
  query RootOrganizationQuery($id: String!) {
    organization(id: $id) {
      id
      draftVersion {
        draft_id
        draft_operation
      }
      entity_type
      name
      x_opencti_aliases
      currentUserAccessRight
      authorized_members {
        id
        member_id
        name
        entity_type
        access_right
        groups_restriction {
          id
          name
        }
      }
      ...StixCoreRelationshipCreationFromEntityHeader_stixCoreObject
      ...StixCoreObjectKnowledgeBar_stixCoreObject
      ...Organization_organization
      ...OrganizationKnowledge_organization
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

type RootOrganizationProps = {
  organizationId: string;
  queryRef: PreloadedQuery<RootOrganizationQuery>;
};

const RootOrganization = ({ organizationId, queryRef }: RootOrganizationProps) => {
  const subConfig = useMemo<GraphQLSubscriptionConfig<RootOrganizationSubscription>>(() => ({
    subscription,
    variables: { id: organizationId },
  }), [organizationId]);
  const location = useLocation();
  const navigate = useNavigate();
  const LOCAL_STORAGE_KEY = `organization-${organizationId}`;
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
  useSubscription<RootOrganizationSubscription>(subConfig);

  const {
    organization,
    connectorsForExport,
    connectorsForImport,
  } = usePreloadedQuery<RootOrganizationQuery>(organizationQuery, queryRef);

  const { forceUpdate } = useForceUpdate();

  const link = `/dashboard/entities/organizations/${organizationId}/knowledge`;
  const paddingRight = getPaddingRight(location.pathname, organizationId, '/dashboard/entities/organizations', viewAs === 'knowledge');
  return (
    <CreateRelationshipContextProvider>
      {organization ? (
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
                  data={organization}
                />
              )}
            />
          </Routes>
          <div style={{ paddingRight }}>
            <Breadcrumbs elements={[
              { label: t_i18n('Entities') },
              { label: t_i18n('Organizations'), link: '/dashboard/entities/organizations' },
              { label: organization.name, current: true },
            ]}
            />
            <StixDomainObjectHeader
              entityType="Organization"
              disableSharing={true}
              stixDomainObject={organization}
              isOpenctiAlias={true}
              enableQuickSubscription={true}
              enableAuthorizedMembers={true}
              EditComponent={(
                <Security needs={[KNOWLEDGE_KNUPDATE]}>
                  <OrganizationEdition organizationId={organization.id} />
                </Security>
              )}
              RelateComponent={(
                <Security needs={[KNOWLEDGE_KNUPDATE]}>
                  <StixCoreRelationshipCreationFromEntityHeader
                    data={organization}
                  />
                </Security>
              )}
              DeleteComponent={({ isOpen, onClose }: { isOpen: boolean, onClose: () => void }) => (
                <Security needs={[KNOWLEDGE_KNUPDATE_KNDELETE]}>
                  <OrganizationDeletion id={organization.id} isOpen={isOpen} handleClose={onClose} />
                </Security>
              )}
              onViewAs={handleChangeViewAs}
              viewAs={viewAs}
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
                value={getCurrentTab(location.pathname, organization.id, '/dashboard/entities/organizations')}
              >
                <Tab
                  component={Link}
                  to={`/dashboard/entities/organizations/${organization.id}`}
                  value={`/dashboard/entities/organizations/${organization.id}`}
                  label={t_i18n('Overview')}
                />
                <Tab
                  component={Link}
                  to={`/dashboard/entities/organizations/${organization.id}/knowledge/overview`}
                  value={`/dashboard/entities/organizations/${organization.id}/knowledge`}
                  label={t_i18n('Knowledge')}
                />
                <Tab
                  component={Link}
                  to={`/dashboard/entities/organizations/${organization.id}/content`}
                  value={`/dashboard/entities/organizations/${organization.id}/content`}
                  label={t_i18n('Content')}
                />
                <Tab
                  component={Link}
                  to={`/dashboard/entities/organizations/${organization.id}/analyses`}
                  value={`/dashboard/entities/organizations/${organization.id}/analyses`}
                  label={t_i18n('Analyses')}
                />
                <Tab
                  component={Link}
                  to={`/dashboard/entities/organizations/${organization.id}/sightings`}
                  value={`/dashboard/entities/organizations/${organization.id}/sightings`}
                  label={t_i18n('Sightings')}
                />
                <Tab
                  component={Link}
                  to={`/dashboard/entities/organizations/${organization.id}/files`}
                  value={`/dashboard/entities/organizations/${organization.id}/files`}
                  label={t_i18n('Data')}
                />
                <Tab
                  component={Link}
                  to={`/dashboard/entities/organizations/${organization.id}/history`}
                  value={`/dashboard/entities/organizations/${organization.id}/history`}
                  label={t_i18n('History')}
                />
              </Tabs>
            </Box>
            <Routes>
              <Route
                path="/"
                element={
                  <Organization
                    organizationData={organization}
                    viewAs={viewAs}
                  />
                }
              />
              <Route
                path="/knowledge"
                element={
                  <Navigate
                    replace={true}
                    to={`/dashboard/entities/organizations/${organizationId}/knowledge/overview`}
                  />
                }
              />
              <Route
                path="/knowledge/*"
                element={
                  <div key={forceUpdate}>
                    <OrganizationKnowledge
                      organizationData={organization}
                      viewAs={viewAs}
                    />
                  </div>
                }
              />
              <Route
                path="/content/*"
                element={
                  <StixCoreObjectContentRoot
                    stixCoreObject={organization}
                  />
                }
              />
              <Route
                path="/analyses"
                element={
                  <OrganizationAnalysis
                    organization={organization}
                    viewAs={viewAs}
                    onViewAs={handleChangeViewAs}
                  />
                }
              />
              <Route
                path="/sightings"
                element={
                  <EntityStixSightingRelationships
                    entityId={organization.id}
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
                    id={organizationId}
                    connectorsImport={connectorsForImport}
                    connectorsExport={connectorsForExport}
                    entity={organization}
                  />
                }
              />
              <Route
                path="/history"
                element={
                  <StixCoreObjectHistory
                    stixCoreObjectId={organizationId}
                  />
                }
              />
            </Routes>
          </div>
        </>
      ) : (
        <ErrorNotFound />
      )}
    </CreateRelationshipContextProvider>
  );
};
const Root = () => {
  const { organizationId } = useParams() as { organizationId: string; };
  const queryRef = useQueryLoading<RootOrganizationQuery>(organizationQuery, {
    id: organizationId,
  });

  return (
    <>
      {queryRef && (
        <Suspense fallback={<Loader variant={LoaderVariant.container} />}>
          <RootOrganization organizationId={organizationId} queryRef={queryRef} />
        </Suspense>
      )}
    </>
  );
};

export default Root;
