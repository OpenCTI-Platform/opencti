// TODO Remove this when V6
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-nocheck
import React, { useMemo } from 'react';
import { Route, useParams, Routes, Link, useLocation, Navigate } from 'react-router-dom';
import { graphql, usePreloadedQuery, useSubscription } from 'react-relay';
import { GraphQLSubscriptionConfig } from 'relay-runtime';
import Box from '@mui/material/Box';
import Tabs from '@mui/material/Tabs';
import Tab from '@mui/material/Tab';
import StixCoreObjectContentRoot from '@components/common/stix_core_objects/StixCoreObjectContentRoot';
import useForceUpdate from '@components/common/bulk/useForceUpdate';
import StixCoreRelationshipCreationFromEntityHeader from '@components/common/stix_core_relationships/StixCoreRelationshipCreationFromEntityHeader';
import CreateRelationshipContextProvider from '@components/common/stix_core_relationships/CreateRelationshipContextProvider';
import InfrastructureKnowledge from './InfrastructureKnowledge';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';
import FileManager from '../../common/files/FileManager';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import StixCoreObjectHistory from '../../common/stix_core_objects/StixCoreObjectHistory';
import StixCoreObjectOrStixCoreRelationshipContainers from '../../common/containers/StixCoreObjectOrStixCoreRelationshipContainers';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import { RootInfrastructureSubscription } from './__generated__/RootInfrastructureSubscription.graphql';
import { RootInfrastructureQuery } from './__generated__/RootInfrastructureQuery.graphql';
import Infrastructure from './Infrastructure';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { useFormatter } from '../../../../components/i18n';
import Breadcrumbs from '../../../../components/Breadcrumbs';
import { getCurrentTab } from '../../../../utils/utils';
import Security from '../../../../utils/Security';
import { KNOWLEDGE_KNUPDATE, KNOWLEDGE_KNUPDATE_KNDELETE } from '../../../../utils/hooks/useGranted';
import InfrastructureEdition from './InfrastructureEdition';
import InfrastructureDeletion from './InfrastructureDeletion';

const subscription = graphql`
  subscription RootInfrastructureSubscription($id: ID!) {
    stixDomainObject(id: $id) {
      ... on Infrastructure {
        ...Infrastructure_infrastructure
        ...InfrastructureEditionOverview_infrastructure
      }
      ...FileImportViewer_entity
      ...FileExportViewer_entity
      ...FileExternalReferencesViewer_entity
      ...WorkbenchFileViewer_entity
    }
  }
`;

const infrastructureQuery = graphql`
  query RootInfrastructureQuery($id: String!) {
    infrastructure(id: $id) {
      id
      draftVersion {
        draft_id
        draft_operation
      }
      standard_id
      name
      aliases
      x_opencti_graph_data
      ...StixCoreRelationshipCreationFromEntityHeader_stixCoreObject
      ...Infrastructure_infrastructure
      ...InfrastructureKnowledge_infrastructure
      ...FileImportViewer_entity
      ...FileExportViewer_entity
      ...FileExternalReferencesViewer_entity
      ...WorkbenchFileViewer_entity
      ...StixCoreObjectContent_stixCoreObject
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

const RootInfrastructureComponent = ({ queryRef, infrastructureId }) => {
  const subConfig = useMemo<GraphQLSubscriptionConfig<RootInfrastructureSubscription>>(
    () => ({
      subscription,
      variables: { id: infrastructureId },
    }),
    [infrastructureId],
  );
  const location = useLocation();
  const { t_i18n } = useFormatter();
  useSubscription(subConfig);
  const data = usePreloadedQuery(infrastructureQuery, queryRef);
  const { infrastructure, connectorsForImport, connectorsForExport } = data;
  const { forceUpdate } = useForceUpdate();
  const paddingRightValue = () => {
    if (location.pathname.includes(`/dashboard/observations/infrastructures/${infrastructure.id}/knowledge`)) return 200;
    if (location.pathname.includes(`/dashboard/observations/infrastructures/${infrastructure.id}/content`)) return 350;
    if (location.pathname.includes(`/dashboard/observations/infrastructures/${infrastructure.id}/content/mapping`)) return 0;
    return 0;
  };
  return (
    <CreateRelationshipContextProvider>
      {infrastructure ? (
        <div
          style={{ paddingRight: paddingRightValue() }}
          data-testid="infrastructure-details-page"
        >
          <Breadcrumbs elements={[
            { label: t_i18n('Observations') },
            { label: t_i18n('Infrastructures'), link: '/dashboard/observations/infrastructures' },
            { label: infrastructure.name, current: true },
          ]}
          />
          <StixDomainObjectHeader
            entityType="Infrastructure"
            stixDomainObject={infrastructure}
            EditComponent={(
              <Security needs={[KNOWLEDGE_KNUPDATE]}>
                <InfrastructureEdition infrastructureId={infrastructure.id} />
              </Security>
            )}
            RelateComponent={(
              <Security needs={[KNOWLEDGE_KNUPDATE]}>
                <StixCoreRelationshipCreationFromEntityHeader
                  data={infrastructure}
                />
              </Security>
            )}
            DeleteComponent={({ isOpen, onClose }: { isOpen: boolean; onClose: () => void }) => (
              <Security needs={[KNOWLEDGE_KNUPDATE_KNDELETE]}>
                <InfrastructureDeletion id={infrastructure.id} isOpen={isOpen} handleClose={onClose} />
              </Security>
            )}
            enableQuickSubscription={true}
            redirectToContent={true}
          />
          <Box
            sx={{ borderBottom: 1, borderColor: 'divider', marginBottom: 3 }}
          >
            <Tabs
              value={getCurrentTab(location.pathname, infrastructure.id, '/dashboard/observations/infrastructures')}
            >
              <Tab
                component={Link}
                to={`/dashboard/observations/infrastructures/${infrastructure.id}`}
                value={`/dashboard/observations/infrastructures/${infrastructure.id}`}
                label={t_i18n('Overview')}
              />
              <Tab
                component={Link}
                to={`/dashboard/observations/infrastructures/${infrastructure.id}/knowledge/overview`}
                value={`/dashboard/observations/infrastructures/${infrastructure.id}/knowledge`}
                label={t_i18n('Knowledge')}
              />
              <Tab
                component={Link}
                to={`/dashboard/observations/infrastructures/${infrastructure.id}/content`}
                value={`/dashboard/observations/infrastructures/${infrastructure.id}/content`}
                label={t_i18n('Content')}
              />
              <Tab
                component={Link}
                to={`/dashboard/observations/infrastructures/${infrastructure.id}/analyses`}
                value={`/dashboard/observations/infrastructures/${infrastructure.id}/analyses`}
                label={t_i18n('Analyses')}
              />
              <Tab
                component={Link}
                to={`/dashboard/observations/infrastructures/${infrastructure.id}/files`}
                value={`/dashboard/observations/infrastructures/${infrastructure.id}/files`}
                label={t_i18n('Data')}
              />
              <Tab
                component={Link}
                to={`/dashboard/observations/infrastructures/${infrastructure.id}/history`}
                value={`/dashboard/observations/infrastructures/${infrastructure.id}/history`}
                label={t_i18n('History')}
              />
            </Tabs>
          </Box>
          <Routes>
            <Route
              path="/"
              element={<Infrastructure data={infrastructure} />}
            />
            <Route
              path="/knowledge"
              element={(
                <Navigate
                  replace={true}
                  to={`/dashboard/observations/infrastructures/${infrastructureId}/knowledge/overview`}
                />
              )}
            />
            <Route
              path="/knowledge/*"
              element={(
                <div key={forceUpdate}>
                  <InfrastructureKnowledge infrastructure={infrastructure} />
                </div>
              )}
            />
            <Route
              path="/content/*"
              element={(
                <StixCoreObjectContentRoot
                  stixCoreObject={infrastructure}
                />
              )}
            />
            <Route
              path="/analyses/*"
              element={(
                <StixCoreObjectOrStixCoreRelationshipContainers
                  stixDomainObjectOrStixCoreRelationship={infrastructure}
                />
              )}
            />
            <Route
              path="/files"
              element={(
                <FileManager
                  id={infrastructureId}
                  connectorsImport={connectorsForImport}
                  connectorsExport={connectorsForExport}
                  entity={infrastructure}
                />
              )}
            />
            <Route
              path="/history"
              element={(
                <StixCoreObjectHistory
                  stixCoreObjectId={infrastructureId}
                />
              )}
            />
          </Routes>
        </div>
      ) : (
        <ErrorNotFound />
      )}
    </CreateRelationshipContextProvider>
  );
};

const RootInfrastructure = () => {
  const { infrastructureId } = useParams() as { infrastructureId: string };
  const queryRef = useQueryLoading<RootInfrastructureQuery>(
    infrastructureQuery,
    { id: infrastructureId },
  );
  return (
    <>
      {queryRef && (
        <React.Suspense fallback={<Loader variant={LoaderVariant.container} />}>
          <RootInfrastructureComponent
            queryRef={queryRef}
            infrastructureId={infrastructureId}
          />
        </React.Suspense>
      )}
    </>
  );
};

export default RootInfrastructure;
