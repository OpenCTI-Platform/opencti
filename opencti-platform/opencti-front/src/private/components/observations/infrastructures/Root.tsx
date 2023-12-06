/* eslint-disable @typescript-eslint/no-explicit-any */
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
import Security from 'src/utils/Security';
import { KNOWLEDGE_KNUPDATE } from 'src/utils/hooks/useGranted';
import CreateRelationshipButtonComponent from '@components/common/menus/RelateComponent';
import RelateComponentContextProvider from '@components/common/menus/RelateComponentProvider';
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
import InfrastructureEdition from './InfrastructureEdition';

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
      standard_id
      name
      aliases
      x_opencti_graph_data
      created_at
      updated_at
      ...Infrastructure_infrastructure
      ...InfrastructureKnowledge_infrastructure
      ...FileImportViewer_entity
      ...FileExportViewer_entity
      ...FileExternalReferencesViewer_entity
      ...WorkbenchFileViewer_entity
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
  const subConfig = useMemo<
  GraphQLSubscriptionConfig<RootInfrastructureSubscription>
  >(
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
  return (
    <RelateComponentContextProvider>
      {infrastructure ? (
        <div
          style={{
            paddingRight: location.pathname.includes(
              `/dashboard/observations/infrastructures/${infrastructure.id}/knowledge`,
            )
              ? 200
              : 0,
          }}
        >
          <Breadcrumbs variant="object" elements={[
            { label: t_i18n('Observations') },
            { label: t_i18n('Infrastructures'), link: '/dashboard/observations/infrastructures' },
            { label: infrastructure.name, current: true },
          ]}
          />
          <StixDomainObjectHeader
            entityType="Infrastructure"
            stixDomainObject={infrastructure}
            EditComponent={<Security needs={[KNOWLEDGE_KNUPDATE]}>
              <InfrastructureEdition infrastructureId={infrastructure.id} />
            </Security>}
            RelateComponent={<CreateRelationshipButtonComponent
              id={infrastructure.id}
              defaultStartTime={infrastructure.created_at}
              defaultStopTime={infrastructure.updated_at}
                             />}
            enableQuickSubscription={true}
          />
          <Box
            sx={{ borderBottom: 1, borderColor: 'divider', marginBottom: 4 }}
          >
            <Tabs
              value={
                location.pathname.includes(
                  `/dashboard/observations/infrastructures/${infrastructure.id}/knowledge`,
                )
                  ? `/dashboard/observations/infrastructures/${infrastructure.id}/knowledge`
                  : location.pathname
              }
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
              element={<Navigate
                to={`/dashboard/observations/infrastructures/${infrastructureId}/knowledge/overview`}
                       />}
            />
            <Route
              path="/knowledge/*"
              element={<InfrastructureKnowledge infrastructure={infrastructure} />}
            />
            <Route
              path="/analyses/*"
              element={
                <StixCoreObjectOrStixCoreRelationshipContainers
                  stixDomainObjectOrStixCoreRelationship={infrastructure}
                />}
            />
            <Route
              path="/files"
              element={
                <FileManager
                  id={infrastructureId}
                  connectorsImport={connectorsForImport}
                  connectorsExport={connectorsForExport}
                  entity={infrastructure}
                />}
            />
            <Route
              path="/history"
              element={
                <StixCoreObjectHistory
                  stixCoreObjectId={infrastructureId}
                />}
            />
          </Routes>
        </div>
      ) : (
        <ErrorNotFound />
      )}
    </RelateComponentContextProvider>
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
