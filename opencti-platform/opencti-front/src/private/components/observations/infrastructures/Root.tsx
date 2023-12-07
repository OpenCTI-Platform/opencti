/* eslint-disable @typescript-eslint/no-explicit-any */
// TODO Remove this when V6
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-nocheck
import React, { useMemo } from 'react';
import { Route, Redirect, useParams, Switch, Link } from 'react-router-dom';
import { graphql, usePreloadedQuery, useSubscription } from 'react-relay';
import { GraphQLSubscriptionConfig } from 'relay-runtime';
import { useLocation } from 'react-router-dom-v5-compat';
import Box from '@mui/material/Box';
import Tabs from '@mui/material/Tabs';
import Tab from '@mui/material/Tab';
import InfrastructureKnowledge from './InfrastructureKnowledge';
import StixDomainObjectHeader from '../../common/stix_domain_objects/StixDomainObjectHeader';
import FileManager from '../../common/files/FileManager';
import InfrastructurePopover from './InfrastructurePopover';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import StixCoreObjectHistory from '../../common/stix_core_objects/StixCoreObjectHistory';
import StixCoreObjectOrStixCoreRelationshipContainers from '../../common/containers/StixCoreObjectOrStixCoreRelationshipContainers';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import { RootInfrastructureSubscription } from './__generated__/RootInfrastructureSubscription.graphql';
import { RootInfrastructureQuery } from './__generated__/RootInfrastructureQuery.graphql';
import Infrastructure from './Infrastructure';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { useFormatter } from '../../../../components/i18n';

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
  const { t } = useFormatter();
  useSubscription(subConfig);
  const data = usePreloadedQuery(infrastructureQuery, queryRef);
  const { infrastructure, connectorsForImport, connectorsForExport } = data;
  return (
    <>
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
          <StixDomainObjectHeader
            entityType="Infrastructure"
            stixDomainObject={infrastructure}
            PopoverComponent={InfrastructurePopover}
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
                label={t('Overview')}
              />
              <Tab
                component={Link}
                to={`/dashboard/observations/infrastructures/${infrastructure.id}/knowledge`}
                value={`/dashboard/observations/infrastructures/${infrastructure.id}/knowledge`}
                label={t('Knowledge')}
              />
              <Tab
                component={Link}
                to={`/dashboard/observations/infrastructures/${infrastructure.id}/analyses`}
                value={`/dashboard/observations/infrastructures/${infrastructure.id}/analyses`}
                label={t('Analyses')}
              />
              <Tab
                component={Link}
                to={`/dashboard/observations/infrastructures/${infrastructure.id}/files`}
                value={`/dashboard/observations/infrastructures/${infrastructure.id}/files`}
                label={t('Data')}
              />
              <Tab
                component={Link}
                to={`/dashboard/observations/infrastructures/${infrastructure.id}/history`}
                value={`/dashboard/observations/infrastructures/${infrastructure.id}/history`}
                label={t('History')}
              />
            </Tabs>
          </Box>
          <Switch>
            <Route
              exact
              path="/dashboard/observations/infrastructures/:infrastructureId"
              render={() => <Infrastructure data={infrastructure} />}
            />
            <Route
              exact
              path="/dashboard/observations/infrastructures/:infrastructureId/knowledge"
              render={() => (
                <Redirect
                  to={`/dashboard/observations/infrastructures/${infrastructureId}/knowledge/overview`}
                />
              )}
            />
            <Route
              path="/dashboard/observations/infrastructures/:infrastructureId/knowledge"
              render={() => (
                <InfrastructureKnowledge infrastructure={infrastructure} />
              )}
            />
            <Route
              exact
              path="/dashboard/observations/infrastructures/:infrastructureId/analyses"
              render={(routeProps) => (
                <StixCoreObjectOrStixCoreRelationshipContainers
                  {...routeProps}
                  stixDomainObjectOrStixCoreRelationship={infrastructure}
                />
              )}
            />
            <Route
              exact
              path="/dashboard/observations/infrastructures/:infrastructureId/files"
              render={(routeProps) => (
                <FileManager
                  {...routeProps}
                  id={infrastructureId}
                  connectorsImport={connectorsForImport}
                  connectorsExport={connectorsForExport}
                  entity={infrastructure}
                />
              )}
            />
            <Route
              exact
              path="/dashboard/observations/infrastructures/:infrastructureId/history"
              render={(routeProps) => (
                <StixCoreObjectHistory
                  {...routeProps}
                  stixCoreObjectId={infrastructureId}
                />
              )}
            />
          </Switch>
        </div>
      ) : (
        <ErrorNotFound />
      )}
    </>
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
