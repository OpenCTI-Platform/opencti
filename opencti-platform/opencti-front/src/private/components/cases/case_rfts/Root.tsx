/* eslint-disable @typescript-eslint/no-explicit-any */
// TODO Remove this when V6
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-nocheck
import React, { useMemo } from 'react';
import { Link, Redirect, Route, Switch, useParams } from 'react-router-dom';
import { graphql, usePreloadedQuery, useSubscription } from 'react-relay';
import { GraphQLSubscriptionConfig } from 'relay-runtime';
import Box from '@mui/material/Box';
import Tabs from '@mui/material/Tabs';
import Tab from '@mui/material/Tab';
import { useLocation } from 'react-router-dom-v5-compat';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import ContainerHeader from '../../common/containers/ContainerHeader';
import StixDomainObjectContent from '../../common/stix_domain_objects/StixDomainObjectContent';
import StixCoreObjectFilesAndHistory from '../../common/stix_core_objects/StixCoreObjectFilesAndHistory';
import StixCoreObjectHistory from '../../common/stix_core_objects/StixCoreObjectHistory';
import CaseRft from './CaseRft';
import CaseRftPopover from './CaseRftPopover';
import CaseRftKnowledge from './CaseRftKnowledge';
import ContainerStixCyberObservables from '../../common/containers/ContainerStixCyberObservables';
import ContainerStixDomainObjects from '../../common/containers/ContainerStixDomainObjects';
import { RootCaseRftCaseQuery } from './__generated__/RootCaseRftCaseQuery.graphql';
import { useFormatter } from '../../../../components/i18n';

const subscription = graphql`
  subscription RootCaseRftCaseSubscription($id: ID!) {
    stixDomainObject(id: $id) {
      ... on Case {
        ...CaseUtils_case
      }
      ...FileImportViewer_entity
      ...FileExportViewer_entity
      ...FileExternalReferencesViewer_entity
      ...WorkbenchFileViewer_entity
    }
  }
`;

const caseRftQuery = graphql`
  query RootCaseRftCaseQuery($id: String!) {
    caseRft(id: $id) {
      id
      standard_id
      name
      x_opencti_graph_data
      ...CaseUtils_case
      ...CaseRftKnowledge_case
      ...FileImportViewer_entity
      ...FileExportViewer_entity
      ...FileExternalReferencesViewer_entity
      ...WorkbenchFileViewer_entity
      ...StixDomainObjectContent_stixDomainObject
      ...ContainerHeader_container
      ...ContainerStixDomainObjects_container
      ...ContainerStixCyberObservables_container
    }
    connectorsForExport {
      ...StixCoreObjectFilesAndHistory_connectorsExport
    }
    connectorsForImport {
      ...StixCoreObjectFilesAndHistory_connectorsImport
    }
  }
`;

const RootCaseRftComponent = ({ queryRef, caseId }) => {
  const subConfig = useMemo<
  GraphQLSubscriptionConfig<RootCaseRftCaseSubscription>
  >(
    () => ({
      subscription,
      variables: { id: caseId },
    }),
    [caseId],
  );
  const location = useLocation();
  const { t } = useFormatter();
  useSubscription(subConfig);
  const {
    caseRft: caseData,
    connectorsForExport,
    connectorsForImport,
  } = usePreloadedQuery<RootCaseRftCaseQuery>(caseRftQuery, queryRef);
  let paddingRight = 0;
  if (caseData) {
    if (
      location.pathname.includes(
        `/dashboard/cases/rfts/${caseData.id}/entities`,
      )
      || location.pathname.includes(
        `/dashboard/cases/rfts/${caseData.id}/observables`,
      )
    ) {
      paddingRight = 260;
    }
    if (
      location.pathname.includes(`/dashboard/cases/rfts/${caseData.id}/content`)
    ) {
      paddingRight = 350;
    }
  }
  return (
    <>
      {caseData ? (
        <div style={{ paddingRight, position: 'relative' }}>
          <ContainerHeader
            container={caseData}
            PopoverComponent={<CaseRftPopover id={caseData.id} />}
            enableQuickSubscription={true}
            enableQuickExport={true}
          />
          <Box
            sx={{
              borderBottom: 1,
              borderColor: 'divider',
              marginBottom: 4,
            }}
          >
            <Tabs
              value={
                location.pathname.includes(
                  `/dashboard/cases/rfts/${caseData.id}/knowledge`,
                )
                  ? `/dashboard/cases/rfts/${caseData.id}/knowledge`
                  : location.pathname
              }
            >
              <Tab
                component={Link}
                to={`/dashboard/cases/rfts/${caseData.id}`}
                value={`/dashboard/cases/rfts/${caseData.id}`}
                label={t('Overview')}
              />
              <Tab
                component={Link}
                to={`/dashboard/cases/rfts/${caseData.id}/knowledge`}
                value={`/dashboard/cases/rfts/${caseData.id}/knowledge`}
                label={t('Knowledge')}
              />
              <Tab
                component={Link}
                to={`/dashboard/cases/rfts/${caseData.id}/content`}
                value={`/dashboard/cases/rfts/${caseData.id}/content`}
                label={t('Content')}
              />
              <Tab
                component={Link}
                to={`/dashboard/cases/rfts/${caseData.id}/entities`}
                value={`/dashboard/cases/rfts/${caseData.id}/entities`}
                label={t('Entities')}
              />
              <Tab
                component={Link}
                to={`/dashboard/cases/rfts/${caseData.id}/observables`}
                value={`/dashboard/cases/rfts/${caseData.id}/observables`}
                label={t('Observables')}
              />
              <Tab
                component={Link}
                to={`/dashboard/cases/rfts/${caseData.id}/files`}
                value={`/dashboard/cases/rfts/${caseData.id}/files`}
                label={t('Data')}
              />
            </Tabs>
          </Box>
          <Switch>
            <Route
              exact
              path="/dashboard/cases/rfts/:caseId"
              render={() => <CaseRft data={caseData} />}
            />
            <Route
              exact
              path="/dashboard/cases/rfts/:caseId/entities"
              render={(routeProps) => (
                <ContainerStixDomainObjects
                  {...routeProps}
                  container={caseData}
                />
              )}
            />
            <Route
              exact
              path="/dashboard/cases/rfts/:caseId/observables"
              render={(routeProps) => (
                <ContainerStixCyberObservables
                  {...routeProps}
                  container={caseData}
                />
              )}
            />
            <Route
              exact
              path="/dashboard/cases/rfts/:caseId/knowledge"
              render={() => (
                <Redirect
                  to={`/dashboard/cases/rfts/${caseId}/knowledge/graph`}
                />
              )}
            />
            <Route
              exact
              path="/dashboard/cases/rfts/:caseId/content"
              render={(routeProps) => (
                <StixDomainObjectContent
                  {...routeProps}
                  stixDomainObject={caseData}
                />
              )}
            />
            <Route
              exact
              path="/dashboard/cases/rfts/:caseId/knowledge/:mode"
              render={(routeProps) => (
                <CaseRftKnowledge {...routeProps} caseData={caseData} />
              )}
            />
            <Route
              exact
              path="/dashboard/cases/rfts/:caseId/files"
              render={(routeProps) => (
                <StixCoreObjectFilesAndHistory
                  {...routeProps}
                  id={caseId}
                  connectorsExport={connectorsForExport}
                  connectorsImport={connectorsForImport}
                  entity={caseData}
                  withoutRelations={true}
                  bypassEntityId={true}
                />
              )}
            />
            <Route
              exact
              path="/dashboard/cases/rfts/:caseId/history"
              render={(routeProps: any) => (
                <StixCoreObjectHistory
                  {...routeProps}
                  stixCoreObjectId={caseId}
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

const Root = () => {
  const { caseId } = useParams() as { caseId: string };
  const queryRef = useQueryLoading<RootCaseRftCaseQuery>(caseRftQuery, {
    id: caseId,
  });
  return (
    <>
      {queryRef && (
        <React.Suspense fallback={<Loader variant={LoaderVariant.container} />}>
          <RootCaseRftComponent queryRef={queryRef} caseId={caseId} />
        </React.Suspense>
      )}
    </>
  );
};

export default Root;
