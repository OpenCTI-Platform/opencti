/* eslint-disable @typescript-eslint/no-explicit-any */
// TODO Remove this when V6
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-nocheck
import React, { useMemo } from 'react';
import { graphql, usePreloadedQuery, useSubscription } from 'react-relay';
import { Link, Redirect, Route, Switch, useParams } from 'react-router-dom';
import { GraphQLSubscriptionConfig } from 'relay-runtime';
import Box from '@mui/material/Box';
import Tabs from '@mui/material/Tabs';
import Tab from '@mui/material/Tab';
import { useLocation } from 'react-router-dom-v5-compat';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import ContainerHeader from '../../common/containers/ContainerHeader';
import ContainerStixCyberObservables from '../../common/containers/ContainerStixCyberObservables';
import ContainerStixDomainObjects from '../../common/containers/ContainerStixDomainObjects';
import StixCoreObjectFilesAndHistory from '../../common/stix_core_objects/StixCoreObjectFilesAndHistory';
import StixDomainObjectContent from '../../common/stix_domain_objects/StixDomainObjectContent';
import { RootIncidentCaseQuery } from './__generated__/RootIncidentCaseQuery.graphql';
import CaseIncident from './CaseIncident';
import CaseIncidentPopover from './CaseIncidentPopover';
import IncidentKnowledge from './IncidentKnowledge';
import { RootIncidentQuery } from '../../events/incidents/__generated__/RootIncidentQuery.graphql';
import { RootIncidentSubscription } from '../../events/incidents/__generated__/RootIncidentSubscription.graphql';
import { useFormatter } from '../../../../components/i18n';

const subscription = graphql`
  subscription RootIncidentCaseSubscription($id: ID!) {
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

const caseIncidentQuery = graphql`
  query RootIncidentCaseQuery($id: String!) {
    caseIncident(id: $id) {
      id
      standard_id
      entity_type
      name
      ...CaseUtils_case
      ...IncidentKnowledge_case
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

const RootCaseIncidentComponent = ({ queryRef, caseId }) => {
  const subConfig = useMemo<
  GraphQLSubscriptionConfig<RootIncidentSubscription>
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
    caseIncident: caseData,
    connectorsForExport,
    connectorsForImport,
  } = usePreloadedQuery<RootIncidentCaseQuery>(caseIncidentQuery, queryRef);
  let paddingRight = 0;
  if (caseData) {
    if (
      location.pathname.includes(
        `/dashboard/cases/incidents/${caseData.id}/entities`,
      )
      || location.pathname.includes(
        `/dashboard/cases/incidents/${caseData.id}/observables`,
      )
    ) {
      paddingRight = 260;
    }
    if (
      location.pathname.includes(
        `/dashboard/cases/incidents/${caseData.id}/content`,
      )
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
            PopoverComponent={<CaseIncidentPopover id={caseData.id} />}
            enableQuickSubscription={true}
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
                  `/dashboard/cases/incidents/${caseData.id}/knowledge`,
                )
                  ? `/dashboard/cases/incidents/${caseData.id}/knowledge`
                  : location.pathname
              }
            >
              <Tab
                component={Link}
                to={`/dashboard/cases/incidents/${caseData.id}`}
                value={`/dashboard/cases/incidents/${caseData.id}`}
                label={t('Overview')}
              />
              <Tab
                component={Link}
                to={`/dashboard/cases/incidents/${caseData.id}/knowledge`}
                value={`/dashboard/cases/incidents/${caseData.id}/knowledge`}
                label={t('Knowledge')}
              />
              <Tab
                component={Link}
                to={`/dashboard/cases/incidents/${caseData.id}/content`}
                value={`/dashboard/cases/incidents/${caseData.id}/content`}
                label={t('Content')}
              />
              <Tab
                component={Link}
                to={`/dashboard/cases/incidents/${caseData.id}/entities`}
                value={`/dashboard/cases/incidents/${caseData.id}/entities`}
                label={t('Entities')}
              />
              <Tab
                component={Link}
                to={`/dashboard/cases/incidents/${caseData.id}/observables`}
                value={`/dashboard/cases/incidents/${caseData.id}/observables`}
                label={t('Observables')}
              />
              <Tab
                component={Link}
                to={`/dashboard/cases/incidents/${caseData.id}/files`}
                value={`/dashboard/cases/incidents/${caseData.id}/files`}
                label={t('Data')}
              />
            </Tabs>
          </Box>
          <Switch>
            <Route
              exact
              path="/dashboard/cases/incidents/:caseId"
              render={() => <CaseIncident data={caseData} />}
            />
            <Route
              exact
              path="/dashboard/cases/incidents/:caseId/entities"
              render={(routeProps) => (
                <ContainerStixDomainObjects
                  {...routeProps}
                  container={caseData}
                />
              )}
            />
            <Route
              exact
              path="/dashboard/cases/incidents/:caseId/observables"
              render={(routeProps) => (
                <ContainerStixCyberObservables
                  {...routeProps}
                  container={caseData}
                />
              )}
            />
            <Route
              exact
              path="/dashboard/cases/incidents/:caseId/knowledge"
              render={() => (
                <Redirect
                  to={`/dashboard/cases/incidents/${caseId}/knowledge/graph`}
                />
              )}
            />
            <Route
              exact
              path="/dashboard/cases/incidents/:caseId/content"
              render={(routeProps) => (
                <StixDomainObjectContent
                  {...routeProps}
                  stixDomainObject={caseData}
                />
              )}
            />
            <Route
              exact
              path="/dashboard/cases/incidents/:caseId/knowledge/:mode"
              render={(routeProps) => (
                <IncidentKnowledge {...routeProps} caseData={caseData} />
              )}
            />
            <Route
              exact
              path="/dashboard/cases/incidents/:caseId/files"
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
          </Switch>
        </div>
      ) : (
        <ErrorNotFound />
      )}
    </>
  );
};

const Root = () => {
  const { caseId } = useParams();
  const queryRef = useQueryLoading<RootIncidentQuery>(caseIncidentQuery, {
    id: caseId,
  });
  return (
    <>
      {queryRef && (
        <React.Suspense fallback={<Loader variant={LoaderVariant.container} />}>
          <RootCaseIncidentComponent queryRef={queryRef} caseId={caseId} />
        </React.Suspense>
      )}
    </>
  );
};

export default Root;
