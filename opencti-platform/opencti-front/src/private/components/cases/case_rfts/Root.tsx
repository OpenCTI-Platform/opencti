/* eslint-disable @typescript-eslint/no-explicit-any */
// TODO Remove this when V6
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-nocheck
import React, { useMemo } from 'react';
import { Link, Navigate, Route, Routes, useLocation, useParams } from 'react-router-dom';
import { graphql, usePreloadedQuery, useSubscription } from 'react-relay';
import { GraphQLSubscriptionConfig } from 'relay-runtime';
import Box from '@mui/material/Box';
import Tabs from '@mui/material/Tabs';
import Tab from '@mui/material/Tab';
import StixCoreObjectContentRoot from '@components/common/stix_core_objects/StixCoreObjectContentRoot';
import Security from 'src/utils/Security';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import ContainerHeader from '../../common/containers/ContainerHeader';
import StixCoreObjectFilesAndHistory from '../../common/stix_core_objects/StixCoreObjectFilesAndHistory';
import StixCoreObjectHistory from '../../common/stix_core_objects/StixCoreObjectHistory';
import CaseRft from './CaseRft';
import CaseRftPopover from './CaseRftPopover';
import CaseRftKnowledge from './CaseRftKnowledge';
import ContainerStixCyberObservables from '../../common/containers/ContainerStixCyberObservables';
import ContainerStixDomainObjects from '../../common/containers/ContainerStixDomainObjects';
import { RootCaseRftCaseQuery } from './__generated__/RootCaseRftCaseQuery.graphql';
import { useFormatter } from '../../../../components/i18n';
import Breadcrumbs from '../../../../components/Breadcrumbs';
import { useIsEnforceReference } from '../../../../utils/hooks/useEntitySettings';
import useGranted, { KNOWLEDGE_KNUPDATE_KNBYPASSREFERENCE, KNOWLEDGE_KNUPDATE } from '../../../../utils/hooks/useGranted';
import { getCurrentTab, getPaddingRight } from '../../../../utils/utils';
import CaseRftEdition from './CaseRftEdition';

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
      entity_type
      name
      x_opencti_graph_data
      ...CaseUtils_case
      ...CaseRftKnowledge_case
      ...FileImportViewer_entity
      ...FileExportViewer_entity
      ...FileExternalReferencesViewer_entity
      ...WorkbenchFileViewer_entity
      ...StixCoreObjectContent_stixCoreObject
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
  const enableReferences = useIsEnforceReference('Case-Rft') && !useGranted([KNOWLEDGE_KNUPDATE_KNBYPASSREFERENCE]);
  const { t_i18n } = useFormatter();
  useSubscription(subConfig);

  const {
    caseRft: caseData,
    connectorsForExport,
    connectorsForImport,
  } = usePreloadedQuery<RootCaseRftCaseQuery>(caseRftQuery, queryRef);
  const paddingRight = getPaddingRight(location.pathname, caseData?.id, '/dashboard/cases/rfts', false);
  return (
    <>
      {caseData ? (
        <div style={{ paddingRight }}>
          <Breadcrumbs variant="object" elements={[
            { label: t_i18n('Cases') },
            { label: t_i18n('Requests for takedown'), link: '/dashboard/cases/rfts' },
            { label: caseData.name, current: true },
          ]}
          />
          <ContainerHeader
            container={caseData}
            PopoverComponent={<CaseRftPopover id={caseData.id} />}
            EditComponent={<Security needs={[KNOWLEDGE_KNUPDATE]}>
              <CaseRftEdition caseId={caseData.id} />
            </Security>}
            enableQuickSubscription={true}
            enableAskAi={true}
            redirectToContent={true}
          />
          <Box
            sx={{
              borderBottom: 1,
              borderColor: 'divider',
              marginBottom: 4,
            }}
          >
            <Tabs
              value={getCurrentTab(location.pathname, caseData.id, '/dashboard/cases/rfts')}
            >
              <Tab
                component={Link}
                to={`/dashboard/cases/rfts/${caseData.id}`}
                value={`/dashboard/cases/rfts/${caseData.id}`}
                label={t_i18n('Overview')}
              />
              <Tab
                component={Link}
                to={`/dashboard/cases/rfts/${caseData.id}/knowledge/graph`}
                value={`/dashboard/cases/rfts/${caseData.id}/knowledge`}
                label={t_i18n('Knowledge')}
              />
              <Tab
                component={Link}
                to={`/dashboard/cases/rfts/${caseData.id}/content`}
                value={`/dashboard/cases/rfts/${caseData.id}/content`}
                label={t_i18n('Content')}
              />
              <Tab
                component={Link}
                to={`/dashboard/cases/rfts/${caseData.id}/entities`}
                value={`/dashboard/cases/rfts/${caseData.id}/entities`}
                label={t_i18n('Entities')}
              />
              <Tab
                component={Link}
                to={`/dashboard/cases/rfts/${caseData.id}/observables`}
                value={`/dashboard/cases/rfts/${caseData.id}/observables`}
                label={t_i18n('Observables')}
              />
              <Tab
                component={Link}
                to={`/dashboard/cases/rfts/${caseData.id}/files`}
                value={`/dashboard/cases/rfts/${caseData.id}/files`}
                label={t_i18n('Data')}
              />
            </Tabs>
          </Box>
          <Routes>
            <Route
              path="/"
              element={<CaseRft caseRftData={caseData} enableReferences={enableReferences} />}
            />
            <Route
              path="/entities"
              element={(
                <ContainerStixDomainObjects
                  container={caseData}
                  enableReferences={enableReferences}
                />
              )}
            />
            <Route
              path="/observables"
              element={(
                <ContainerStixCyberObservables
                  container={caseData}
                  enableReferences={enableReferences}
                />
              )}
            />
            <Route
              path="/content/*"
              element={
                <StixCoreObjectContentRoot
                  stixCoreObject={caseData}
                  isContainer={true}
                />
              }
            />
            <Route
              path="/knowledge"
              element={
                <Navigate
                  replace={true}
                  to={`/dashboard/cases/rfts/${caseId}/knowledge/graph`}
                />
                }
            />
            <Route
              path="/knowledge/*"
              element={(
                <CaseRftKnowledge caseData={caseData}
                  enableReferences={enableReferences}
                />
              )}
            />
            <Route
              path="/files"
              element={(
                <StixCoreObjectFilesAndHistory
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
              path="/history"
              element={
                <StixCoreObjectHistory
                  stixCoreObjectId={caseId}
                />}
            />
          </Routes>
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
