/* eslint-disable @typescript-eslint/no-explicit-any */
// TODO Remove this when V6
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-nocheck
import React, { useMemo } from 'react';
import { Link, Navigate, Route, Routes, useLocation, useParams } from 'react-router-dom';
import { graphql, useSubscription } from 'react-relay';
import Box from '@mui/material/Box';
import Tabs from '@mui/material/Tabs';
import Tab from '@mui/material/Tab';
import { GraphQLSubscriptionConfig } from 'relay-runtime';
import { RootReportSubscription } from '@components/analyses/reports/__generated__/RootReportSubscription.graphql';
import StixCoreObjectSimulationResult from '@components/common/stix_core_objects/StixCoreObjectSimulationResult';
import StixCoreObjectContent from '../../common/stix_core_objects/StixCoreObjectContent';
import { QueryRenderer } from '../../../../relay/environment';
import Grouping from './Grouping';
import GroupingPopover from './GroupingPopover';
import GroupingKnowledge from './GroupingKnowledge';
import ContainerHeader from '../../common/containers/ContainerHeader';
import Loader from '../../../../components/Loader';
import ContainerStixDomainObjects from '../../common/containers/ContainerStixDomainObjects';
import ContainerStixCyberObservables from '../../common/containers/ContainerStixCyberObservables';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import StixCoreObjectFilesAndHistory from '../../common/stix_core_objects/StixCoreObjectFilesAndHistory';
import { useFormatter } from '../../../../components/i18n';
import Breadcrumbs from '../../../../components/Breadcrumbs';
import { useIsEnforceReference } from '../../../../utils/hooks/useEntitySettings';
import useGranted, { BYPASSREFERENCE } from '../../../../utils/hooks/useGranted';

const subscription = graphql`
  subscription RootGroupingSubscription($id: ID!) {
    stixDomainObject(id: $id) {
      ... on Grouping {
        ...Grouping_grouping
        ...GroupingKnowledgeGraph_grouping
        ...GroupingEditionContainer_grouping
        ...StixCoreObjectContent_stixCoreObject
      }
      ...FileImportViewer_entity
      ...FileExportViewer_entity
      ...FileExternalReferencesViewer_entity
      ...WorkbenchFileViewer_entity
    }
  }
`;

const groupingQuery = graphql`
  query RootGroupingQuery($id: String!) {
    grouping(id: $id) {
      id
      standard_id
      entity_type
      name
      ...Grouping_grouping
      ...GroupingDetails_grouping
      ...GroupingKnowledge_grouping
      ...ContainerHeader_container
      ...ContainerStixDomainObjects_container
      ...ContainerStixCyberObservables_container
      ...StixCoreObjectContent_stixCoreObject
      ...FileImportViewer_entity
      ...FileExportViewer_entity
      ...FileExternalReferencesViewer_entity
      ...WorkbenchFileViewer_entity
    }
    connectorsForExport {
      ...StixCoreObjectFilesAndHistory_connectorsExport
    }
    connectorsForImport {
      ...StixCoreObjectFilesAndHistory_connectorsImport
    }
  }
`;

const RootGrouping = () => {
  const { groupingId } = useParams() as { groupingId: string };
  const subConfig = useMemo<
  GraphQLSubscriptionConfig<RootReportSubscription>
  >(
    () => ({
      subscription,
      variables: { id: groupingId },
    }),
    [groupingId],
  );
  const location = useLocation();
  const enableReferences = useIsEnforceReference('Grouping') && !useGranted([BYPASSREFERENCE]);
  const { t_i18n } = useFormatter();
  useSubscription(subConfig);
  return (
    <>
      <QueryRenderer
        query={groupingQuery}
        variables={{ id: groupingId }}
        render={({ props }) => {
          if (props) {
            if (props.grouping) {
              const { grouping } = props;
              let paddingRight = 0;
              const isOverview = location.pathname === `/dashboard/analyses/groupings/${grouping.id}`;
              if (
                location.pathname.includes(
                  `/dashboard/analyses/groupings/${grouping.id}/entities`,
                )
                      || location.pathname.includes(
                        `/dashboard/analyses/groupings/${grouping.id}/observables`,
                      )
              ) {
                paddingRight = 250;
              }
              if (
                location.pathname.includes(
                  `/dashboard/analyses/groupings/${grouping.id}/content`,
                )
              ) {
                paddingRight = 350;
              }
              return (
                <div style={{ paddingRight }}>
                  <Breadcrumbs variant="object" elements={[
                    { label: t_i18n('Analyses') },
                    { label: t_i18n('Groupings'), link: '/dashboard/analyses/groupings' },
                    { label: grouping.name, current: true },
                  ]}
                  />
                  <ContainerHeader
                    container={grouping}
                    PopoverComponent={<GroupingPopover />}
                    enableQuickSubscription={true}
                    enableQuickExport={true}
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
                      value={
                                location.pathname.includes(
                                  `/dashboard/analyses/groupings/${grouping.id}/knowledge`,
                                )
                                  ? `/dashboard/analyses/groupings/${grouping.id}/knowledge`
                                  : location.pathname
                              }
                    >
                      <Tab
                        component={Link}
                        to={`/dashboard/analyses/groupings/${grouping.id}`}
                        value={`/dashboard/analyses/groupings/${grouping.id}`}
                        label={t_i18n('Overview')}
                      />
                      <Tab
                        component={Link}
                        to={`/dashboard/analyses/groupings/${grouping.id}/knowledge/graph`}
                        value={`/dashboard/analyses/groupings/${grouping.id}/knowledge`}
                        label={t_i18n('Knowledge')}
                      />
                      <Tab
                        component={Link}
                        to={`/dashboard/analyses/groupings/${grouping.id}/content`}
                        value={`/dashboard/analyses/groupings/${grouping.id}/content`}
                        label={t_i18n('Content')}
                      />
                      <Tab
                        component={Link}
                        to={`/dashboard/analyses/groupings/${grouping.id}/entities`}
                        value={`/dashboard/analyses/groupings/${grouping.id}/entities`}
                        label={t_i18n('Entities')}
                      />
                      <Tab
                        component={Link}
                        to={`/dashboard/analyses/groupings/${grouping.id}/observables`}
                        value={`/dashboard/analyses/groupings/${grouping.id}/observables`}
                        label={t_i18n('Observables')}
                      />
                      <Tab
                        component={Link}
                        to={`/dashboard/analyses/groupings/${grouping.id}/files`}
                        value={`/dashboard/analyses/groupings/${grouping.id}/files`}
                        label={t_i18n('Data')}
                      />
                    </Tabs>
                    {isOverview && (
                      <StixCoreObjectSimulationResult id={grouping.id} type="container" />
                    )}
                  </Box>
                  <Routes>
                    <Route
                      path="/"
                      element={
                        <Grouping grouping={grouping} />
                      }
                    />
                    <Route
                      path="/entities"
                      element={
                        <ContainerStixDomainObjects
                          container={grouping}
                          enableReferences={enableReferences}
                        />
                      }
                    />
                    <Route
                      path="/observables"
                      element={
                        <ContainerStixCyberObservables
                          container={grouping}
                          enableReferences={enableReferences}
                        />
                      }
                    />
                    <Route
                      path="/content"
                      element={
                        <StixCoreObjectContent
                          stixCoreObject={grouping}
                        />
                      }
                    />
                    <Route
                      path="/knowledge"
                      element={
                        <Navigate
                          replace={true}
                          to={`/dashboard/analyses/groupings/${groupingId}/knowledge/graph`}
                        />}
                    />
                    <Route
                      path="/knowledge/*"
                      element={
                        <GroupingKnowledge
                          grouping={grouping}
                          enableReferences={enableReferences}
                        />
                      }
                    />
                    <Route
                      path="/files"
                      element={
                        <StixCoreObjectFilesAndHistory
                          id={groupingId}
                          connectorsExport={props.connectorsForExport}
                          connectorsImport={props.connectorsForImport}
                          entity={props.grouping}
                          withoutRelations={true}
                          bypassEntityId={true}
                        />
                      }
                    />
                  </Routes>
                </div>
              );
            }
            return <ErrorNotFound />;
          }
          return <Loader />;
        }}
      />
    </>
  );
};

export default RootGrouping;
