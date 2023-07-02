/* eslint-disable @typescript-eslint/no-explicit-any */
// TODO Remove this when V6
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-nocheck
import React, { useMemo } from 'react';
import { Route, Switch, useParams } from 'react-router-dom';
import { graphql, usePreloadedQuery, useSubscription } from 'react-relay';
import { GraphQLSubscriptionConfig } from 'relay-runtime';
import TopBar from '../../nav/TopBar';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import useAuth from '../../../../utils/hooks/useAuth';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import ContainerHeader from '../../common/containers/ContainerHeader';
import StixDomainObjectContent from '../../common/stix_domain_objects/StixDomainObjectContent';
import StixCoreObjectFilesAndHistory from '../../common/stix_core_objects/StixCoreObjectFilesAndHistory';
import StixCoreObjectHistory from '../../common/stix_core_objects/StixCoreObjectHistory';
import CaseTask from './Task';
import TasksPopover from './TaskPopover';
import { RootTaskQuery } from './__generated__/RootTaskQuery.graphql';
import { RootTaskSubscription } from './__generated__/RootTaskSubscription.graphql';

const subscription = graphql`
  subscription RootTaskSubscription($id: ID!) {
    stixDomainObject(id: $id) {
      ... on Task {
        ...Tasks_tasks
      }
      ...FileImportViewer_entity
      ...FileExportViewer_entity
      ...FileExternalReferencesViewer_entity
      ...WorkbenchFileViewer_entity
    }
  }
`;

const TaskQuery = graphql`
  query RootTaskQuery($id: String!) {
    task(id: $id) {
      id
      standard_id
      name
      x_opencti_graph_data
      ...Tasks_tasks
      ...FileImportViewer_entity
      ...FileExportViewer_entity
      ...FileExternalReferencesViewer_entity
      ...WorkbenchFileViewer_entity
      ...StixDomainObjectContent_stixDomainObject
    }
    connectorsForExport {
      ...StixCoreObjectFilesAndHistory_connectorsExport
    }
    connectorsForImport {
      ...StixCoreObjectFilesAndHistory_connectorsImport
    }
  }
`;

const RootTaskComponent = ({ queryRef, caseId }) => {
  const { me } = useAuth();
  const subConfig = useMemo<GraphQLSubscriptionConfig<RootTaskSubscription>>(
    () => ({
      subscription,
      variables: { id: caseId },
    }),
    [caseId],
  );
  useSubscription(subConfig);
  const {
    task: data,
    connectorsForExport,
    connectorsForImport,
  } = usePreloadedQuery<RootTaskQuery>(TaskQuery, queryRef);
  return (
    <div>
      <TopBar me={me} />
      <>
        {data ? (
          <Switch>
            <Route
              exact
              path="/dashboard/cases/tasks/:caseId"
              render={() => <CaseTask data={data} />}
            />
            <Route
              exact
              path="/dashboard/cases/tasks/:caseId/content"
              render={(routeProps) => (
                <React.Fragment>
                  <ContainerHeader
                    container={data}
                    PopoverComponent={<TasksPopover id={data.id} />}
                    enableSuggestions={false}
                  />
                  <StixDomainObjectContent
                    {...routeProps}
                    stixDomainObject={data}
                  />
                </React.Fragment>
              )}
            />
            <Route
              exact
              path="/dashboard/cases/tasks/:caseId/files"
              render={(routeProps) => (
                <React.Fragment>
                  <ContainerHeader
                    container={data}
                    PopoverComponent={<TasksPopover id={data.id} />}
                    enableSuggestions={false}
                  />
                  <StixCoreObjectFilesAndHistory
                    {...routeProps}
                    id={caseId}
                    connectorsExport={connectorsForExport}
                    connectorsImport={connectorsForImport}
                    entity={data}
                    withoutRelations={true}
                    bypassEntityId={true}
                  />
                </React.Fragment>
              )}
            />
            <Route
              exact
              path="/dashboard/cases/tasks/:caseId/history"
              render={(routeProps: any) => (
                <React.Fragment>
                  <ContainerHeader
                    container={data}
                    PopoverComponent={<TasksPopover id={data.id} />}
                    enableSuggestions={false}
                    disableSharing={true}
                  />
                  <StixCoreObjectHistory
                    {...routeProps}
                    stixCoreObjectId={caseId}
                  />
                </React.Fragment>
              )}
            />
          </Switch>
        ) : (
          <ErrorNotFound />
        )}
      </>
    </div>
  );
};

const Root = () => {
  const { caseId } = useParams() as { caseId: string };
  const queryRef = useQueryLoading<RootTaskQuery>(TaskQuery, {
    id: caseId,
  });
  return queryRef ? (
    <React.Suspense fallback={<Loader variant={LoaderVariant.container} />}>
      <RootTaskComponent queryRef={queryRef} caseId={caseId} />
    </React.Suspense>
  ) : (
    <Loader variant={LoaderVariant.container} />
  );
};

export default Root;
