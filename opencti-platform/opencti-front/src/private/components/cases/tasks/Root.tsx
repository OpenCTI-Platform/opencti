// TODO Remove this when V6
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-nocheck
import React, { useMemo } from 'react';
import { useLocation, useParams } from 'react-router-dom';
import { graphql, usePreloadedQuery, useSubscription } from 'react-relay';
import { GraphQLSubscriptionConfig } from 'relay-runtime';
import StixCoreObjectContentRoot from '@components/common/stix_core_objects/StixCoreObjectContentRoot';
import StixDomainObjectMain from '@components/common/stix_domain_objects/StixDomainObjectMain';
import Security from 'src/utils/Security';
import useGranted, { KNOWLEDGE_KNUPDATE, KNOWLEDGE_KNUPDATE_KNDELETE, KNOWLEDGE_KNUPDATE_KNBYPASSREFERENCE } from 'src/utils/hooks/useGranted';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import ContainerHeader from '../../common/containers/ContainerHeader';
import StixCoreObjectFilesAndHistory from '../../common/stix_core_objects/StixCoreObjectFilesAndHistory';
import StixCoreObjectHistory from '../../common/stix_core_objects/StixCoreObjectHistory';
import CaseTask from './Task';
import { RootTaskQuery } from './__generated__/RootTaskQuery.graphql';
import { RootTaskSubscription } from './__generated__/RootTaskSubscription.graphql';
import { useFormatter } from '../../../../components/i18n';
import Breadcrumbs from '../../../../components/Breadcrumbs';
import { useIsEnforceReference } from '../../../../utils/hooks/useEntitySettings';
import { getPaddingRight } from '../../../../utils/utils';
import TaskEdition from './TaskEdition';
import TaskDeletion from './TaskDeletion';
import { PATH_TASK, PATH_TASKS } from '@components/common/routes/paths';

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
      entity_type
      objectMarking {
        id
        definition_type
        definition
        x_opencti_order
        x_opencti_color
      }
      ...Tasks_tasks
      ...FileImportViewer_entity
      ...FileExportViewer_entity
      ...FileExternalReferencesViewer_entity
      ...WorkbenchFileViewer_entity
      ...StixCoreObjectContent_stixCoreObject
      ...ContainerHeader_container
    }
    connectorsForExport {
      ...StixCoreObjectFilesAndHistory_connectorsExport
    }
    connectorsForImport {
      ...StixCoreObjectFilesAndHistory_connectorsImport
    }
  }
`;

const RootTaskComponent = ({ queryRef, taskId }) => {
  const subConfig = useMemo<GraphQLSubscriptionConfig<RootTaskSubscription>>(
    () => ({
      subscription,
      variables: { id: taskId },
    }),
    [taskId],
  );
  const location = useLocation();
  const enableReferences = useIsEnforceReference('Task') && !useGranted([KNOWLEDGE_KNUPDATE_KNBYPASSREFERENCE]);
  const { t_i18n } = useFormatter();

  useSubscription(subConfig);

  const {
    task: data,
    connectorsForExport,
    connectorsForImport,
  } = usePreloadedQuery<RootTaskQuery>(TaskQuery, queryRef);

  const basePath = PATH_TASK(taskId);
  const paddingRight = getPaddingRight(location.pathname, basePath);
  return (
    <>
      {data ? (
        <div style={{ paddingRight }}>
          <Breadcrumbs elements={[
            { label: t_i18n('Cases') },
            { label: t_i18n('Tasks'), link: PATH_TASKS },
            { label: data.name, current: true },
          ]}
          />
          <ContainerHeader
            container={data}
            EditComponent={(
              <Security needs={[KNOWLEDGE_KNUPDATE]}>
                <TaskEdition caseId={data.id} />
              </Security>
            )}
            DeleteComponent={({ isOpen, onClose }: { isOpen: boolean; onClose: () => void }) => (
              <Security needs={[KNOWLEDGE_KNUPDATE_KNDELETE]}>
                <TaskDeletion id={data.id} isOpen={isOpen} handleClose={onClose} />
              </Security>
            )}
            enableSuggestions={false}
            redirectToContent={true}
            disableAuthorizedMembers={true}
            enableEnrollPlaybook={true}
          />
          <StixDomainObjectMain
            basePath={basePath}
            pages={{
              overview: <CaseTask taskData={data} enableReferences={enableReferences} />,
              content: (
                <StixCoreObjectContentRoot
                  stixCoreObject={data}
                />
              ),
              files: (
                <StixCoreObjectFilesAndHistory
                  id={taskId}
                  connectorsExport={connectorsForExport}
                  connectorsImport={connectorsForImport}
                  entity={data}
                  withoutRelations={true}
                  bypassEntityId={true}
                />
              ),
              history:
                <StixCoreObjectHistory stixCoreObjectId={taskId} />,
            }}
          />
        </div>
      ) : (
        <ErrorNotFound />
      )}
    </>
  );
};

const Root = () => {
  const { taskId } = useParams() as { taskId: string };
  const queryRef = useQueryLoading<RootTaskQuery>(TaskQuery, {
    id: taskId,
  });
  return (
    <>
      {queryRef && (
        <React.Suspense fallback={<Loader variant={LoaderVariant.container} />}>
          <RootTaskComponent queryRef={queryRef} taskId={taskId} />
        </React.Suspense>
      )}
    </>
  );
};

export default Root;
