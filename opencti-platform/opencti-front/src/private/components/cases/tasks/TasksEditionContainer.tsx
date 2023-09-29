import React, { FunctionComponent } from 'react';
import { graphql, PreloadedQuery, usePreloadedQuery } from 'react-relay';
import Drawer, { DrawerVariant } from '@components/common/drawer/Drawer';
import ErrorNotFound from '../../../../components/ErrorNotFound';
import { useFormatter } from '../../../../components/i18n';
import { useIsEnforceReference } from '../../../../utils/hooks/useEntitySettings';
import TasksEditionOverview from './TasksEditionOverview';
import { TasksEditionContainerQuery } from './__generated__/TasksEditionContainerQuery.graphql';

interface TasksEditionContainerProps {
  queryRef: PreloadedQuery<TasksEditionContainerQuery>
  handleClose: () => void
  open?: boolean
}

export const tasksEditionQuery = graphql`
  query TasksEditionContainerQuery($id: String!) {
    task(id: $id) {
      ...TasksEditionOverview_task
      editContext {
        name
        focusOn
      }
    }
  }
`;

const TasksEditionContainer: FunctionComponent<TasksEditionContainerProps> = ({ queryRef, handleClose, open }) => {
  const { t } = useFormatter();
  const { task } = usePreloadedQuery(tasksEditionQuery, queryRef);
  if (task === null) {
    return <ErrorNotFound />;
  }
  return (
    <Drawer
      title={t('Update a task')}
      variant={open == null ? DrawerVariant.update : undefined}
      context={task.editContext}
      onClose={handleClose}
      open={open}
    >
      {({ onClose }) => (
        <TasksEditionOverview
          taskRef={task}
          context={task.editContext}
          enableReferences={useIsEnforceReference('Task')}
          handleClose={onClose}
        />
      )}
    </Drawer>
  );
};

export default TasksEditionContainer;
