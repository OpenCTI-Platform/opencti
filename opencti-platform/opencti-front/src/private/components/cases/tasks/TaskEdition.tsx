import React, { FunctionComponent } from 'react';
import EditEntityControlledDial from '../../../../components/EditEntityControlledDial';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { tasksEditionOverviewFocus } from './TasksEditionOverview';
import TasksEditionContainer, { tasksEditionQuery } from './TasksEditionContainer';
import { TasksEditionContainerQuery } from './__generated__/TasksEditionContainerQuery.graphql';
import useApiMutation from '../../../../utils/hooks/useApiMutation';

const TaskEdition: FunctionComponent<{ caseId: string }> = ({ caseId }) => {
  const [commit] = useApiMutation(tasksEditionOverviewFocus);
  const handleClose = () => {
    commit({
      variables: {
        id: caseId,
        input: { focusOn: '' },
      },
    });
  };
  const queryRef = useQueryLoading<TasksEditionContainerQuery>(
    tasksEditionQuery,
    { id: caseId },
  );
  return (
    <>
      {queryRef && (
        <React.Suspense
          fallback={<Loader variant={LoaderVariant.inline} />}
        >
          <TasksEditionContainer
            queryRef={queryRef}
            handleClose={handleClose}
            controlledDial={EditEntityControlledDial}
          />
        </React.Suspense>
      )}
    </>
  );
};

export default TaskEdition;
