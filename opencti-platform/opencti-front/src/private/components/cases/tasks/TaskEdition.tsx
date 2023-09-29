import React, { FunctionComponent } from 'react';
import { useMutation } from 'react-relay';
import Loader, { LoaderVariant } from '../../../../components/Loader';
import useQueryLoading from '../../../../utils/hooks/useQueryLoading';
import { tasksEditionOverviewFocus } from './TasksEditionOverview';
import TasksEditionContainer, { tasksEditionQuery } from './TasksEditionContainer';
import { TasksEditionContainerQuery } from './__generated__/TasksEditionContainerQuery.graphql';

const TaskEdition: FunctionComponent<{ caseId: string }> = ({ caseId }) => {
  const [commit] = useMutation(tasksEditionOverviewFocus);
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
          fallback={<Loader variant={LoaderVariant.inElement} />}
        >
          <TasksEditionContainer
            queryRef={queryRef}
            handleClose={handleClose}
          />
        </React.Suspense>
      )}
    </>
  );
};

export default TaskEdition;
