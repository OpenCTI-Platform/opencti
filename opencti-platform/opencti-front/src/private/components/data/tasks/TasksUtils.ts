import { BackgroundTaskScope, BackgroundTaskType } from './__generated__/TasksList_data.graphql';

const computeLabel = (type: BackgroundTaskType | null, taskScope?: BackgroundTaskScope) => {
  return taskScope ?? type;
};

export default computeLabel;
