import { APIRequestContext } from '@playwright/test';
import { graphqlQuery } from './query-utils';
import { awaitUntilCondition } from './utils';

const getBackgroundTasksQuery = () => `
  query {
    backgroundTasks() {
      id
      completed
    }
  }
`;

const getBackgroundTasks = async (
  request: APIRequestContext,
) => {
  return graphqlQuery(request, getBackgroundTasksQuery());
};

/**
 * Wait for all the background tasks to be completed via a graphql check
 * @param request
 */
export const checkBackgroundTasksCompletion = async (
  request: APIRequestContext,
) => {
  const conditionPromise = async () => {
    const backgroundTasksResponse = await getBackgroundTasks(request);
    const backgroundTasks = await backgroundTasksResponse.json();
    console.log('----------------backgroundTasks', backgroundTasks); // TODO to remove
    return backgroundTasks.every((t: { completed: boolean }) => t.completed);
  };
  return awaitUntilCondition(
    conditionPromise,
    6000,
    20,
  );
};
