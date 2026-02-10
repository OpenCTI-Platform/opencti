import { APIRequestContext } from '@playwright/test';
import { graphqlQuery } from './query-utils';
import { awaitUntilCondition } from './utils';

const getBackgroundTasksQuery = () => `
  query {
    backgroundTasks {
      edges {
        node {
          id
          completed
        }
      }
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
    console.log('backgroundTasksResponse', JSON.stringify(backgroundTasksResponse));
    const backgroundTasks = await backgroundTasksResponse.json();
    console.log('----------------backgroundTasks', JSON.stringify(backgroundTasks)); // TODO to remove
    return backgroundTasks.every((t: { completed: boolean }) => t.completed);
  };
  return awaitUntilCondition(
    conditionPromise,
    6000,
    20,
  );
};
