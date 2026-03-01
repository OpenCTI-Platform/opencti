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
    const backgroundTasksBody = await backgroundTasksResponse.json();
    return backgroundTasksBody.data.backgroundTasks.edges.every((t: { node: { id: string; completed: boolean } }) => t.node.completed);
  };
  return awaitUntilCondition(
    conditionPromise,
    6000,
    20,
  );
};
