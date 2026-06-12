import { expect, describe, it } from 'vitest';
import gql from 'graphql-tag';
import { queryAsAdminWithSuccess, queryAsUserWithSuccess, queryUnauthenticatedIsExpectedForbidden } from '../../utils/testQueryHelper';
import { deleteWork } from '../../../src/domain/work';
import { ADMIN_USER, queryInitPlatformAsAdmin, testContext, USER_EDITOR, USER_SECURITY } from '../../utils/testQuery';
import { getBestBackgroundConnectorId } from '../../../src/database/rabbitmq';
import { createWorkForBackgroundTask } from '../../../src/domain/backgroundTask-common';
import type { BackgroundTaskConnectionEdge, ListTask } from '../../../src/generated/graphql';

const DELETE_QUERY = gql`
  mutation deleteBackgroundTask($id: ID!) {
    deleteBackgroundTask(id: $id)
  }
`;

const LIST_TASK_ADD_MUTATION = gql`  
  mutation listTaskAdd($input: ListTaskAddInput!) {
    listTaskAdd(input: $input) {
      id
      ... on ListTask {
        description
      }
    }
  }`;

const BACKGROUND_TASKS_QUERY = gql`  
  query backgroundTasks {
    backgroundTasks {
      edges {
        node {
          id
          ... on ListTask {
            description
          }
        }
      }
    }
  }`;

describe('Background task graphQL API permission checks', () => {
  it('should Anonymous not be allowed to delete a BackgroundTask.', async () => {
    await queryUnauthenticatedIsExpectedForbidden({
      query: DELETE_QUERY,
      variables: { id: 'whatever-id' },
    });
  });
});
describe('Verify deleted works', () => {
  it('should request on deleted work be rejected with reason WORK_NOT_ALIVE.', async () => {
    const backgroundTaskConnectorId = await getBestBackgroundConnectorId(testContext, ADMIN_USER);
    const work = await createWorkForBackgroundTask(testContext, 'fake_id', backgroundTaskConnectorId);
    await deleteWork(testContext, ADMIN_USER, work?.id);

    let error: any;
    try {
      await queryInitPlatformAsAdmin(DELETE_QUERY, { id: 'whatever-id' }, { workId: work?.id });
    } catch (err) {
      error = err;
    }
    expect(error?.response.data.errors[0].name).toEqual('WORK_NOT_ALIVE');
  });
});
describe('Background task visibility per initiator', () => {
  let taskCreatedByEditor: string;
  let taskCreatedBySecurity: string;
  it('should USER_EDITOR create a background task', async () => {
    const result = await queryAsUserWithSuccess(USER_EDITOR, {
      query: LIST_TASK_ADD_MUTATION,
      variables: {
        input: {
          description: 'Task created by editor',
          ids: [],
          actions: [{ type: 'DELETE' }],
          scope: 'KNOWLEDGE',
        },
      },
    });
    taskCreatedByEditor = (result.data.listTaskAdd as ListTask).id;
    expect(taskCreatedByEditor).toBeDefined();
  });

  it('should USER_SECURITY create a background task', async () => {
    const result = await queryAsUserWithSuccess(USER_SECURITY, {
      query: LIST_TASK_ADD_MUTATION,
      variables: {
        input: {
          description: 'Task created by security',
          ids: [],
          actions: [{ type: 'DELETE' }],
          scope: 'KNOWLEDGE',
        },
      },
    });
    taskCreatedBySecurity = (result.data.listTaskAdd as ListTask).id;
    expect(taskCreatedBySecurity).toBeDefined();
  });

  it('should USER_EDITOR only see its own tasks, not tasks from USER_SECURITY', async () => {
    const result = await queryAsUserWithSuccess(USER_EDITOR, {
      query: BACKGROUND_TASKS_QUERY,
    });
    const ids = result.data.backgroundTasks.edges.map((e: BackgroundTaskConnectionEdge) => e.node.id);
    expect(ids).toContain(taskCreatedByEditor);
    expect(ids).not.toContain(taskCreatedBySecurity);
  });

  it('should USER_SECURITY only see its own tasks, not tasks from USER_EDITOR', async () => {
    const result = await queryAsUserWithSuccess(USER_SECURITY, {
      query: BACKGROUND_TASKS_QUERY,
    });
    const ids = result.data.backgroundTasks.edges.map((e: BackgroundTaskConnectionEdge) => e.node.id);
    expect(ids).toContain(taskCreatedBySecurity);
    expect(ids).not.toContain(taskCreatedByEditor);
  });

  it('should ADMIN see all tasks', async () => {
    const result = await queryAsAdminWithSuccess({
      query: BACKGROUND_TASKS_QUERY,
    });
    const ids = result.data.backgroundTasks.edges.map((e: BackgroundTaskConnectionEdge) => e.node.id);
    expect(ids).toContain(taskCreatedByEditor);
    expect(ids).toContain(taskCreatedBySecurity);
  });
});
