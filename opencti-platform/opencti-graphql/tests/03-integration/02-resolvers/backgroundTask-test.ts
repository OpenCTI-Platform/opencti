import { expect, describe, it } from 'vitest';
import gql from 'graphql-tag';
import { queryUnauthenticatedIsExpectedForbidden } from '../../utils/testQueryHelper';
import { deleteWork } from '../../../src/domain/work';
import { ADMIN_USER, internalAdminQuery, testContext } from '../../utils/testQuery';
import { getBestBackgroundConnectorId } from '../../../src/database/rabbitmq';
import { createWorkForBackgroundTask } from '../../../src/domain/backgroundTask-common';

const DELETE_QUERY = gql`
  mutation deleteBackgroundTask($id: ID!) {
    deleteBackgroundTask(id: $id)
  }
`;
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
      await internalAdminQuery(DELETE_QUERY, { id: 'whatever-id' }, { workId: work?.id });
    } catch (err) {
      error = err;
    }
    expect(error?.response.data.errors[0].name).toEqual('WORK_NOT_ALIVE');
  });
});
