import { describe, it } from 'vitest';
import gql from 'graphql-tag';
import { queryUnauthenticatedIsExpectedForbidden } from '../../utils/testQueryHelper';

describe('Background task graphQL API permission checks', () => {
  it('should Anonymous not be allowed to delete a BackgroundTask.', async () => {
    const DELETE_QUERY = gql`
          mutation deleteBackgroundTask($id: ID!) {
              deleteBackgroundTask(id: $id)
          }
      `;

    await queryUnauthenticatedIsExpectedForbidden({
      query: DELETE_QUERY,
      variables: { id: 'whatever-id' },
    });
  });
});
