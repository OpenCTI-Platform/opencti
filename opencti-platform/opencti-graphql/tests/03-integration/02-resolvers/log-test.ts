import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import gql from 'graphql-tag';
import { addReport } from '../../../src/domain/report';
import { ADMIN_USER, testContext } from '../../utils/testQuery';
import { stixDomainObjectDelete, stixDomainObjectEditField } from '../../../src/domain/stixDomainObject';
import { awaitUntilCondition, queryAsAdminWithSuccess } from '../../utils/testQueryHelper';
import { utcDate } from '../../../src/utils/format';
import { ENTITY_TYPE_CONTAINER_REPORT } from '../../../src/schema/stixDomainObject';

const READ_QUERY = gql`
  query Logs($first: Int, $filters: FilterGroup) {
    logs(first: $first, filters: $filters) {
      edges {
        node {
          id
          event_type
          event_scope
          context_data {
            message
            changes {
              field
              previous
              new
              added
              removed
            }
          }
        }
      }
    }
  }
`;

describe('Log resolver standard behavior', async () => {
  let reportInternalId: string;

  beforeAll(async () => {
    const report = await addReport(testContext, ADMIN_USER, {
      name: 'Report2',
      published: utcDate(),
    });
    reportInternalId = report.id;
  });

  afterAll(async () => {
    await stixDomainObjectDelete(testContext, ADMIN_USER, reportInternalId, ENTITY_TYPE_CONTAINER_REPORT);
  });
  it('should log previous and value for description update', async () => {
    // Update description
    await stixDomainObjectEditField(testContext, ADMIN_USER, reportInternalId, [{ key: 'description', value: ['new description'] }]);

    // Wait until the log is available
    await awaitUntilCondition(async () => {
      const queryResult = await queryAsAdminWithSuccess({
        query: READ_QUERY,
        variables: {
          filters: {
            mode: 'and',
            filterGroups: [],
            filters: [
              {
                key: [
                  'context_data.id',
                ],
                values: [reportInternalId],
              },
            ],
          },
        },
      });
      return queryResult?.data?.logs.edges.length > 1; // we need create and update
    }, 2000, 20);

    const queryResult = await queryAsAdminWithSuccess({
      query: READ_QUERY,
      variables: {
        filters: {
          mode: 'and',
          filterGroups: [],
          filters: [
            {
              key: [
                'context_data.id',
              ],
              values: [reportInternalId],
            },
          ],
        },
      },
    });

    const updateEvent = queryResult?.data?.logs.edges.find((item: any) => item.node.event_scope === 'update');
    expect(updateEvent.node.context_data.changes[0]).toEqual({
      field: 'description',
      previous: [],
      new: ['new description'],
      added: null,
      removed: null,
    });
  });
});
