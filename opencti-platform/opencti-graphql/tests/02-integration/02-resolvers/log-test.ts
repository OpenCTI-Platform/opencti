import {afterAll, beforeAll, describe, expect, it} from 'vitest';
import gql from "graphql-tag";
import {addReport, findById} from "../../../src/domain/report";
import {ADMIN_USER, testContext} from "../../utils/testQuery";
import {stixDomainObjectDelete, stixDomainObjectEditField} from "../../../src/domain/stixDomainObject";
import {queryAsAdminWithSuccess} from "../../utils/testQueryHelper";
import {utcDate} from "../../../src/utils/format";

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

describe.skip('Log resolver standard behavior', async () => {
  let reportInternalId: string;

  beforeAll(async () => {
    const report = await addReport(testContext, ADMIN_USER, {
      name: 'Report2',
      published: utcDate(),
  });
  reportInternalId = report.id;
  })

  afterAll(async() => {
    await stixDomainObjectDelete(testContext, ADMIN_USER, reportInternalId)
  });
  it('should log previous and value for description update', async () => {
    // Update description
    await stixDomainObjectEditField(testContext, ADMIN_USER, reportInternalId, [{key: 'description', value: ['new description']}])
    const queryResult = await queryAsAdminWithSuccess({
      query: READ_QUERY,
      variables: {
        "filters": {
          "mode": "and",
          "filterGroups": [],
          "filters": [
            {
              "key": [
                "context_data.id"
              ],
              "values": [reportInternalId]
            }
          ]
        }
      }
    })
    console.log({queryResult: JSON.stringify(queryResult)})
    expect(queryResult?.data?.logs.edges[0].node.event_scope).toEqual('update');
    expect(queryResult?.data?.logs.edges[0].node.context_data.changes[0]).toEqual({
        "field": "Description",
        "previous": [],
        "new": ['new description'],
      });
  });
});
