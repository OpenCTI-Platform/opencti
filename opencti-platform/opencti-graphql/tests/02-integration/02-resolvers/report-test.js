import gql from 'graphql-tag';
import { queryAsAdmin } from '../../utils/testQuery';
import { now } from '../../../src/database/grakn';

const LIST_QUERY = gql`
  query reports(
    $first: Int
    $after: ID
    $orderBy: ReportsOrdering
    $orderMode: OrderingMode
    $filters: [ReportsFiltering]
    $filterMode: FilterMode
    $search: String
  ) {
    reports(
      first: $first
      after: $after
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
      filterMode: $filterMode
      search: $search
    ) {
      edges {
        node {
          id
          name
          description
        }
      }
    }
  }
`;

const TIMESERIES_QUERY = gql`
  query reportsTimeSeries(
    $objectId: String
    $authorId: String
    $field: String!
    $operation: StatsOperation!
    $startDate: DateTime!
    $endDate: DateTime!
    $interval: String!
  ) {
    reportsTimeSeries(
      objectId: $objectId
      authorId: $authorId
      field: $field
      operation: $operation
      startDate: $startDate
      endDate: $endDate
      interval: $interval
    ) {
      date
      value
    }
  }
`;

const NUMBER_QUERY = gql`
  query reportsNumber($objectId: String, $endDate: DateTime!) {
    reportsNumber(objectId: $objectId, endDate: $endDate) {
      total
      count
    }
  }
`;

const DISTRIBUTION_QUERY = gql`
  query reportsDistribution(
    $objectId: String
    $field: String!
    $operation: StatsOperation!
    $limit: Int
    $order: String
  ) {
    reportsDistribution(objectId: $objectId, field: $field, operation: $operation, limit: $limit, order: $order) {
      label
      value
    }
  }
`;

const READ_QUERY = gql`
  query report($id: String!) {
    report(id: $id) {
      id
      name
      description
      toStix
    }
  }
`;

describe('Report resolver standard behavior', () => {
  let reportInternalId;
  let reportMarkingDefinitionRelationId;
  const reportStixId = 'report--aa0d4d61-0fc5-4f8b-9b7b-c7ddcf1d3111';
  it('should report created', async () => {
    const CREATE_QUERY = gql`
      mutation ReportAdd($input: ReportAddInput) {
        reportAdd(input: $input) {
          id
          name
          description
        }
      }
    `;
    // Create the report
    const REPORT_TO_CREATE = {
      input: {
        name: 'Report',
        stix_id_key: reportStixId,
        description: 'Report description',
        published: '2020-02-26T00:51:35.000Z',
      },
    };
    const report = await queryAsAdmin({
      query: CREATE_QUERY,
      variables: REPORT_TO_CREATE,
    });
    expect(report).not.toBeNull();
    expect(report.data.reportAdd).not.toBeNull();
    expect(report.data.reportAdd.name).toEqual('Report');
    reportInternalId = report.data.reportAdd.id;
  });
  it('should report loaded by internal id', async () => {
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: reportInternalId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.report).not.toBeNull();
    expect(queryResult.data.report.id).toEqual(reportInternalId);
    expect(queryResult.data.report.toStix.length).toBeGreaterThan(5);
  });
  it('should report loaded by stix id', async () => {
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: reportStixId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.report).not.toBeNull();
    expect(queryResult.data.report.id).toEqual(reportInternalId);
  });
  it('should report stix domain entities accurate', async () => {
    const REPORT_STIX_DOMAIN_ENTITIES = gql`
      query report($id: String!) {
        report(id: $id) {
          id
          objectRefs {
            edges {
              node {
                id
              }
            }
          }
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: REPORT_STIX_DOMAIN_ENTITIES,
      variables: { id: '685aac19-d2f6-4835-a256-0631bb322732' },
    });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.report).not.toBeNull();
    expect(queryResult.data.report.id).toEqual('685aac19-d2f6-4835-a256-0631bb322732');
    expect(queryResult.data.report.objectRefs.edges.length).toEqual(14);
  });
  it('should report contains stix domain entity accurate', async () => {
    const REPORT_CONTAINS_STIX_DOMAIN_ENTITY = gql`
      query reportContainsStixDomainEntity($id: String!, $objectId: String!) {
        reportContainsStixDomainEntity(id: $id, objectId: $objectId)
      }
    `;
    const queryResult = await queryAsAdmin({
      query: REPORT_CONTAINS_STIX_DOMAIN_ENTITY,
      variables: { id: '685aac19-d2f6-4835-a256-0631bb322732', objectId: '9f7f00f9-304b-4055-8c4f-f5eadb00de3b' },
    });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.reportContainsStixDomainEntity).not.toBeNull();
    expect(queryResult.data.reportContainsStixDomainEntity).toBeTruthy();
  });
  it('should report stix relations accurate', async () => {
    const REPORT_STIX_RELATIONS = gql`
      query report($id: String!) {
        report(id: $id) {
          id
          relationRefs {
            edges {
              node {
                id
              }
            }
          }
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: REPORT_STIX_RELATIONS,
      variables: { id: '685aac19-d2f6-4835-a256-0631bb322732' },
    });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.report).not.toBeNull();
    expect(queryResult.data.report.id).toEqual('685aac19-d2f6-4835-a256-0631bb322732');
    expect(queryResult.data.report.relationRefs.edges.length).toEqual(11);
  });
  it('should report contains stix relation accurate', async () => {
    const REPORT_CONTAINS_STIX_RELATION = gql`
      query reportContainsStixRelation($id: String!, $objectId: String!) {
        reportContainsStixRelation(id: $id, objectId: $objectId)
      }
    `;
    const queryResult = await queryAsAdmin({
      query: REPORT_CONTAINS_STIX_RELATION,
      variables: { id: '685aac19-d2f6-4835-a256-0631bb322732', objectId: 'c094dbfe-7034-45f6-a283-b00b6a740b6c' },
    });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.reportContainsStixRelation).not.toBeNull();
    expect(queryResult.data.reportContainsStixRelation).toBeTruthy();
  });
  it('should report stix observables accurate', async () => {
    const REPORT_STIX_OBSERVABLES = gql`
      query report($id: String!) {
        report(id: $id) {
          id
          observableRefs {
            edges {
              node {
                id
              }
            }
          }
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: REPORT_STIX_OBSERVABLES,
      variables: { id: '685aac19-d2f6-4835-a256-0631bb322732' },
    });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.report).not.toBeNull();
    expect(queryResult.data.report.id).toEqual('685aac19-d2f6-4835-a256-0631bb322732');
    expect(queryResult.data.report.observableRefs.edges.length).toEqual(6);
  });
  it('should list reports', async () => {
    const queryResult = await queryAsAdmin({ query: LIST_QUERY, variables: { first: 10 } });
    expect(queryResult.data.reports.edges.length).toEqual(2);
  });
  it('should timeseries reports to be accurate', async () => {
    const queryResult = await queryAsAdmin({
      query: TIMESERIES_QUERY,
      variables: {
        field: 'published',
        operation: 'count',
        startDate: '2020-01-01T00:00:00+00:00',
        endDate: '2021-01-01T00:00:00+00:00',
        interval: 'month',
      },
    });
    expect(queryResult.data.reportsTimeSeries.length).toEqual(13);
    expect(queryResult.data.reportsTimeSeries[1].value).toEqual(1);
    expect(queryResult.data.reportsTimeSeries[2].value).toEqual(1);
  });
  it('should timeseries reports for entity to be accurate', async () => {
    const queryResult = await queryAsAdmin({
      query: TIMESERIES_QUERY,
      variables: {
        objectId: 'ab78a62f-4928-4d5a-8740-03f0af9c4330',
        field: 'published',
        operation: 'count',
        startDate: '2020-01-01T00:00:00+00:00',
        endDate: '2021-01-01T00:00:00+00:00',
        interval: 'month',
      },
    });
    expect(queryResult.data.reportsTimeSeries.length).toEqual(13);
    expect(queryResult.data.reportsTimeSeries[1].value).toEqual(0);
    expect(queryResult.data.reportsTimeSeries[2].value).toEqual(1);
  });
  it('should timeseries reports for author to be accurate', async () => {
    const queryResult = await queryAsAdmin({
      query: TIMESERIES_QUERY,
      variables: {
        authorId: 'c79e5d9f-4321-4174-b120-7cd9342ec88a',
        field: 'published',
        operation: 'count',
        startDate: '2020-01-01T00:00:00+00:00',
        endDate: '2021-01-01T00:00:00+00:00',
        interval: 'month',
      },
    });
    expect(queryResult.data.reportsTimeSeries.length).toEqual(13);
    expect(queryResult.data.reportsTimeSeries[1].value).toEqual(0);
    expect(queryResult.data.reportsTimeSeries[2].value).toEqual(1);
  });
  it('should reports number to be accurate', async () => {
    const queryResult = await queryAsAdmin({
      query: NUMBER_QUERY,
      variables: {
        endDate: now(),
      },
    });
    expect(queryResult.data.reportsNumber.total).toEqual(2);
    expect(queryResult.data.reportsNumber.count).toEqual(2);
  });
  it('should reports number by entity to be accurate', async () => {
    const queryResult = await queryAsAdmin({
      query: NUMBER_QUERY,
      variables: {
        objectId: 'ab78a62f-4928-4d5a-8740-03f0af9c4330',
        endDate: now(),
      },
    });
    expect(queryResult.data.reportsNumber.total).toEqual(1);
    expect(queryResult.data.reportsNumber.count).toEqual(1);
  });
  it('should reports distribution to be accurate', async () => {
    const queryResult = await queryAsAdmin({
      query: DISTRIBUTION_QUERY,
      variables: {
        field: 'created_by_ref.name',
        operation: 'count',
      },
    });
    expect(queryResult.data.reportsDistribution.length).toEqual(0);
  });
  it('should reports distribution by entity to be accurate', async () => {
    const queryResult = await queryAsAdmin({
      query: DISTRIBUTION_QUERY,
      variables: {
        objectId: 'ab78a62f-4928-4d5a-8740-03f0af9c4330',
        field: 'created_by_ref.name',
        operation: 'count',
      },
    });
    expect(queryResult.data.reportsDistribution[0].label).toEqual('ANSSI');
    expect(queryResult.data.reportsDistribution[0].value).toEqual(1);
  });
  it('should update report', async () => {
    const UPDATE_QUERY = gql`
      mutation ReportEdit($id: ID!, $input: EditInput!) {
        reportEdit(id: $id) {
          fieldPatch(input: $input) {
            id
            name
          }
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: UPDATE_QUERY,
      variables: { id: reportInternalId, input: { key: 'name', value: ['Report - test'] } },
    });
    expect(queryResult.data.reportEdit.fieldPatch.name).toEqual('Report - test');
  });
  it('should context patch report', async () => {
    const CONTEXT_PATCH_QUERY = gql`
      mutation ReportEdit($id: ID!, $input: EditContext) {
        reportEdit(id: $id) {
          contextPatch(input: $input) {
            id
          }
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: CONTEXT_PATCH_QUERY,
      variables: { id: reportInternalId, input: { focusOn: 'description' } },
    });
    expect(queryResult.data.reportEdit.contextPatch.id).toEqual(reportInternalId);
  });
  it('should context clean report', async () => {
    const CONTEXT_PATCH_QUERY = gql`
      mutation ReportEdit($id: ID!) {
        reportEdit(id: $id) {
          contextClean {
            id
          }
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: CONTEXT_PATCH_QUERY,
      variables: { id: reportInternalId },
    });
    expect(queryResult.data.reportEdit.contextClean.id).toEqual(reportInternalId);
  });
  it('should add relation in report', async () => {
    const RELATION_ADD_QUERY = gql`
      mutation ReportEdit($id: ID!, $input: RelationAddInput!) {
        reportEdit(id: $id) {
          relationAdd(input: $input) {
            id
            from {
              ... on Report {
                markingDefinitions {
                  edges {
                    node {
                      id
                    }
                    relation {
                      id
                    }
                  }
                }
              }
            }
          }
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: RELATION_ADD_QUERY,
      variables: {
        id: reportInternalId,
        input: {
          fromRole: 'so',
          toRole: 'marking',
          toId: '43f586bc-bcbc-43d1-ab46-43e5ab1a2c46',
          through: 'object_marking_refs',
        },
      },
    });
    expect(queryResult.data.reportEdit.relationAdd.from.markingDefinitions.edges.length).toEqual(1);
    reportMarkingDefinitionRelationId =
      queryResult.data.reportEdit.relationAdd.from.markingDefinitions.edges[0].relation.id;
  });
  it('should delete relation in report', async () => {
    const RELATION_DELETE_QUERY = gql`
      mutation ReportEdit($id: ID!, $relationId: ID!) {
        reportEdit(id: $id) {
          relationDelete(relationId: $relationId) {
            id
            markingDefinitions {
              edges {
                node {
                  id
                }
              }
            }
          }
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: RELATION_DELETE_QUERY,
      variables: {
        id: reportInternalId,
        relationId: reportMarkingDefinitionRelationId,
      },
    });
    expect(queryResult.data.reportEdit.relationDelete.markingDefinitions.edges.length).toEqual(0);
  });
  it('should report deleted', async () => {
    const DELETE_QUERY = gql`
      mutation reportDelete($id: ID!) {
        reportEdit(id: $id) {
          delete
        }
      }
    `;
    // Delete the report
    await queryAsAdmin({
      query: DELETE_QUERY,
      variables: { id: reportInternalId },
    });
    // Verify is no longer found
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: reportStixId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.report).toBeNull();
  });
});
