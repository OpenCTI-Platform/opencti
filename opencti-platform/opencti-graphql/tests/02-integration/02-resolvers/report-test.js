import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import gql from 'graphql-tag';
import { ADMIN_USER, queryAsAdmin, testContext } from '../../utils/testQuery';
import { elLoadById } from '../../../src/database/engine';
import { now } from '../../../src/utils/format';
import { fullEntitiesList } from '../../../src/database/middleware-loader';
import { ENTITY_TYPE_WORKSPACE } from '../../../src/modules/workspace/workspace-types';
import { deleteElementById } from '../../../src/database/middleware';

const LIST_QUERY = gql`
  query reports(
    $first: Int
    $after: ID
    $orderBy: ReportsOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
    $search: String
  ) {
    reports(
      first: $first
      after: $after
      orderBy: $orderBy
      orderMode: $orderMode
      filters: $filters
      search: $search
    ) {
      edges {
        node {
          id
          name
          description
          published
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
      entity {
        ... on Identity {
          name
        }
      }
    }
  }
`;

const READ_QUERY = gql`
  query report($id: String!) {
    report(id: $id) {
      id
      standard_id
      name
      description
      published
      toStix
      updated_at
      modified
    }
  }
`;

describe('Report resolver standard behavior', () => {
  let reportInternalId;
  let datasetReportInternalId;
  let datasetMalwareInternalId;
  const reportStixId = 'report--994491f0-f114-4e41-bcf0-3288c0324f53';
  it('should report created', async () => {
    const CREATE_QUERY = gql`
      mutation ReportAdd($input: ReportAddInput!) {
        reportAdd(input: $input) {
          id
          standard_id
          name
          description
          published
        }
      }
    `;
    // Create the report
    const REPORT_TO_CREATE = {
      input: {
        stix_id: reportStixId,
        name: 'Report',
        description: 'Report description',
        published: '2020-02-26T00:51:35.000Z',
        objects: [
          'campaign--92d46985-17a6-4610-8be8-cc70c82ed214',
          'relationship--e35b3fc1-47f3-4ccb-a8fe-65a0864edd02',
        ],
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
  it('should report stix objects or stix relationships accurate', async () => {
    const report = await elLoadById(testContext, ADMIN_USER, 'report--a445d22a-db0c-4b5d-9ec8-e9ad0b6dbdd7');
    datasetReportInternalId = report.internal_id;
    const REPORT_STIX_DOMAIN_ENTITIES = gql`
      query report($id: String!) {
        report(id: $id) {
          id
          standard_id
          objects(first: 30) {
            edges {
              node {
                ... on BasicObject {
                  id
                  standard_id
                }
                ... on BasicRelationship {
                  id
                  standard_id
                }
              }
            }
          }
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: REPORT_STIX_DOMAIN_ENTITIES,
      variables: { id: datasetReportInternalId },
    });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.report).not.toBeNull();
    expect(queryResult.data.report.standard_id).toEqual('report--f3e554eb-60f5-587c-9191-4f25e9ba9f32');
    expect(queryResult.data.report.objects.edges.length).toEqual(26);
  });
  it('should report contains stix object or stix relationship accurate', async () => {
    const intrusionSet = await elLoadById(testContext, ADMIN_USER, 'intrusion-set--18854f55-ac7c-4634-bd9a-352dd07613b7');
    const stixRelationship = await elLoadById(testContext, ADMIN_USER, 'relationship--9f999fc5-5c74-4964-ab87-ee4c7cdc37a3');
    const REPORT_CONTAINS_STIX_OBJECT_OR_STIX_RELATIONSHIP = gql`
      query reportContainsStixObjectOrStixRelationship($id: String!, $stixObjectOrStixRelationshipId: String!) {
        reportContainsStixObjectOrStixRelationship(
          id: $id
          stixObjectOrStixRelationshipId: $stixObjectOrStixRelationshipId
        )
      }
    `;
    let queryResult = await queryAsAdmin({
      query: REPORT_CONTAINS_STIX_OBJECT_OR_STIX_RELATIONSHIP,
      variables: {
        id: datasetReportInternalId,
        stixObjectOrStixRelationshipId: intrusionSet.internal_id,
      },
    });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.reportContainsStixObjectOrStixRelationship).not.toBeNull();
    expect(queryResult.data.reportContainsStixObjectOrStixRelationship).toBeTruthy();
    queryResult = await queryAsAdmin({
      query: REPORT_CONTAINS_STIX_OBJECT_OR_STIX_RELATIONSHIP,
      variables: {
        id: datasetReportInternalId,
        stixObjectOrStixRelationshipId: stixRelationship.internal_id,
      },
    });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.reportContainsStixObjectOrStixRelationship).not.toBeNull();
    expect(queryResult.data.reportContainsStixObjectOrStixRelationship).toBeTruthy();
  });
  it('should list reports', async () => {
    const queryResult = await queryAsAdmin({ query: LIST_QUERY, variables: { first: 10 } });
    expect(queryResult.data.reports.edges.length).toEqual(3);
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
    expect(queryResult.data.reportsTimeSeries[2].value).toEqual(1);
    expect(queryResult.data.reportsTimeSeries[3].value).toEqual(0);
  });
  it('should timeseries reports for entity to be accurate', async () => {
    const malware = await elLoadById(testContext, ADMIN_USER, 'malware--faa5b705-cf44-4e50-8472-29e5fec43c3c');
    datasetMalwareInternalId = malware.internal_id;
    const queryResult = await queryAsAdmin({
      query: TIMESERIES_QUERY,
      variables: {
        objectId: datasetMalwareInternalId,
        field: 'published',
        operation: 'count',
        startDate: '2020-01-01T00:00:00+00:00',
        endDate: '2021-01-01T00:00:00+00:00',
        interval: 'month',
      },
    });
    expect(queryResult.data.reportsTimeSeries.length).toEqual(13);
    expect(queryResult.data.reportsTimeSeries[2].value).toEqual(1);
    expect(queryResult.data.reportsTimeSeries[3].value).toEqual(0);
  });
  it('should timeseries reports for author to be accurate', async () => {
    const identity = await elLoadById(testContext, ADMIN_USER, 'identity--7b82b010-b1c0-4dae-981f-7756374a17df');
    const queryResult = await queryAsAdmin({
      query: TIMESERIES_QUERY,
      variables: {
        authorId: identity.internal_id,
        field: 'published',
        operation: 'count',
        startDate: '2020-01-01T00:00:00+00:00',
        endDate: '2021-01-01T00:00:00+00:00',
        interval: 'month',
      },
    });
    expect(queryResult.data.reportsTimeSeries.length).toEqual(13);
    expect(queryResult.data.reportsTimeSeries[2].value).toEqual(1);
    expect(queryResult.data.reportsTimeSeries[3].value).toEqual(0);
  });
  it('should reports number to be accurate', async () => {
    const queryResult = await queryAsAdmin({
      query: NUMBER_QUERY,
      variables: {
        endDate: now(),
      },
    });
    expect(queryResult.data.reportsNumber.total).toEqual(3);
    expect(queryResult.data.reportsNumber.count).toEqual(3);
  });
  it('should reports number by entity to be accurate', async () => {
    const queryResult = await queryAsAdmin({
      query: NUMBER_QUERY,
      variables: {
        objectId: datasetMalwareInternalId,
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
        field: 'created-by.internal_id',
        operation: 'count',
      },
    });
    expect(queryResult.data.reportsDistribution.length).toEqual(1);
  });
  it('should reports distribution by entity to be accurate', async () => {
    const queryResult = await queryAsAdmin({
      query: DISTRIBUTION_QUERY,
      variables: {
        objectId: datasetMalwareInternalId,
        field: 'created-by.internal_id',
        operation: 'count',
      },
    });
    const aggregationMap = new Map(queryResult.data.reportsDistribution.map((i) => [i.entity.name, i]));
    expect(aggregationMap.get('ANSSI').value).toEqual(1);
  });
  it('should update report', async () => {
    const UPDATE_QUERY = gql`
      mutation ReportEdit($id: ID!, $input: [EditInput]!) {
        reportEdit(id: $id) {
          fieldPatch(input: $input) {
            id
            name
            description
            published
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
  it('should update report with invalid published date fail', async () => {
    const UPDATE_QUERY = gql`
      mutation ReportEdit($id: ID!, $input: [EditInput]!) {
        reportEdit(id: $id) {
          fieldPatch(input: $input) {
            id
            name
            description
            published
          }
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: UPDATE_QUERY,
      variables: { id: reportInternalId, input: { key: 'published', value: ['2025-02-01'] } },
    });
    expect(queryResult.errors).toBeDefined();
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
      mutation ReportEdit($id: ID!, $input: StixRefRelationshipAddInput!) {
        reportEdit(id: $id) {
          relationAdd(input: $input) {
            id
            from {
              ... on Report {
                objectMarking {
                  id
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
          toId: 'marking-definition--78ca4366-f5b8-4764-83f7-34ce38198e27',
          relationship_type: 'object-marking',
        },
      },
    });
    expect(queryResult.data.reportEdit.relationAdd.from.objectMarking.length).toEqual(1);
  });
  it('should delete relation in report', async () => {
    const RELATION_DELETE_QUERY = gql`
      mutation ReportEdit($id: ID!, $toId: StixRef!, $relationship_type: String!) {
        reportEdit(id: $id) {
          relationDelete(toId: $toId, relationship_type: $relationship_type) {
            id
            objectMarking {
              id
            }
          }
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: RELATION_DELETE_QUERY,
      variables: {
        id: reportInternalId,
        toId: 'marking-definition--78ca4366-f5b8-4764-83f7-34ce38198e27',
        relationship_type: 'object-marking',
      },
    });
    expect(queryResult.data.reportEdit.relationDelete.objectMarking.length).toEqual(0);
  });
  describe('investigationAdd', () => {
    let investigationId;

    const investigationAdd = async () => {
      return await queryAsAdmin({
        query: gql`
          mutation InvestigationAddFromReport($id: ID!) {
            containerEdit(id: $id) {
              investigationAdd {
                id
              }
            }
          }
        `,
        variables: {
          id: reportInternalId
        },
      });
    };

    beforeAll(async () => {
      const test = (await investigationAdd());
      investigationId = test.data.containerEdit.investigationAdd.id;
    });

    afterAll(async () => {
      const investigations = await fullEntitiesList(
        testContext,
        ADMIN_USER,
        [ENTITY_TYPE_WORKSPACE],
        {
          filters: {
            mode: 'and',
            filters: [{
              key: ['type'],
              values: ['investigation'],
            }],
            filterGroups: [],
          },
          noFiltersChecking: true
        },
      );
      await Promise.all(investigations.map(({ id }) => deleteElementById(testContext, ADMIN_USER, id, ENTITY_TYPE_WORKSPACE)));
    });

    it('can start an investigation', () => {
      expect(investigationId).toBeDefined();
    });
  });

  describe('When adding an observable to a report', () => {
    it('should add the observable and update updated_at and modified', async () => {
      const RELATION_ADD_OBSERVABLE_QUERY = gql`
      mutation ReportEdit($id: ID!, $input: StixRefRelationshipAddInput!) {
        reportEdit(id: $id) {
          relationAdd(input: $input) {
            id
            from {
            ... on Report {
                  id
                  }
            }
            to {
            ... on Software {
                  id
                }
            }
          }
        }
      }
    `;

      const readQueryResultBefore = await queryAsAdmin({ query: READ_QUERY, variables: { id: reportInternalId } });

      const queryResult = await queryAsAdmin({
        query: RELATION_ADD_OBSERVABLE_QUERY,
        variables: {
          id: reportInternalId,
          input: {
            toId: 'software--b0debdba-74e7-4463-ad2a-34334ee66d8d', // id of a software in DATA-TEST-STIX2_v2.json
            relationship_type: 'object',
          },
        },
      });

      const readQueryResultAfter = await queryAsAdmin({ query: READ_QUERY, variables: { id: reportInternalId } });

      expect(queryResult.data.reportEdit.relationAdd.from.id).toEqual(reportInternalId);

      expect(readQueryResultBefore.data.report.updated_at < readQueryResultAfter.data.report.updated_at).toBeTruthy();
      expect(readQueryResultBefore.data.report.modified < readQueryResultAfter.data.report.modified).toBeTruthy();
    });
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
