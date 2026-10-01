import { describe, expect, it } from 'vitest';
import * as R from 'ramda';
import gql from 'graphql-tag';
import { queryAsAdmin } from '../../utils/testQueryHelper';
import { isStixCoreObject } from '../../../src/schema/stixCoreObject';
import { isStixCoreRelationship } from '../../../src/schema/stixCoreRelationship';
import { isStixRefRelationship } from '../../../src/schema/stixRefRelationship';
import { addFilter } from '../../../src/utils/filtering/filtering-utils';

const REPORT_RELATIONSHIPS_QUERY = gql`
  query paginatedReportRelationships($filters: FilterGroup!, $first: Int!, $after: ID) {
    stixCoreRelationships(filters: $filters, first: $first, after: $after, orderBy: created_at, orderMode: asc) {
      edges {
        node {
          id
          relationship_type
          confidence
          from { ... on BasicObject { id } }
          to { ... on BasicObject { id } }
        }
      }
      pageInfo {
        endCursor
        hasNextPage
        globalCount
      }
    }
  }
`;

type ReportRelationship = {
  id: string;
  relationship_type: string;
  confidence: number;
};

describe('Container resolver standard behavior', () => {
  const REPORT_RAW_ID = 'report--a445d22a-db0c-4b5d-9ec8-e9ad0b6dbdd7';
  const REPORT_ID = 'report--f3e554eb-60f5-587c-9191-4f25e9ba9f32';

  it('should container loaded by internal id', async () => {
    const queryResult = await queryAsAdmin(
      {
        query: gql`
          query container($id: String!) {
            container(id: $id) {
              id
              standard_id
            }
          }
        `,
        variables: { id: REPORT_RAW_ID },
      },
    );
    expect(queryResult).not.toBeNull();
    expect(queryResult.data?.container).not.toBeNull();
    expect(queryResult.data?.container.standard_id).toEqual(REPORT_ID);
  });

  it('should containers list loaded', async () => {
    const queryResult = await queryAsAdmin(
      {
        query: gql`
            query containers {
              containers(first: 1, orderBy: created, orderMode: asc) {
                edges {
                  node {
                    standard_id
                    entity_type
                  }
                }
              }
            }
          `,
      },
    );
    expect(queryResult).not.toBeNull();
    expect(queryResult.data?.containers).not.toBeNull();
    expect(queryResult.data?.containers.edges.length).toEqual(1);
    expect(queryResult.data?.containers.edges[0].node.standard_id).toEqual('report--01d982e0-4850-5e0c-b3cc-c9a25c1cf1b8');
  });

  it('should malware containersNumber accurate', async () => {
    const queryResult = await queryAsAdmin(
      {
        query: gql`
            query malware {
              attackPattern(id: "attack-pattern--2fc04aa5-48c1-49ec-919a-b88241ef1d17") {
                standard_id
                containersNumber {
                  count
                  total
                }
              }
            }
          `,
      },
    );
    expect(queryResult).not.toBeNull();
    expect(queryResult.data?.attackPattern).not.toBeNull();
    expect(queryResult.data?.attackPattern.standard_id).toEqual('attack-pattern--b7f107ad-4327-5546-8eaf-d4139cd57498');
    expect(queryResult.data?.attackPattern.containersNumber.count).toEqual(1);
    expect(queryResult.data?.attackPattern.containersNumber.total).toEqual(1);
  });

  it('should container objects loaded', async () => {
    const queryResult = await queryAsAdmin(
      {
        query: gql`
            query container($id: String!) {
              container(id: $id) {
                id
                standard_id
                relatedContainers {
                  edges {
                     node {
                       standard_id
                     }
                  }
                }
                numberOfConnectedElement
                objects(first: 1, orderBy: created, orderMode: asc) {
                  edges {
                    node {
                      __typename
                      ... on StixCoreRelationship {
                        id
                        standard_id
                      }
                      ... on StixCoreObject {
                        id
                        standard_id
                      }
                    }
                  }
                }
              }
            }
          `,
        variables: { id: REPORT_RAW_ID },
      },
    );
    expect(queryResult).not.toBeNull();
    expect(queryResult.data?.container).not.toBeNull();
    expect(queryResult.data?.container.standard_id).toEqual(REPORT_ID);
    expect(queryResult.data?.container.numberOfConnectedElement).toEqual(29);
    expect(queryResult.data?.container.relatedContainers.edges.length).toEqual(4);
    expect(queryResult.data?.container.objects.edges.length).toEqual(1);
  });

  it('should container frst 1 object', async () => {
    const queryResult = await queryAsAdmin(
      {
        query: gql`
            query container($id: String!) {
              container(id: $id) {
                id
                standard_id
                objects(first: 1, orderBy: created, orderMode: asc) {
                  edges {
                    node {
                      __typename
                      ... on StixCoreRelationship {
                        id
                        standard_id
                      }
                      ... on StixCoreObject {
                        id
                        standard_id
                      }
                    }
                  }
                }
              }
            }
          `,
        variables: { id: REPORT_RAW_ID },
      },
    );
    expect(queryResult).not.toBeNull();
    expect(queryResult.data?.container).not.toBeNull();
    expect(queryResult.data?.container.standard_id).toEqual(REPORT_ID);
    expect(queryResult.data?.container.objects.edges.length).toEqual(1);
  });

  it('should container all objects', async () => {
    const queryResult = await queryAsAdmin(
      {
        query: gql`
            query container($id: String!) {
              container(id: $id) {
                id
                standard_id
                objects(all: true, first: 10, orderBy: created, orderMode: asc) {
                  edges {
                    node {
                      ... on StixCoreRelationship {
                        id
                        entity_type
                        standard_id
                      }
                      ... on StixCoreObject {
                        id
                        entity_type
                        standard_id
                      }
                    }
                  }
                }
              }
            }
          `,
        variables: { id: REPORT_RAW_ID },
      },
    );
    expect(queryResult).not.toBeNull();
    expect(queryResult.data?.container).not.toBeNull();
    expect(queryResult.data?.container.standard_id).toEqual(REPORT_ID);
    expect(queryResult.data?.container.objects.edges.length).toEqual(26);
    const entities = queryResult.data?.container.objects.edges.filter((e: any) => isStixCoreObject(e.node.entity_type));
    expect(entities.length).toEqual(15);
    const relationships = queryResult.data?.container.objects.edges.filter((e: any) => isStixCoreRelationship(e.node.entity_type));
    expect(relationships.length).toEqual(11);
  });

  it('should list and paginate only the core relationships referenced by a report', async () => {
    const containerResult = await queryAsAdmin({
      query: gql`
        query reportRelationships($id: String!) {
          container(id: $id) {
            id
            objects(types: ["stix-core-relationship"], first: 100) {
              edges {
                node {
                  ... on StixCoreRelationship {
                    id
                    relationship_type
                    confidence
                  }
                }
              }
            }
          }
        }
      `,
      variables: { id: REPORT_RAW_ID },
    });
    expect(containerResult.errors).toBeUndefined();
    const container = containerResult.data?.container;
    const expectedRelationships: ReportRelationship[] = container.objects.edges.map((edge: { node: ReportRelationship }) => edge.node);
    const expectedIds = expectedRelationships.map((relationship) => relationship.id);
    expect(expectedIds).toHaveLength(11);

    const filters = addFilter(undefined, 'objects', container.id);
    const firstPage = await queryAsAdmin({ query: REPORT_RELATIONSHIPS_QUERY, variables: { filters, first: 6 } });
    expect(firstPage.errors).toBeUndefined();
    const firstConnection = firstPage.data?.stixCoreRelationships;
    expect(firstConnection.edges).toHaveLength(6);
    expect(firstConnection.pageInfo.globalCount).toEqual(11);
    expect(firstConnection.pageInfo.hasNextPage).toEqual(true);

    const secondPage = await queryAsAdmin({
      query: REPORT_RELATIONSHIPS_QUERY,
      variables: { filters, first: 6, after: firstConnection.pageInfo.endCursor },
    });
    expect(secondPage.errors).toBeUndefined();
    const secondConnection = secondPage.data?.stixCoreRelationships;
    expect(secondConnection.edges).toHaveLength(5);
    expect(secondConnection.pageInfo.globalCount).toEqual(11);
    expect(secondConnection.pageInfo.hasNextPage).toEqual(false);
    const actualIds = [...firstConnection.edges, ...secondConnection.edges]
      .map((edge: { node: { id: string } }) => edge.node.id);
    expect(actualIds.sort()).toEqual(expectedIds.sort());

    const relationshipType = expectedRelationships[0].relationship_type;
    const filteredResult = await queryAsAdmin({
      query: REPORT_RELATIONSHIPS_QUERY,
      variables: { filters: addFilter(filters, 'relationship_type', relationshipType), first: 100 },
    });
    expect(filteredResult.errors).toBeUndefined();
    const filteredIds = expectedRelationships
      .filter((relationship) => relationship.relationship_type === relationshipType)
      .map((relationship) => relationship.id);
    expect(filteredResult.data?.stixCoreRelationships.pageInfo.globalCount).toEqual(filteredIds.length);
    expect(filteredResult.data?.stixCoreRelationships.edges.map((edge: { node: { id: string } }) => edge.node.id).sort())
      .toEqual(filteredIds.sort());

    const userFilters = {
      ...addFilter(undefined, 'relationship_type', relationshipType),
      mode: 'or',
      filters: [
        ...addFilter(undefined, 'relationship_type', relationshipType).filters,
        ...addFilter(undefined, 'confidence', '80', 'gte').filters,
      ],
    } as ReturnType<typeof addFilter>;
    const combinedResult = await queryAsAdmin({
      query: REPORT_RELATIONSHIPS_QUERY,
      variables: { filters: addFilter(userFilters, 'objects', container.id), first: 100 },
    });
    expect(combinedResult.errors).toBeUndefined();
    const combinedIds = expectedRelationships
      .filter((relationship) => relationship.relationship_type === relationshipType || relationship.confidence >= 80)
      .map((relationship) => relationship.id);
    expect(combinedResult.data?.stixCoreRelationships.pageInfo.globalCount).toEqual(combinedIds.length);
    expect(combinedResult.data?.stixCoreRelationships.edges.map((edge: { node: { id: string } }) => edge.node.id).sort())
      .toEqual(combinedIds.sort());
  });

  it('should require explicit report membership and preserve a shared relationship when removing it', async () => {
    const relationshipResult = await queryAsAdmin({
      query: gql`
        query sharedReportRelationship($id: String!) {
          stixCoreRelationship(id: $id) {
            id
            from { ... on BasicObject { id } }
            to { ... on BasicObject { id } }
          }
        }
      `,
      variables: { id: 'relationship--e35b3fc1-47f3-4ccb-a8fe-65a0864edd02' },
    });
    expect(relationshipResult.errors).toBeUndefined();
    const relationship = relationshipResult.data?.stixCoreRelationship;
    expect(relationship).toBeTruthy();
    const reportIds: string[] = [];
    const createReport = async (name: string, objects: string[]) => {
      const result = await queryAsAdmin({
        query: gql`
          mutation reportRelationshipListCreate($input: ReportAddInput!) {
            reportAdd(input: $input) { id }
          }
        `,
        variables: { input: { name, published: '2020-02-26T00:51:35.000Z', objects } },
      });
      if (result.data?.reportAdd?.id) reportIds.push(result.data.reportAdd.id);
      expect(result.errors).toBeUndefined();
      return result.data?.reportAdd.id as string;
    };
    const listRelationships = async (reportId: string) => {
      const result = await queryAsAdmin({
        query: REPORT_RELATIONSHIPS_QUERY,
        variables: { filters: addFilter(undefined, 'objects', reportId), first: 100 },
      });
      expect(result.errors).toBeUndefined();
      return result.data?.stixCoreRelationships;
    };

    try {
      const reportId = await createReport('Relationship list membership test', [relationship.from.id, relationship.to.id]);
      const sharedReportId = await createReport('Relationship list shared reference test', [relationship.id]);
      const initiallyEmpty = await listRelationships(reportId);
      expect(initiallyEmpty.edges).toEqual([]);
      expect(initiallyEmpty.pageInfo.globalCount).toEqual(0);

      const addResult = await queryAsAdmin({
        query: gql`
          mutation reportRelationshipListAdd($id: ID!, $input: StixRefRelationshipAddInput!) {
            reportEdit(id: $id) { relationAdd(input: $input) { id } }
          }
        `,
        variables: { id: reportId, input: { toId: relationship.id, relationship_type: 'object' } },
      });
      expect(addResult.errors).toBeUndefined();
      const afterAdd = await listRelationships(reportId);
      expect(afterAdd.edges.map((edge: { node: { id: string } }) => edge.node.id)).toEqual([relationship.id]);
      expect(afterAdd.pageInfo.globalCount).toEqual(1);

      const removeResult = await queryAsAdmin({
        query: gql`
          mutation reportRelationshipListRemove($id: ID!, $toId: StixRef!) {
            reportEdit(id: $id) { relationDelete(toId: $toId, relationship_type: "object") { id } }
          }
        `,
        variables: { id: reportId, toId: relationship.id },
      });
      expect(removeResult.errors).toBeUndefined();
      const afterRemove = await listRelationships(reportId);
      expect(afterRemove.edges).toEqual([]);
      expect(afterRemove.pageInfo.globalCount).toEqual(0);
      const sharedRelationships = await listRelationships(sharedReportId);
      expect(sharedRelationships.edges.map((edge: { node: { id: string } }) => edge.node.id)).toEqual([relationship.id]);
      expect(sharedRelationships.pageInfo.globalCount).toEqual(1);
    } finally {
      for (const reportId of reportIds) {
        const deleted = await queryAsAdmin({
          query: gql`
            mutation reportRelationshipListDelete($id: ID!) {
              reportEdit(id: $id) { delete }
            }
          `,
          variables: { id: reportId },
        });
        expect(deleted.errors).toBeUndefined();
      }
    }
  });

  it('should container containersObjectsOfObject from malware', async () => {
    const queryResult = await queryAsAdmin(
      {
        query: gql`
            query container($id: String!) {
              containersObjectsOfObject(id: $id, types: "Malware") {
                edges {
                  node {
                    __typename
                    ... on StixCoreObject {
                      entity_type
                    }
                    ... on StixRefRelationship {
                      entity_type
                      to {
                        ... on StixCoreObject {
                          standard_id
                          entity_type
                        }
                      }
                    }
                  }
                }                
              }
            }
          `,
        variables: { id: 'malware--faa5b705-cf44-4e50-8472-29e5fec43c3c' },
      },
    );
    expect(queryResult).not.toBeNull();
    expect(queryResult.data?.containersObjectsOfObject).not.toBeNull();
    expect(queryResult.data?.containersObjectsOfObject.edges.length).toEqual(9);
    const entities = queryResult.data?.containersObjectsOfObject.edges.filter((e: any) => isStixCoreObject(e.node.entity_type));
    expect(entities.length).toEqual(5);
    const relationships = queryResult.data?.containersObjectsOfObject.edges.filter((e: any) => isStixRefRelationship(e.node.entity_type));
    expect(relationships.length).toEqual(4);
    expect(R.uniq(relationships.map((r: any) => r.node.to.standard_id))).toEqual(['malware--21c45dbe-54ec-5bb7-b8cd-9f27cc518714']);
  });
});
