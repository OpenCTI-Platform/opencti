import { describe, expect, it } from 'vitest';
import * as R from 'ramda';
import gql from 'graphql-tag';
import { queryAsAdmin } from '../../utils/testQuery';
import { isStixCoreObject } from '../../../src/schema/stixCoreObject';
import { isStixCoreRelationship } from '../../../src/schema/stixCoreRelationship';
import { isStixRefRelationship } from '../../../src/schema/stixRefRelationship';

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
        variables: { id: REPORT_RAW_ID }
      }
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
      }
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
      }
    );
    expect(queryResult).not.toBeNull();
    expect(queryResult.data?.attackPattern).not.toBeNull();
    expect(queryResult.data?.attackPattern.standard_id).toEqual('attack-pattern--a01046cc-192f-5d52-8e75-6e447fae3890');
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
        variables: { id: REPORT_RAW_ID }
      }
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
        variables: { id: REPORT_RAW_ID }
      }
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
        variables: { id: REPORT_RAW_ID }
      }
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
        variables: { id: 'malware--faa5b705-cf44-4e50-8472-29e5fec43c3c' }
      }
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
