import gql from 'graphql-tag';
import { beforeAll, describe, expect, it } from 'vitest';
import { now } from 'moment';
import { ADMIN_USER, buildStandardUser, ONE_MINUTE, queryAsAdmin, testContext } from '../../utils/testQuery';
import { FilterMode, FilterOperator, PirType, StatsOperation } from '../../../src/generated/graphql';
import { SYSTEM_USER } from '../../../src/utils/access';
import { internalLoadById, pageEntitiesConnection, pageRelationsConnection } from '../../../src/database/middleware-loader';
import { ENTITY_TYPE_MALWARE } from '../../../src/schema/stixDomainObject';
import type { BasicStoreEntity } from '../../../src/types/store';
import { ABSTRACT_STIX_DOMAIN_OBJECT } from '../../../src/schema/general';
import { resetCacheForEntity } from '../../../src/database/cache';
import { type BasicStoreRelationPir, ENTITY_TYPE_PIR } from '../../../src/modules/pir/pir-types';
import { RELATION_IN_PIR } from '../../../src/schema/internalRelationship';
import { connectorsForWorker } from '../../../src/database/repository';
import { pirRelationshipsDistribution, pirRelationshipsMultiTimeSeries } from '../../../src/modules/pir/pir-domain';
import { ENTITY_TYPE_IDENTITY_ORGANIZATION } from '../../../src/modules/organization/organization-types';
import { LAST_PIR_SCORE_DATE_FILTER, PIR_SCORE_FILTER } from '../../../src/utils/filtering/filtering-constants';

const LIST_QUERY = gql`
  query pirs(
    $first: Int
    $after: ID
    $filters: FilterGroup
    $search: String
  ) {
    pirs(
      first: $first
      after: $after
      filters: $filters
      search: $search
    ) {
      edges {
        node {
          id
          name
          pir_type
          pir_filters
          pir_criteria {
            weight
            filters
          }
        }
      }
    }
  }
`;

const LIST_RELS_QUERY = gql`
  query pirRelationships(
    $pirId: ID!
    $filters: FilterGroup
  ) {
    pirRelationships(
      pirId: $pirId
      filters: $filters
    ) {
      edges {
        node {
          id
          from {
            id
          }
          to {
            id
          }
          ... on PirRelationship {
            pir_explanation {
              dependencies {
                element_id
                author_id
              }
              criterion {
                filters
                weight
              }
            }
            pir_score
          }
        }
      }
    }
  }
`;

const READ_QUERY = gql`
  query pir($id: ID!) {
    pir(id: $id) {
      id
      standard_id
      name
      pir_type
      pir_criteria {
        weight
        filters
      }
      pir_filters
    }
  }
`;

const MALWARE_QUERY = gql`
  query malware($id: String, $pirId: ID!) {
    malware(id: $id) {
      id
      entity_type
      refreshed_at
      pirInformation(pirId: $pirId) {
        pir_score
        last_pir_score_date
        pir_explanation {
          criterion {
            filters
          }
        }
      }
    }
  }
`;

describe('PIR resolver standard behavior', () => {
  let pirInternalId1: string = '';
  let pirInternalId2: string = '';
  let flaggedElementId: string = '';
  const userUpdate = buildStandardUser([], [], [{ name: 'KNOWLEDGE_KNUPDATE' }]);
  let relationshipAuthorId: string = ''; // id of Allied Universal

  beforeAll(async () => {
    const author = await internalLoadById<BasicStoreEntity>(
      testContext,
      SYSTEM_USER,
      'identity--732421a0-8471-52de-8d9f-18c8b260813c',
      { type: ENTITY_TYPE_IDENTITY_ORGANIZATION },
    );
    relationshipAuthorId = author.id;
  });

  it('should pir created', async () => {
    const CREATE_QUERY = gql`
      mutation PirAdd($input: PirAddInput!) {
        pirAdd(input: $input) {
          id
          standard_id
          name
        }
      }
    `;
    // Create the PIRs
    const PIR_TO_CREATE_1 = {
      input: {
        name: 'MyPir1',
        pir_type: PirType.ThreatLandscape,
        pir_rescan_days: 30,
        pir_filters: {
          mode: FilterMode.And,
          filterGroups: [],
          filters: [
            { key: ['confidence'], values: ['80'], operator: FilterOperator.Gt }
          ]
        },
        pir_criteria: [
          {
            weight: 2,
            filters: {
              mode: FilterMode.And,
              filterGroups: [],
              filters: [
                { key: ['toId'], values: ['24b6365f-dd85-4ee3-a28d-bb4b37e1619c'] }
              ]
            },
          },
          {
            weight: 1,
            filters: {
              mode: FilterMode.And,
              filterGroups: [],
              filters: [
                { key: ['toId'], values: ['d17360d5-0b58-4a21-bebc-84aa5a3f32b4'] }
              ]
            },
          },
        ]
      },
    };
    const PIR_TO_CREATE_2 = {
      input: {
        name: 'MyPir2',
        pir_type: PirType.ThreatLandscape,
        pir_rescan_days: 0,
        pir_filters: {
          mode: FilterMode.And,
          filterGroups: [],
          filters: [
            { key: ['confidence'], values: ['60'], operator: FilterOperator.Gt }
          ]
        },
        pir_criteria: [
          {
            weight: 1,
            filters: {
              mode: FilterMode.And,
              filterGroups: [],
              filters: [
                { key: ['toId'], values: ['d17360d5-0b58-4a21-bebc-84aa5a3f32b4'] } // this id is also present in pir1 criteria
              ]
            },
          },
          {
            weight: 1,
            filters: {
              mode: FilterMode.And,
              filterGroups: [],
              filters: [
                { key: ['toId'], values: ['527e5e30-02c5-4ba9-a698-45954d1f3763'] }
              ]
            },
          },
        ]
      },
    };
    const pir1 = await queryAsAdmin({
      query: CREATE_QUERY,
      variables: PIR_TO_CREATE_1,
    });
    const pir2 = await queryAsAdmin({
      query: CREATE_QUERY,
      variables: PIR_TO_CREATE_2,
    });
    expect(pir1).not.toBeNull();
    expect(pir1.data?.pirAdd).not.toBeNull();
    expect(pir1.data?.pirAdd.name).toEqual('MyPir1');
    pirInternalId1 = pir1.data?.pirAdd.id;
    expect(pir2.data?.pirAdd.name).toEqual('MyPir2');
    pirInternalId2 = pir2.data?.pirAdd.id;
    // reset cache for Pir
    resetCacheForEntity(ENTITY_TYPE_PIR);
  });

  it('should pir loaded by internal id', async () => {
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: pirInternalId1 } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data?.pir).not.toBeNull();
    expect(queryResult.data?.pir.id).toEqual(pirInternalId1);
    expect(queryResult.data?.pir.pir_type).toEqual(PirType.ThreatLandscape);
    expect(queryResult.data?.pir.pir_criteria.length).toEqual(2);
    expect(queryResult.data?.pir.pir_criteria[0].weight).toEqual(2);
    expect(JSON.parse(queryResult.data?.pir.pir_criteria[0].filters).filters[0].key[0]).toEqual('toId');
  });

  it('should list pirs', async () => {
    const queryResult = await queryAsAdmin({ query: LIST_QUERY, variables: { first: 10 } });
    expect(queryResult.data?.pirs.edges.length).toEqual(2);
  });

  it('should exist associated pir connector queue for worker', async () => {
    const connectors = await connectorsForWorker(testContext, ADMIN_USER);
    const pirConnectors = connectors.filter((c) => c.id === pirInternalId1);
    expect(pirConnectors.length).toEqual(1);
  });

  it('should update a pir', async () => {
    const UPDATE_QUERY = gql`
      mutation PirUpdate($id: ID!, $input: [EditInput!]!) {
        pirFieldPatch(id: $id, input: $input) {
          id
          standard_id
          name
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: UPDATE_QUERY,
      variables: { id: pirInternalId1, input: [{ key: 'name', value: ['myPirNewName'] }] },
    });
    expect(queryResult.data?.pirFieldPatch.name).toEqual('myPirNewName');
  });

  it('should not update some pir fields', async () => {
    const UPDATE_QUERY = gql`
      mutation PirUpdate($id: ID!, $input: [EditInput!]!) {
        pirFieldPatch(id: $id, input: $input) {
          id
          standard_id
          name
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: UPDATE_QUERY,
      variables: { id: pirInternalId1, input: [{ key: 'pir_filters', value: [undefined] }] },
    });
    expect(queryResult.errors?.[0].message).toEqual('Error while updating the PIR, invalid or forbidden key.');
  });

  it('should not fetch pir relationships for a not accessible Pir', async () => {
    // Verify in-pir relations are not accessible for a not accessible Pir
    const relationshipsQueryResult = await queryAsAdmin({
      query: LIST_RELS_QUERY,
      variables: { pirId: 'fakeId' },
    });
    expect(relationshipsQueryResult).not.toBeNull();
    expect(relationshipsQueryResult.errors?.length).toEqual(1);
    expect(relationshipsQueryResult.errors?.[0].message).toEqual('No PIR found');
  });

  it('should flag an element and create a pir relationship', async () => {
    // fetch an element standard id
    const malware = await internalLoadById<BasicStoreEntity>(
      testContext,
      SYSTEM_USER,
      'malware--c6006dd5-31ca-45c2-8ae0-4e428e712f88',
      { type: ENTITY_TYPE_MALWARE },
    );
    flaggedElementId = malware.id;
    // flag the element
    const flagStartDatetime = now();
    const FLAG_QUERY = gql`
      mutation pirFlagElement($id: ID!, $input: PirFlagElementInput!) {
        pirFlagElement(id: $id, input: $input)
      }
    `;
    const relationshipId = 'relationship1';
    const matchingCriteria = {
      filters: {
        mode: FilterMode.And,
        filters: [
          { key: ['toId'], values: ['24b6365f-dd85-4ee3-a28d-bb4b37e1619c'] }
        ],
        filterGroups: [],
      },
      weight: 2,
    };
    await queryAsAdmin({
      query: FLAG_QUERY,
      variables: { id: pirInternalId1, input: { relationshipId, sourceId: flaggedElementId, matchingCriteria, relationshipAuthorId } },
    });
    // Verify the in-pir relation has been created
    const queryResult = await queryAsAdmin({
      query: LIST_RELS_QUERY,
      variables: { pirId: pirInternalId1 },
    });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data?.pirRelationships.edges.length).toEqual(1);
    expect(queryResult.data?.pirRelationships.edges[0].node.from.id).toEqual(flaggedElementId);
    expect(queryResult.data?.pirRelationships.edges[0].node.to.id).toEqual(pirInternalId1);
    expect(queryResult.data?.pirRelationships.edges[0].node.pir_score).toEqual(67);
    expect(queryResult.data?.pirRelationships.edges[0].node.pir_explanation.length).toEqual(1);
    expect(queryResult.data?.pirRelationships.edges[0].node.pir_explanation[0].dependencies[0].element_id).toEqual(relationshipId);
    expect(queryResult.data?.pirRelationships.edges[0].node.pir_explanation[0].dependencies[0].author_id).toEqual(relationshipAuthorId);
    // Verify the pir information has been updated at the entity level
    const malwareAfterFlag = await internalLoadById<BasicStoreEntity>(
      testContext,
      SYSTEM_USER,
      'malware--c6006dd5-31ca-45c2-8ae0-4e428e712f88',
      { type: ENTITY_TYPE_MALWARE },
    );
    expect(malwareAfterFlag.pir_information).toBeDefined();
    expect(malwareAfterFlag.pir_information!.length).toEqual(1);
    expect(malwareAfterFlag.pir_information!.filter((s) => s.pir_id === pirInternalId1).length).toEqual(1);
    expect(malwareAfterFlag.pir_information!.filter((s) => s.pir_id === pirInternalId1)[0].pir_score).toEqual(67);
    // should fetch stix domain object pir information & refreshed_at
    const malwareQueryResult = await queryAsAdmin({
      query: MALWARE_QUERY,
      variables: {
        id: flaggedElementId,
        pirId: pirInternalId1,
      },
    });
    expect(malwareQueryResult.data?.malware).not.toBeNull();
    expect(flagStartDatetime < malwareQueryResult.data?.malware.refreshed_at).toBeTruthy();
    expect(malwareQueryResult.data?.malware.pirInformation.pir_score).toEqual(67);
    expect(malwareQueryResult.data?.malware.pirInformation.pir_explanation.length).toEqual(1);
    expect(malwareQueryResult.data?.malware.pirInformation.pir_explanation[0].criterion.filters).toEqual(JSON.stringify(matchingCriteria.filters));
  });

  it('should display top sources distribution for in-pir relationships', async () => {
    const args = {
      dateAttribute: 'created_at',
      field: 'pir_explanation.dependencies.author_id',
      isTo: false,
      relationship_type: ['in-pir'],
      pirId: pirInternalId1,
      operation: StatsOperation.Count,
    };
    const distribution = await pirRelationshipsDistribution(testContext, ADMIN_USER, args);
    expect(distribution.length).toEqual(1);
    expect(distribution[0].value).toEqual(1);
    expect(distribution[0].entity.entity_type).toEqual(ENTITY_TYPE_IDENTITY_ORGANIZATION);
    expect(distribution[0].entity.name).toEqual('Allied Universal');
  });

  it('should display pir relationship time series', async () => {
    // we count the number of pir relationships created in the last minute over time with intervals of 1 day
    const args = {
      interval: 'day',
      operation: StatsOperation.Count,
      relationship_type: ['in-pir'],
      startDate: now() - ONE_MINUTE, // the last minute
      timeSeriesParameters: [{ field: 'created_at', pirId: pirInternalId1 }],
    };
    const timeSeries = await pirRelationshipsMultiTimeSeries(testContext, ADMIN_USER, args);
    expect(timeSeries.length).toEqual(1);
    expect(timeSeries[0].data.length).toEqual(1); // 1 interval of 1 day between now and the last minute
    expect(timeSeries[0].data[0].value).toEqual(1); // in the last interval: 1 pir relationship created between the malware and pir1
  });

  it('should filter entities by a pir score', async () => {
    // return no entities if the pir id matches no PIR
    const filtersWithFakePirId = {
      mode: FilterMode.And,
      filters: [{
        key: [PIR_SCORE_FILTER],
        values: [
          { key: 'score', values: ['50'], operator: 'gt' },
          { key: 'pir_ids', values: ['fakeId'] },
        ],
      }],
      filterGroups: [],
    };
    await expect(async () => {
      await pageEntitiesConnection(testContext, SYSTEM_USER, [ABSTRACT_STIX_DOMAIN_OBJECT], { filters: filtersWithFakePirId });
    }).rejects.toThrowError('No PIR found');
    // return error if no pir id is provided
    const filtersInIncorrectFormat = {
      mode: FilterMode.And,
      filters: [{
        key: [PIR_SCORE_FILTER],
        values: [
          { key: 'score', values: ['50'], operator: 'gt' },
        ],
      }],
      filterGroups: [],
    };
    await expect(async () => {
      await pageEntitiesConnection(testContext, SYSTEM_USER, [ABSTRACT_STIX_DOMAIN_OBJECT], { filters: filtersInIncorrectFormat });
    }).rejects.toThrowError('This filter should be related to at least 1 Pir');
    // return error if the pir is not accessible for the user
    const filtersWithGtOperator = {
      mode: FilterMode.And,
      filters: [{
        key: [PIR_SCORE_FILTER],
        values: [
          { key: 'score', values: ['50'], operator: 'gt' },
          { key: 'pir_ids', values: [pirInternalId1] },
        ],
      }],
      filterGroups: [],
    };
    await expect(async () => {
      await pageEntitiesConnection(testContext, userUpdate, [ABSTRACT_STIX_DOMAIN_OBJECT], { filters: filtersWithGtOperator });
    }).rejects.toThrowError('Unauthorized Pir access');
    // fetch entities with a score > 50 for a given PIR
    const stixDomainObjects1 = await pageEntitiesConnection(testContext, SYSTEM_USER, [ABSTRACT_STIX_DOMAIN_OBJECT], { filters: filtersWithGtOperator });
    expect(stixDomainObjects1.edges.length).toEqual(1);
    expect(stixDomainObjects1.edges[0].node.internal_id).toEqual(flaggedElementId);
    // fetch entities with a score < 50 for a given PIR
    const filtersWithLtOperator = {
      mode: FilterMode.And,
      filters: [{
        key: [PIR_SCORE_FILTER],
        values: [
          { key: 'score', values: ['50'], operator: 'lt' },
          { key: 'pir_ids', values: [pirInternalId1] },
        ],
      }],
      filterGroups: [],
    };
    const stixDomainObjects2 = await pageEntitiesConnection(testContext, SYSTEM_USER, [ABSTRACT_STIX_DOMAIN_OBJECT], { filters: filtersWithLtOperator });
    expect(stixDomainObjects2.edges.length).toEqual(0);
  });

  it('should filter entities by last pir score date', async () => {
    // return no entities if the pir id matches no PIR
    const filtersWithFakePirId = {
      mode: FilterMode.And,
      filters: [{
        key: [LAST_PIR_SCORE_DATE_FILTER],
        values: [
          { key: 'date', values: [now().toString()], operator: 'lt' },
          { key: 'pir_ids', values: ['fakeId'] },
        ],
      }],
      filterGroups: [],
    };
    await expect(async () => {
      await pageEntitiesConnection(testContext, SYSTEM_USER, [ABSTRACT_STIX_DOMAIN_OBJECT], { filters: filtersWithFakePirId });
    }).rejects.toThrowError('No PIR found');
    // return error if no pir id is provided
    const filtersInIncorrectFormat = {
      mode: FilterMode.And,
      filters: [{
        key: [LAST_PIR_SCORE_DATE_FILTER],
        values: [
          { key: 'date', values: [now().toString()], operator: 'lt' },
        ],
      }],
      filterGroups: [],
    };
    await expect(async () => {
      await pageEntitiesConnection(testContext, SYSTEM_USER, [ABSTRACT_STIX_DOMAIN_OBJECT], { filters: filtersInIncorrectFormat });
    }).rejects.toThrowError('This filter should be related to at least 1 Pir');
    // fetch entities scored before now for the pir
    const filtersWithLtOperator = {
      mode: FilterMode.And,
      filters: [{
        key: [LAST_PIR_SCORE_DATE_FILTER],
        values: [
          { key: 'date', values: [now().toString()], operator: 'lt' },
          { key: 'pir_ids', values: [pirInternalId1] },
        ],
      }],
      filterGroups: [],
    };
    const stixDomainObjects1 = await pageEntitiesConnection(testContext, SYSTEM_USER, [ABSTRACT_STIX_DOMAIN_OBJECT], { filters: filtersWithLtOperator });
    expect(stixDomainObjects1.edges.length).toEqual(1);
    expect(stixDomainObjects1.edges[0].node.internal_id).toEqual(flaggedElementId);
    // fetch entities scored after now for the pir
    const filtersWithGtOperator = {
      mode: FilterMode.And,
      filters: [{
        key: [LAST_PIR_SCORE_DATE_FILTER],
        values: [
          { key: 'date', values: [now().toString()], operator: 'gt' },
          { key: 'pir_ids', values: [pirInternalId1] },
        ],
      }],
      filterGroups: [],
    };
    const stixDomainObjects2 = await pageEntitiesConnection(testContext, SYSTEM_USER, [ABSTRACT_STIX_DOMAIN_OBJECT], { filters: filtersWithGtOperator });
    expect(stixDomainObjects2.edges.length).toEqual(0);
    // fetch entities scored today
    const filtersWithinToday = {
      mode: FilterMode.And,
      filters: [{
        key: [LAST_PIR_SCORE_DATE_FILTER],
        values: [
          { key: 'date', values: ['now-1d', 'now'], operator: 'within' },
          { key: 'pir_ids', values: [pirInternalId1] },
        ],
      }],
      filterGroups: [],
    };
    const stixDomainObjects3 = await pageEntitiesConnection(testContext, SYSTEM_USER, [ABSTRACT_STIX_DOMAIN_OBJECT], { filters: filtersWithinToday });
    expect(stixDomainObjects3.edges.length).toEqual(1);
    expect(stixDomainObjects3.edges[0].node.internal_id).toEqual(flaggedElementId);
    // fetch entities scored tomorrow
    const filtersWithinTomorrow = {
      mode: FilterMode.And,
      filters: [{
        key: [LAST_PIR_SCORE_DATE_FILTER],
        values: [
          { key: 'date', values: ['now', 'now+1d'], operator: 'within' },
          { key: 'pir_ids', values: [pirInternalId1] },
        ],
      }],
      filterGroups: [],
    };
    const stixDomainObjects4 = await pageEntitiesConnection(testContext, SYSTEM_USER, [ABSTRACT_STIX_DOMAIN_OBJECT], { filters: filtersWithinTomorrow });
    expect(stixDomainObjects4.edges.length).toEqual(0);
  });

  it('should update a pir relationship by adding a new explanation', async () => {
    const FLAG_QUERY = gql`
      mutation pirFlagElement($id: ID!, $input: PirFlagElementInput!) {
        pirFlagElement(id: $id, input: $input)
      }
    `;
    const relationshipId = 'relationship2';
    // a criteria matching both Pir1 and Pir2
    const matchingCriteria = {
      filters: {
        mode: FilterMode.And,
        filterGroups: [],
        filters: [
          { key: ['toId'], values: ['d17360d5-0b58-4a21-bebc-84aa5a3f32b4'] }
        ]
      },
      weight: 1,
    };
    await Promise.all([
      queryAsAdmin({
        query: FLAG_QUERY,
        variables: { id: pirInternalId1, input: { relationshipId, sourceId: flaggedElementId, matchingCriteria } },
      }),
      queryAsAdmin({
        query: FLAG_QUERY,
        variables: { id: pirInternalId2, input: { relationshipId, sourceId: flaggedElementId, matchingCriteria } },
      }),
    ]);
    // Verify the in-pir rel has been updated
    const queryResult = await queryAsAdmin({
      query: LIST_RELS_QUERY,
      variables: { pirId: pirInternalId1 },
    });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data?.pirRelationships.edges.length).toEqual(1);
    expect(queryResult.data?.pirRelationships.edges[0].node.from.id).toEqual(flaggedElementId);
    expect(queryResult.data?.pirRelationships.edges[0].node.to.id).toEqual(pirInternalId1);
    expect(queryResult.data?.pirRelationships.edges[0].node.pir_score).toEqual(100);
    expect(queryResult.data?.pirRelationships.edges[0].node.pir_explanation.length).toEqual(2);
    // Verify the pir information has been updated at the entity level for all the PIRs concerned
    const malwareAfterFlag = await internalLoadById<BasicStoreEntity>(
      testContext,
      SYSTEM_USER,
      'malware--c6006dd5-31ca-45c2-8ae0-4e428e712f88',
      { type: ENTITY_TYPE_MALWARE },
    );

    expect(malwareAfterFlag.pir_information).toBeDefined();
    expect(malwareAfterFlag.pir_information!.length).toEqual(2);
    expect(malwareAfterFlag.pir_information!.filter((s) => s.pir_id === pirInternalId1).length).toEqual(1);
    expect(malwareAfterFlag.pir_information!.filter((s) => s.pir_id === pirInternalId1)[0].pir_score).toEqual(100);
    expect(malwareAfterFlag.pir_information!.filter((s) => s.pir_id === pirInternalId2).length).toEqual(1);
    expect(malwareAfterFlag.pir_information!.filter((s) => s.pir_id === pirInternalId2)[0].pir_score).toEqual(50);
  });

  it('should update a pir relationship by removing an explanation', async () => {
    const UNFLAG_QUERY = gql`
      mutation pirUnflagElement($id: ID!, $input: PirUnflagElementInput!) {
        pirUnflagElement(id: $id, input: $input)
      }
    `;
    const relationshipId = 'relationship2';
    await queryAsAdmin({
      query: UNFLAG_QUERY,
      variables: { id: pirInternalId1, input: { relationshipId, sourceId: flaggedElementId } },
    });
    // Verify the in-pir rel has been updated
    const queryResult = await queryAsAdmin({
      query: LIST_RELS_QUERY,
      variables: { pirId: pirInternalId1 },
    });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data?.pirRelationships.edges.length).toEqual(1);
    expect(queryResult.data?.pirRelationships.edges[0].node.from.id).toEqual(flaggedElementId);
    expect(queryResult.data?.pirRelationships.edges[0].node.to.id).toEqual(pirInternalId1);
    expect(queryResult.data?.pirRelationships.edges[0].node.pir_score).toEqual(67);
    expect(queryResult.data?.pirRelationships.edges[0].node.pir_explanation.length).toEqual(1);
  });

  it('should unflag an element', async () => {
    const UNFLAG_QUERY = gql`
      mutation pirUnflagElement($id: ID!, $input: PirUnflagElementInput!) {
        pirUnflagElement(id: $id, input: $input)
      }
    `;
    const relationshipId = 'relationship1';
    await queryAsAdmin({
      query: UNFLAG_QUERY,
      variables: { id: pirInternalId1, input: { relationshipId, sourceId: flaggedElementId } },
    });
    // Verify the in-pir rel has been deleted
    const queryResult = await queryAsAdmin({
      query: LIST_RELS_QUERY,
      variables: { pirId: pirInternalId1 },
    });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data?.pirRelationships.edges.length).toEqual(0);
  });

  it('should pir deleted', async () => {
    const DELETE_QUERY = gql`
      mutation pirDelete($id: ID!) {
        pirDelete(id: $id)
      }
    `;
    // Delete the PIRs
    await queryAsAdmin({
      query: DELETE_QUERY,
      variables: { id: pirInternalId1 },
    });
    await queryAsAdmin({
      query: DELETE_QUERY,
      variables: { id: pirInternalId2 },
    });
    // Verify the in-pir relations have been deleted
    const pirRelations = await pageRelationsConnection<BasicStoreRelationPir>(testContext, SYSTEM_USER, RELATION_IN_PIR, { toId: [pirInternalId1] });
    expect(pirRelations).not.toBeNull();
    expect(pirRelations.edges.length).toEqual(0);
    // Verify the pir information has been removed for the PIR at entities levels
    const malwareAfterFlag = await internalLoadById<BasicStoreEntity>(
      testContext,
      SYSTEM_USER,
      'malware--c6006dd5-31ca-45c2-8ae0-4e428e712f88',
      { type: ENTITY_TYPE_MALWARE },
    );
    expect(malwareAfterFlag.pir_information).toBeDefined();
    expect(malwareAfterFlag.pir_information!.length).toEqual(0);
    // Verify the associated connector queue is no longer found
    const connectors = await connectorsForWorker(testContext, ADMIN_USER);
    const pirConnector = connectors.filter((c) => c.id === pirInternalId1 || c.id === pirInternalId2);
    expect(pirConnector.length).toEqual(0);
    // Verify the PIR is no longer found
    let queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: pirInternalId1 } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data?.pir).toBeNull();
    queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: pirInternalId2 } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data?.pir).toBeNull();
  });
});
