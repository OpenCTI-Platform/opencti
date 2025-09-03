import gql from 'graphql-tag';
import { describe, expect, it } from 'vitest';
import { now } from 'moment';
import { ADMIN_USER, queryAsAdmin, testContext } from '../../utils/testQuery';
import { FilterMode, FilterOperator, PirType } from '../../../src/generated/graphql';
import { RESTRICTED_USER, SYSTEM_USER } from '../../../src/utils/access';
import { internalLoadById, listEntitiesPaginated, listRelationsPaginated } from '../../../src/database/middleware-loader';
import { ENTITY_TYPE_MALWARE } from '../../../src/schema/stixDomainObject';
import type { BasicStoreEntity } from '../../../src/types/store';
import { addFilter } from '../../../src/utils/filtering/filtering-utils';
import { ABSTRACT_STIX_DOMAIN_OBJECT } from '../../../src/schema/general';
import { LAST_PIR_SCORE_DATE_FILTER_PREFIX, PIR_SCORE_FILTER_PREFIX } from '../../../src/utils/filtering/filtering-constants';
import { resetCacheForEntity } from '../../../src/database/cache';
import { type BasicStoreRelationPir, ENTITY_TYPE_PIR } from '../../../src/modules/pir/pir-types';
import { RELATION_IN_PIR } from '../../../src/schema/internalRelationship';
import { connectorsForWorker } from '../../../src/database/repository';

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
            pir_explanations {
              dependencies {
                element_id
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
      pirInformation(pirId: $pirId) {
        pir_score
        last_pir_score_date
        pir_explanations {
          criterion {
            filters
          }
        }
      }
    }
  }
`;

describe('PIR resolver standard behavior', () => {
  let pirInternalId: string = '';
  let flaggedElementId: string = '';

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
    // Create the pir
    const PIR_TO_CREATE = {
      input: {
        name: 'MyPir',
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
    const pir = await queryAsAdmin({
      query: CREATE_QUERY,
      variables: PIR_TO_CREATE,
    });
    expect(pir).not.toBeNull();
    expect(pir.data?.pirAdd).not.toBeNull();
    expect(pir.data?.pirAdd.name).toEqual('MyPir');
    pirInternalId = pir.data?.pirAdd.id;
    // reset cache for Pir
    resetCacheForEntity(ENTITY_TYPE_PIR);
  });

  it('should pir loaded by internal id', async () => {
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: pirInternalId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data?.pir).not.toBeNull();
    expect(queryResult.data?.pir.id).toEqual(pirInternalId);
    expect(queryResult.data?.pir.pir_type).toEqual(PirType.ThreatLandscape);
    expect(queryResult.data?.pir.pir_criteria.length).toEqual(2);
    expect(queryResult.data?.pir.pir_criteria[0].weight).toEqual(2);
    expect(JSON.parse(queryResult.data?.pir.pir_criteria[0].filters).filters[0].key[0]).toEqual('toId');
  });

  it('should list pirs', async () => {
    const queryResult = await queryAsAdmin({ query: LIST_QUERY, variables: { first: 10 } });
    expect(queryResult.data?.pirs.edges.length).toEqual(1);
  });

  it('should exist associated pir connector queue for worker', async () => {
    const connectors = await connectorsForWorker(testContext, ADMIN_USER);
    const pirConnectors = connectors.filter((c) => c.id === pirInternalId);
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
      variables: { id: pirInternalId, input: [{ key: 'name', value: ['myPirNewName'] }] },
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
      variables: { id: pirInternalId, input: [{ key: 'pir_filters', value: [undefined] }] },
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
      variables: { id: pirInternalId, input: { relationshipId, sourceId: flaggedElementId, matchingCriteria } },
    });
    // Verify the in-pir relation has been created
    const queryResult = await queryAsAdmin({
      query: LIST_RELS_QUERY,
      variables: { pirId: pirInternalId },
    });
    expect(queryResult).not.toBeNull();
    expect(queryResult).toEqual('test');
    expect(queryResult.data?.pirRelationships.edges.length).toEqual(1);
    expect(queryResult.data?.pirRelationships.edges[0].node.from.id).toEqual(flaggedElementId);
    expect(queryResult.data?.pirRelationships.edges[0].node.to.id).toEqual(pirInternalId);
    expect(queryResult.data?.pirRelationships.edges[0].node.pir_score).toEqual(67);
    expect(queryResult.data?.pirRelationships.edges[0].node.pir_explanations.length).toEqual(1);
    expect(queryResult.data?.pirRelationships.edges[0].node.pir_explanations[0].dependencies[0].element_id).toEqual(relationshipId);
    // Verify the pir information has been updated at the entity level
    const malwareAfterFlag = await internalLoadById<BasicStoreEntity>(
      testContext,
      SYSTEM_USER,
      'malware--c6006dd5-31ca-45c2-8ae0-4e428e712f88',
      { type: ENTITY_TYPE_MALWARE },
    );
    expect(malwareAfterFlag.pir_information.length).toEqual(1);
    expect(malwareAfterFlag.pir_information.filter((s) => s.pir_id === pirInternalId).length).toEqual(1);
    expect(malwareAfterFlag.pir_information.filter((s) => s.pir_id === pirInternalId)[0].pir_score).toEqual(67);
    // should fetch stix domain object pir information
    const malwareQueryResult = await queryAsAdmin({
      query: MALWARE_QUERY,
      variables: {
        id: flaggedElementId,
        pirId: pirInternalId,
      },
    });
    expect(malwareQueryResult.data?.malware).not.toBeNull();
    expect(malwareQueryResult.data?.malware.pirInformation.pir_score).toEqual(67);
    expect(malwareQueryResult.data?.malware.pirInformation.pir_explanations.length).toEqual(1);
    expect(malwareQueryResult.data?.malware.pirInformation.pir_explanations[0].criterion.filters).toEqual(JSON.stringify(matchingCriteria.filters));
  });

  it('should filter entities by a pir score', async () => {
    // return no entities if the pir id matches no PIR
    const filtersWithFakePirId = addFilter(undefined, `${PIR_SCORE_FILTER_PREFIX}.fakeId}`, ['50'], 'gt');
    await expect(async () => {
      await listEntitiesPaginated(testContext, SYSTEM_USER, [ABSTRACT_STIX_DOMAIN_OBJECT], { filters: filtersWithFakePirId });
    }).rejects.toThrowError('No PIR found');
    // return error if the filter key is not in a correct format
    const filtersInIncorrectFormat = addFilter(undefined, PIR_SCORE_FILTER_PREFIX, ['50'], 'gt');
    await expect(async () => {
      await listEntitiesPaginated(testContext, SYSTEM_USER, [ABSTRACT_STIX_DOMAIN_OBJECT], { filters: filtersInIncorrectFormat });
    }).rejects.toThrowError('The filter key should be followed by a dot and the Pir ID');
    // return error if the pir is not accessible for the user
    const filtersWithGtOperator = addFilter(undefined, `${PIR_SCORE_FILTER_PREFIX}.${pirInternalId}`, ['50'], 'gt');
    await expect(async () => {
      await listEntitiesPaginated(testContext, RESTRICTED_USER, [ABSTRACT_STIX_DOMAIN_OBJECT], { filters: filtersWithGtOperator });
    }).rejects.toThrowError('No PIR found');
    // fetch entities with a score > 50 for a given PIR
    const stixDomainObjects1 = await listEntitiesPaginated(testContext, SYSTEM_USER, [ABSTRACT_STIX_DOMAIN_OBJECT], { filters: filtersWithGtOperator });
    expect(stixDomainObjects1.edges.length).toEqual(1);
    expect(stixDomainObjects1.edges[0].node.internal_id).toEqual(flaggedElementId);
    // fetch entities with a score < 50 for a given PIR
    const filtersWithLtOperator = addFilter(undefined, `${PIR_SCORE_FILTER_PREFIX}.${pirInternalId}`, ['50'], 'lt');
    const stixDomainObjects2 = await listEntitiesPaginated(testContext, SYSTEM_USER, [ABSTRACT_STIX_DOMAIN_OBJECT], { filters: filtersWithLtOperator });
    expect(stixDomainObjects2.edges.length).toEqual(0);
  });

  it('should filter entities by last pir score date', async () => {
    // return no entities if the pir id matches no PIR
    const filtersWithFakePirId = addFilter(undefined, `${LAST_PIR_SCORE_DATE_FILTER_PREFIX}.fakeId}`, [now().toString()], 'lt');
    await expect(async () => {
      await listEntitiesPaginated(testContext, SYSTEM_USER, [ABSTRACT_STIX_DOMAIN_OBJECT], { filters: filtersWithFakePirId });
    }).rejects.toThrowError('No PIR found');
    // return error if the filter key is not in a correct format
    const filtersInIncorrectFormat = addFilter(undefined, LAST_PIR_SCORE_DATE_FILTER_PREFIX, [now().toString()], 'lt');
    await expect(async () => {
      await listEntitiesPaginated(testContext, SYSTEM_USER, [ABSTRACT_STIX_DOMAIN_OBJECT], { filters: filtersInIncorrectFormat });
    }).rejects.toThrowError('The filter key should be followed by a dot and the Pir ID');
    // fetch entities scored before now for the pir
    const filtersWithGtOperator = addFilter(undefined, `${LAST_PIR_SCORE_DATE_FILTER_PREFIX}.${pirInternalId}`, [now().toString()], 'lt');
    const stixDomainObjects1 = await listEntitiesPaginated(testContext, SYSTEM_USER, [ABSTRACT_STIX_DOMAIN_OBJECT], { filters: filtersWithGtOperator });
    expect(stixDomainObjects1.edges.length).toEqual(1);
    expect(stixDomainObjects1.edges[0].node.internal_id).toEqual(flaggedElementId);
    // fetch entities scored after now for the pir
    const filtersWithLtOperator = addFilter(undefined, `${LAST_PIR_SCORE_DATE_FILTER_PREFIX}.${pirInternalId}`, [now().toString()], 'gt');
    const stixDomainObjects2 = await listEntitiesPaginated(testContext, SYSTEM_USER, [ABSTRACT_STIX_DOMAIN_OBJECT], { filters: filtersWithLtOperator });
    expect(stixDomainObjects2.edges.length).toEqual(0);
    // fetch entities scored today
    const filtersWithinToday = addFilter(undefined, `${LAST_PIR_SCORE_DATE_FILTER_PREFIX}.${pirInternalId}`, ['now-1d', 'now'], 'within');
    const stixDomainObjects3 = await listEntitiesPaginated(testContext, SYSTEM_USER, [ABSTRACT_STIX_DOMAIN_OBJECT], { filters: filtersWithinToday });
    expect(stixDomainObjects3.edges.length).toEqual(1);
    expect(stixDomainObjects3.edges[0].node.internal_id).toEqual(flaggedElementId);
    // fetch entities scored tomorrow
    const filtersWithinTomorrow = addFilter(undefined, `${LAST_PIR_SCORE_DATE_FILTER_PREFIX}.${pirInternalId}`, ['now', 'now+1d'], 'within');
    const stixDomainObjects4 = await listEntitiesPaginated(testContext, SYSTEM_USER, [ABSTRACT_STIX_DOMAIN_OBJECT], { filters: filtersWithinTomorrow });
    expect(stixDomainObjects4.edges.length).toEqual(0);
  });

  it('regardingOf filter used with in-pir relationship type', async () => {
    // error if regardingOf filter with in-pir relationship type and no id
    let filters = {
      mode: FilterMode.And,
      filterGroups: [],
      filters: [
        {
          key: ['regardingOf'],
          values: [
            { key: 'relationship_type', values: [RELATION_IN_PIR, 'targets'] },
          ],
        },
      ]
    };
    await expect(async () => {
      await listEntitiesPaginated(testContext, SYSTEM_USER, [ABSTRACT_STIX_DOMAIN_OBJECT], { filters });
    }).rejects.toThrowError('regardingOf filter with in-pir relationship type should be used with one or more valid pir id.');
    // error if regardingOf filter with in-pir relationship type and id corresponding to no pir
    filters = {
      mode: FilterMode.And,
      filterGroups: [],
      filters: [
        {
          key: ['regardingOf'],
          values: [
            { key: 'relationship_type', values: [RELATION_IN_PIR] },
            { key: 'id', values: ['fakeId'] },
          ],
        },
      ]
    };
    await expect(async () => {
      await listEntitiesPaginated(testContext, SYSTEM_USER, [ABSTRACT_STIX_DOMAIN_OBJECT], { filters });
    }).rejects.toThrowError('regardingOf filter with in-pir relationship type should be used with one or more valid pir id.');
    // error if regardingOf filter with in-pir relationship type and a pir id not accessible for the user
    filters = {
      mode: FilterMode.And,
      filterGroups: [],
      filters: [
        {
          key: ['regardingOf'],
          values: [
            { key: 'relationship_type', values: [RELATION_IN_PIR] },
            { key: 'id', values: [pirInternalId] },
          ],
        },
      ]
    };
    await expect(async () => {
      await listEntitiesPaginated(testContext, RESTRICTED_USER, [ABSTRACT_STIX_DOMAIN_OBJECT], { filters });
    }).rejects.toThrowError('regardingOf filter with in-pir relationship type should be used with one or more valid pir id.');
    // regardingOf filter with in-pir relationship type and pir id should return flagged entities
    filters = {
      mode: FilterMode.And,
      filterGroups: [],
      filters: [
        {
          key: ['regardingOf'],
          values: [
            { key: 'relationship_type', values: [RELATION_IN_PIR] },
            { key: 'id', values: [pirInternalId] },
          ],
        },
      ]
    };
    const stixDomainObjects = await listEntitiesPaginated(testContext, SYSTEM_USER, [ABSTRACT_STIX_DOMAIN_OBJECT], { filters });
    expect(stixDomainObjects.edges.length).toEqual(1);
    expect(stixDomainObjects.edges[0].node.internal_id).toEqual(flaggedElementId);
  });

  it('should update a pir meta rel by adding a new explanation', async () => {
    const FLAG_QUERY = gql`
      mutation pirFlagElement($id: ID!, $input: PirFlagElementInput!) {
        pirFlagElement(id: $id, input: $input)
      }
    `;
    const relationshipId = 'relationship2';
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
    await queryAsAdmin({
      query: FLAG_QUERY,
      variables: { id: pirInternalId, input: { relationshipId, sourceId: flaggedElementId, matchingCriteria } },
    });
    // Verify the in-pir rel has been updated
    const queryResult = await queryAsAdmin({
      query: LIST_RELS_QUERY,
      variables: { pirId: pirInternalId },
    });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data?.pirRelationships.edges.length).toEqual(1);
    expect(queryResult.data?.pirRelationships.edges[0].node.from.id).toEqual(flaggedElementId);
    expect(queryResult.data?.pirRelationships.edges[0].node.to.id).toEqual(pirInternalId);
    expect(queryResult.data?.pirRelationships.edges[0].node.pir_score).toEqual(100);
    expect(queryResult.data?.pirRelationships.edges[0].node.pir_explanations.length).toEqual(2);
    // Verify the pir information has been updated at the entity level
    const malwareAfterFlag = await internalLoadById<BasicStoreEntity>(
      testContext,
      SYSTEM_USER,
      'malware--c6006dd5-31ca-45c2-8ae0-4e428e712f88',
      { type: ENTITY_TYPE_MALWARE },
    );
    expect(malwareAfterFlag.pir_information.length).toEqual(1);
    expect(malwareAfterFlag.pir_information.filter((s) => s.pir_id === pirInternalId).length).toEqual(1);
    expect(malwareAfterFlag.pir_information.filter((s) => s.pir_id === pirInternalId)[0].pir_score).toEqual(100);
  });

  it('should update a pir meta rel by removing an explanation', async () => {
    const UNFLAG_QUERY = gql`
      mutation pirUnflagElement($id: ID!, $input: PirUnflagElementInput!) {
        pirUnflagElement(id: $id, input: $input)
      }
    `;
    const relationshipId = 'relationship2';
    await queryAsAdmin({
      query: UNFLAG_QUERY,
      variables: { id: pirInternalId, input: { relationshipId, sourceId: flaggedElementId } },
    });
    // Verify the in-pir rel has been updated
    const queryResult = await queryAsAdmin({
      query: LIST_RELS_QUERY,
      variables: { pirId: pirInternalId },
    });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data?.pirRelationships.edges.length).toEqual(1);
    expect(queryResult.data?.pirRelationships.edges[0].node.from.id).toEqual(flaggedElementId);
    expect(queryResult.data?.pirRelationships.edges[0].node.to.id).toEqual(pirInternalId);
    expect(queryResult.data?.pirRelationships.edges[0].node.pir_score).toEqual(67);
    expect(queryResult.data?.pirRelationships.edges[0].node.pir_explanations.length).toEqual(1);
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
      variables: { id: pirInternalId, input: { relationshipId, sourceId: flaggedElementId } },
    });
    // Verify the in-pir rel has been deleted
    const queryResult = await queryAsAdmin({
      query: LIST_RELS_QUERY,
      variables: { pirId: pirInternalId },
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
    // Delete the pir
    await queryAsAdmin({
      query: DELETE_QUERY,
      variables: { id: pirInternalId },
    });
    // Verify the in-pir relations have been deleted
    const pirRelations = await listRelationsPaginated<BasicStoreRelationPir>(testContext, SYSTEM_USER, RELATION_IN_PIR, { toId: [pirInternalId] });
    expect(pirRelations).not.toBeNull();
    expect(pirRelations.edges.length).toEqual(0);
    // Verify the pir information has been removed for the PIR at entities levels
    const malwareAfterFlag = await internalLoadById<BasicStoreEntity>(
      testContext,
      SYSTEM_USER,
      'malware--c6006dd5-31ca-45c2-8ae0-4e428e712f88',
      { type: ENTITY_TYPE_MALWARE },
    );
    expect(malwareAfterFlag.pir_information).toEqual(null);
    // Verify the associated connector queue is no longer found
    const connectors = await connectorsForWorker(testContext, ADMIN_USER);
    const pirConnector = connectors.filter((c) => c.id === pirInternalId);
    expect(pirConnector.length).toEqual(0);
    // Verify the PIR is no longer found
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: pirInternalId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data?.pir).toBeNull();
  });
});
