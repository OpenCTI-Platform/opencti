import { expect, it, describe } from 'vitest';
import gql from 'graphql-tag';
import { queryAsAdmin } from '../../utils/testQuery';
import { ENTITY_DOMAIN_NAME } from '../../../src/schema/stixCyberObservable';
import { MARKING_TLP_GREEN } from '../../../src/schema/identifier';
import type { BasicStoreEntityEdge } from '../../../src/types/store';
import type { BasicStoreEntityIndicator } from '../../../src/modules/indicator/indicator-types';

const LIST_QUERY = gql`
    query indicators(
        $first: Int
        $after: ID
        $orderBy: IndicatorsOrdering
        $orderMode: OrderingMode
        $filters: FilterGroup
        $search: String
    ) {
        indicators(
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
                    standard_id
                    name
                    description
                }
            }
        }
    }
`;

const READ_QUERY = gql`
    query indicator($id: String!) {
        indicator(id: $id) {
            id
            standard_id
            name
            description
            toStix
        }
    }
`;

const CREATE_QUERY = gql`
    mutation IndicatorAdd($input: IndicatorAddInput!) {
        indicatorAdd(input: $input) {
            id
            name
            description
            observables {
                edges {
                    node {
                        id
                        standard_id
                    }
                }
            }
        }
    }
`;

describe('Indicator resolver standard behavior', () => {
  let firstIndicatorInternalId: string;
  let secondIndicatorInternalId: string;
  const indicatorStixId = 'indicator--f6ad652c-166a-43e6-98b8-8ff078e2349f';
  const indicatorForTestName = 'Indicator in indicator-test';

  it('should indicator created', async () => {
    // Create the indicator
    const INDICATOR_TO_CREATE = {
      input: {
        name: indicatorForTestName,
        stix_id: indicatorStixId,
        description: 'Indicator created for test purpose that will be deleted at the end of this test file.',
        pattern: "[domain-name:value = 'www.payah.rest']",
        pattern_type: 'stix',
        x_opencti_main_observable_type: 'Domain-Name',
      },
    };
    const indicator = await queryAsAdmin({
      query: CREATE_QUERY,
      variables: INDICATOR_TO_CREATE,
    });
    expect(indicator).not.toBeNull();
    expect(indicator.data?.indicatorAdd).not.toBeNull();
    expect(indicator.data?.indicatorAdd.name).toEqual(indicatorForTestName);
    expect(indicator.data?.indicatorAdd.observables.edges.length).toEqual(0);
    firstIndicatorInternalId = indicator.data?.indicatorAdd.id;
  });
  it('should indicator with same name be created also (no upsert) (see issues/5819)', async () => {
    const INDICATOR_TO_CREATE = {
      input: {
        name: indicatorForTestName,
        description: 'Indicator that should be created as new and not upsert even if name already exists.',
        pattern: "[domain-name:value = 'www.test2.rest']", // pattern is different so it should be a new indicator
        pattern_type: 'stix',
        x_opencti_main_observable_type: ENTITY_DOMAIN_NAME,
      },
    };
    const indicator = await queryAsAdmin({
      query: CREATE_QUERY,
      variables: INDICATOR_TO_CREATE,
    });
    expect(indicator.data?.indicatorAdd).toBeDefined();
    expect(indicator.data?.indicatorAdd.name).toEqual(indicatorForTestName);
    expect(indicator.data?.indicatorAdd.observables.edges.length).toEqual(0);
    expect(indicator.data?.indicatorAdd.id, 'A new indicator should be created, if not it is an upsert and it is a bug').not.toEqual(firstIndicatorInternalId);
    secondIndicatorInternalId = indicator.data?.indicatorAdd.id;
  });

  it('should indicator with same pattern be upsert (not created)', async () => {
    // Create the indicator
    const INDICATOR_TO_CREATE = {
      input: {
        name: `New name for ${indicatorForTestName}`, // name is different
        description: 'Indicator that should be upsert from the first one created on this test.',
        pattern: "[domain-name:value = 'www.payah.rest']", // same pattern as first creation test
        pattern_type: 'stix',
        x_opencti_main_observable_type: ENTITY_DOMAIN_NAME,
      },
    };
    const indicator = await queryAsAdmin({
      query: CREATE_QUERY,
      variables: INDICATOR_TO_CREATE,
    });
    expect(indicator.data?.indicatorAdd).toBeDefined();
    expect(indicator.data?.indicatorAdd.name).toEqual(`New name for ${indicatorForTestName}`);
    expect(indicator.data?.indicatorAdd.observables.edges.length).toEqual(0);
    expect(indicator.data?.indicatorAdd.id).toEqual(firstIndicatorInternalId);
  });
  it('should indicator loaded by internal id', async () => {
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: firstIndicatorInternalId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data?.indicator).not.toBeNull();
    expect(queryResult.data?.indicator.id).toEqual(firstIndicatorInternalId);
    expect(queryResult.data?.indicator.toStix.length).toBeGreaterThan(5);
  });
  it('should indicator loaded by stix id', async () => {
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: indicatorStixId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data?.indicator).not.toBeNull();
    expect(queryResult.data?.indicator.id).toEqual(firstIndicatorInternalId);
  });
  it('should list indicators', async () => {
    const queryResult = await queryAsAdmin({ query: LIST_QUERY, variables: { first: 10 } });
    const indicatorList: [] = queryResult.data?.indicators.edges;
    expect(indicatorList).toBeDefined();
    if (indicatorList) {
      const indicatorCreatedEarlier = indicatorList.find((indicator: BasicStoreEntityEdge<BasicStoreEntityIndicator>) => indicator.node.name === indicatorForTestName);
      expect(indicatorCreatedEarlier).toBeDefined();
    }
  });
  it('should update indicator', async () => {
    const UPDATE_QUERY = gql`
        mutation IndicatorFieldPatch($id: ID!, $input: [EditInput]!) {
            indicatorFieldPatch(id: $id, input: $input) {
                id
                name
            }
        }
    `;
    const queryResult = await queryAsAdmin({
      query: UPDATE_QUERY,
      variables: { id: firstIndicatorInternalId, input: { key: 'name', value: ['Indicator - test'] } },
    });
    expect(queryResult.data?.indicatorFieldPatch.name).toEqual('Indicator - test');
  });
  it('should context patch indicator', async () => {
    const CONTEXT_PATCH_QUERY = gql`
        mutation IndicatorContextPatch($id: ID!, $input: EditContext) {
            indicatorContextPatch(id: $id, input: $input) {
              id
            }
        }
    `;
    const queryResult = await queryAsAdmin({
      query: CONTEXT_PATCH_QUERY,
      variables: { id: firstIndicatorInternalId, input: { focusOn: 'description' } },
    });
    expect(queryResult.data?.indicatorContextPatch.id).toEqual(firstIndicatorInternalId);
  });
  it('should context clean indicator', async () => {
    const CONTEXT_PATCH_QUERY = gql`
        mutation IndicatorContextClean($id: ID!) {
            indicatorContextClean(id: $id) {
              id
            }
        }
    `;
    const queryResult = await queryAsAdmin({
      query: CONTEXT_PATCH_QUERY,
      variables: { id: firstIndicatorInternalId },
    });
    expect(queryResult.data?.indicatorContextClean.id).toEqual(firstIndicatorInternalId);
  });
  it('should add relation in indicator', async () => {
    const RELATION_ADD_QUERY = gql`
        mutation IndicatorRelationAdd($id: ID!, $input: StixRefRelationshipAddInput!) {
            indicatorRelationAdd(id: $id, input: $input) {
                id
                from {
                    ... on Indicator {
                        objectMarking {
                            id
                        }
                    }
                }
            }
        }
    `;
    const queryResult = await queryAsAdmin({
      query: RELATION_ADD_QUERY,
      variables: {
        id: firstIndicatorInternalId,
        input: {
          toId: MARKING_TLP_GREEN,
          relationship_type: 'object-marking',
        },
      },
    });
    expect(queryResult.data?.indicatorRelationAdd.from.objectMarking.length).toEqual(1);
  });
  it('should delete relation in indicator', async () => {
    const RELATION_DELETE_QUERY = gql`
        mutation IndicatorRelationDelete($id: ID!, $toId: StixRef!, $relationship_type: String!) {
            indicatorRelationDelete(id: $id, toId: $toId, relationship_type: $relationship_type) {
                id
                objectMarking {
                    id
                }
            }
        }
    `;
    const queryResult = await queryAsAdmin({
      query: RELATION_DELETE_QUERY,
      variables: {
        id: firstIndicatorInternalId,
        toId: MARKING_TLP_GREEN,
        relationship_type: 'object-marking',
      },
    });
    expect(queryResult.data?.indicatorRelationDelete.objectMarking.length).toEqual(0);
  });
  it('should indicator deleted', async () => {
    const DELETE_QUERY = gql`
        mutation indicatorDelete($id: ID!) {
            indicatorDelete(id: $id)
        }
    `;
    // Delete the indicator
    await queryAsAdmin({
      query: DELETE_QUERY,
      variables: { id: firstIndicatorInternalId },
    });

    await queryAsAdmin({
      query: DELETE_QUERY,
      variables: { id: secondIndicatorInternalId },
    });
    // Verify is no longer found
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: indicatorStixId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data?.indicator).toBeNull();
  });
});
