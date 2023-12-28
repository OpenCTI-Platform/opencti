import { expect, it, describe } from 'vitest';
import gql from 'graphql-tag';
import { queryAsAdmin } from '../../utils/testQuery';
// import type { Indicator } from '../../../src/generated/graphql';

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

describe('Indicator resolver standard behavior', () => {
  let indicatorInternalId: string;
  const indicatorStixId = 'indicator--f6ad652c-166a-43e6-98b8-8ff078e2349f';
  it('should indicator created', async () => {
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
    // Create the indicator
    const INDICATOR_TO_CREATE = {
      input: {
        name: 'Indicator',
        stix_id: indicatorStixId,
        description: 'Indicator description',
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
    expect(indicator.data?.indicatorAdd.name).toEqual('Indicator');
    expect(indicator.data?.indicatorAdd.observables.edges.length).toEqual(0);
    indicatorInternalId = indicator.data?.indicatorAdd.id;
  });
  /* it('should indicator be merged', async () => {
    const CREATE_QUERY = gql`
          mutation IndicatorAdd($input: IndicatorAddInput!) {
            indicatorAdd(input: $input) {
              id
              name
              description
              x_opencti_score
              x_opencti_base_score
              x_opencti_decay_rule {
                id
              }
              x_opencti_decay_history {
                date
                score
              }
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
    // Create the indicator
    const INDICATOR_TO_CREATE = {
      input: {
        name: 'Indicator',
        confidence: 50,
        stix_id: indicatorStixId,
        description: 'Indicator description should be merged',
        pattern: "[domain-name:value = 'www.payah.rest']",
        pattern_type: 'stix',
        x_opencti_main_observable_type: 'Domain-Name',
        x_opencti_score: 80,
      },
    };
    const indicator = await queryAsAdmin({
      query: CREATE_QUERY,
      variables: INDICATOR_TO_CREATE,
    });
    expect(indicator).not.toBeNull();
    const createdIndicator: Indicator = indicator.data?.indicatorAdd;
    expect(createdIndicator).not.toBeNull();
    expect(createdIndicator.name).toEqual('Indicator');
    expect(createdIndicator.observables?.edges.length).toEqual(0);
    expect(createdIndicator.x_opencti_score, 'Stable score should be reset to 80').toEqual(80);
    expect(createdIndicator.x_opencti_base_score, 'Base score should be reset to 80').toEqual(80);
    expect(createdIndicator.x_opencti_decay_history?.length).toEqual(2);
  }); */
  it('should indicator loaded by internal id', async () => {
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: indicatorInternalId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data?.indicator).not.toBeNull();
    expect(queryResult.data?.indicator.id).toEqual(indicatorInternalId);
    expect(queryResult.data?.indicator.toStix.length).toBeGreaterThan(5);
  });
  it('should indicator loaded by stix id', async () => {
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: indicatorStixId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data?.indicator).not.toBeNull();
    expect(queryResult.data?.indicator.id).toEqual(indicatorInternalId);
  });
  it('should list indicators', async () => {
    const queryResult = await queryAsAdmin({ query: LIST_QUERY, variables: { first: 10 } });
    expect(queryResult.data?.indicators.edges.length).toEqual(4);
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
      variables: { id: indicatorInternalId, input: { key: 'name', value: ['Indicator - test'] } },
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
      variables: { id: indicatorInternalId, input: { focusOn: 'description' } },
    });
    expect(queryResult.data?.indicatorContextPatch.id).toEqual(indicatorInternalId);
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
      variables: { id: indicatorInternalId },
    });
    expect(queryResult.data?.indicatorContextClean.id).toEqual(indicatorInternalId);
  });
  it('should add relation in indicator', async () => {
    const RELATION_ADD_QUERY = gql`
        mutation IndicatorRelationAdd($id: ID!, $input: StixRefRelationshipAddInput!) {
            indicatorRelationAdd(id: $id, input: $input) {
                id
                from {
                    ... on Indicator {
                        objectMarking {
                            edges {
                                node {
                                    id
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
        id: indicatorInternalId,
        input: {
          toId: 'marking-definition--78ca4366-f5b8-4764-83f7-34ce38198e27',
          relationship_type: 'object-marking',
        },
      },
    });
    expect(queryResult.data?.indicatorRelationAdd.from.objectMarking.edges.length).toEqual(1);
  });
  it('should delete relation in indicator', async () => {
    const RELATION_DELETE_QUERY = gql`
        mutation IndicatorRelationDelete($id: ID!, $toId: StixRef!, $relationship_type: String!) {
            indicatorRelationDelete(id: $id, toId: $toId, relationship_type: $relationship_type) {
                id
                objectMarking {
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
      query: RELATION_DELETE_QUERY,
      variables: {
        id: indicatorInternalId,
        toId: 'marking-definition--78ca4366-f5b8-4764-83f7-34ce38198e27',
        relationship_type: 'object-marking',
      },
    });
    expect(queryResult.data?.indicatorRelationDelete.objectMarking.edges.length).toEqual(0);
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
      variables: { id: indicatorInternalId },
    });
    // Verify is no longer found
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: indicatorStixId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data?.indicator).toBeNull();
  });
});
