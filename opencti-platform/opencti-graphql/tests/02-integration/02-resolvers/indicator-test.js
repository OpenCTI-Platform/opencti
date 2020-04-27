import gql from 'graphql-tag';
import { queryAsAdmin } from '../../utils/testQuery';

const LIST_QUERY = gql`
  query indicators(
    $first: Int
    $after: ID
    $orderBy: IndicatorsOrdering
    $orderMode: OrderingMode
    $filters: [IndicatorsFiltering]
    $filterMode: FilterMode
    $search: String
  ) {
    indicators(
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

const READ_QUERY = gql`
  query indicator($id: String!) {
    indicator(id: $id) {
      id
      name
      description
      toStix
    }
  }
`;

describe('Indicator resolver standard behavior', () => {
  let indicatorInternalId;
  let stixObservableInternalId;
  let indicatorMarkingDefinitionRelationId;
  const indicatorStixId = 'indicator--f6ad652c-166a-43e6-98b8-8ff078e2349f';
  it('should indicator created', async () => {
    const CREATE_QUERY = gql`
      mutation IndicatorAdd($input: IndicatorAddInput) {
        indicatorAdd(input: $input) {
          id
          name
          description
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
    // Create the indicator
    const INDICATOR_TO_CREATE = {
      input: {
        name: 'Indicator',
        stix_id_key: indicatorStixId,
        description: 'Indicator description',
        indicator_pattern: "[domain-name:value = 'www.payah.rest']",
        pattern_type: 'stix',
        main_observable_type: 'domain',
      },
    };
    const indicator = await queryAsAdmin({
      query: CREATE_QUERY,
      variables: INDICATOR_TO_CREATE,
    });
    expect(indicator).not.toBeNull();
    expect(indicator.data.indicatorAdd).not.toBeNull();
    expect(indicator.data.indicatorAdd.name).toEqual('Indicator');
    expect(indicator.data.indicatorAdd.observableRefs.edges.length).toEqual(1);
    indicatorInternalId = indicator.data.indicatorAdd.id;
    stixObservableInternalId = indicator.data.indicatorAdd.observableRefs.edges[0].node.id;
  });
  it('should indicator loaded by internal id', async () => {
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: indicatorInternalId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.indicator).not.toBeNull();
    expect(queryResult.data.indicator.id).toEqual(indicatorInternalId);
    expect(queryResult.data.indicator.toStix.length).toBeGreaterThan(5);
  });
  it('should indicator loaded by stix id', async () => {
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: indicatorStixId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.indicator).not.toBeNull();
    expect(queryResult.data.indicator.id).toEqual(indicatorInternalId);
  });
  it('should list indicators', async () => {
    const queryResult = await queryAsAdmin({ query: LIST_QUERY, variables: { first: 10 } });
    expect(queryResult.data.indicators.edges.length).toEqual(4);
  });
  it('should update indicator', async () => {
    const UPDATE_QUERY = gql`
      mutation IndicatorEdit($id: ID!, $input: EditInput!) {
        indicatorEdit(id: $id) {
          fieldPatch(input: $input) {
            id
            name
          }
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: UPDATE_QUERY,
      variables: { id: indicatorInternalId, input: { key: 'name', value: ['Indicator - test'] } },
    });
    expect(queryResult.data.indicatorEdit.fieldPatch.name).toEqual('Indicator - test');
  });
  it('should context patch indicator', async () => {
    const CONTEXT_PATCH_QUERY = gql`
      mutation IndicatorEdit($id: ID!, $input: EditContext) {
        indicatorEdit(id: $id) {
          contextPatch(input: $input) {
            id
          }
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: CONTEXT_PATCH_QUERY,
      variables: { id: indicatorInternalId, input: { focusOn: 'description' } },
    });
    expect(queryResult.data.indicatorEdit.contextPatch.id).toEqual(indicatorInternalId);
  });
  it('should context clean indicator', async () => {
    const CONTEXT_PATCH_QUERY = gql`
      mutation IndicatorEdit($id: ID!) {
        indicatorEdit(id: $id) {
          contextClean {
            id
          }
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: CONTEXT_PATCH_QUERY,
      variables: { id: indicatorInternalId },
    });
    expect(queryResult.data.indicatorEdit.contextClean.id).toEqual(indicatorInternalId);
  });
  it('should add relation in indicator', async () => {
    const RELATION_ADD_QUERY = gql`
      mutation IndicatorEdit($id: ID!, $input: RelationAddInput!) {
        indicatorEdit(id: $id) {
          relationAdd(input: $input) {
            id
            from {
              ... on Indicator {
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
        id: indicatorInternalId,
        input: {
          fromRole: 'so',
          toRole: 'marking',
          toId: '43f586bc-bcbc-43d1-ab46-43e5ab1a2c46',
          through: 'object_marking_refs',
        },
      },
    });
    expect(queryResult.data.indicatorEdit.relationAdd.from.markingDefinitions.edges.length).toEqual(1);
    indicatorMarkingDefinitionRelationId =
      queryResult.data.indicatorEdit.relationAdd.from.markingDefinitions.edges[0].relation.id;
  });
  it('should delete relation in indicator', async () => {
    const RELATION_DELETE_QUERY = gql`
      mutation IndicatorEdit($id: ID!, $relationId: ID!) {
        indicatorEdit(id: $id) {
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
        id: indicatorInternalId,
        relationId: indicatorMarkingDefinitionRelationId,
      },
    });
    expect(queryResult.data.indicatorEdit.relationDelete.markingDefinitions.edges.length).toEqual(0);
  });
  it('should indicator deleted', async () => {
    const DELETE_QUERY = gql`
      mutation indicatorDelete($id: ID!) {
        indicatorEdit(id: $id) {
          delete
        }
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
    expect(queryResult.data.indicator).toBeNull();
    const DELETE_OBSERVABLE_QUERY = gql`
      mutation stixObservableDelete($id: ID!) {
        stixObservableEdit(id: $id) {
          delete
        }
      }
    `;
    // Delete the observable
    await queryAsAdmin({
      query: DELETE_OBSERVABLE_QUERY,
      variables: { id: stixObservableInternalId },
    });
  });
});
