import gql from 'graphql-tag';
import { queryAsAdmin } from '../../utils/testQuery';

const LIST_QUERY = gql`
  query attackPatterns(
    $first: Int
    $after: ID
    $orderBy: AttackPatternsOrdering
    $orderMode: OrderingMode
    $filters: [AttackPatternsFiltering]
    $filterMode: FilterMode
    $search: String
  ) {
    attackPatterns(
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
  query attackPattern($id: String!) {
    attackPattern(id: $id) {
      id
      name
      description
      killChainPhases {
        edges {
          node {
            id
          }
        }
      }
      coursesOfAction {
        edges {
          node {
            id
          }
        }
      }
      toStix
    }
  }
`;

describe('AttackPattern resolver standard behavior', () => {
  let attackPatternInternalId;
  let attackPatternMarkingDefinitionRelationId;
  const attackPatternStixId = 'attack-pattern--7dd8142a-e21b-4a29-b241-e63dac6a23ea';
  it('should attackPattern created', async () => {
    const CREATE_QUERY = gql`
      mutation AttackPatternAdd($input: AttackPatternAddInput) {
        attackPatternAdd(input: $input) {
          id
          name
          description
        }
      }
    `;
    // Create the attackPattern
    const ATTACK_PATTERN_TO_CREATE = {
      input: {
        name: 'AttackPattern',
        stix_id_key: attackPatternStixId,
        description: 'AttackPattern description',
        killChainPhases: ['2a2202bd-1da6-4668-9fc5-ad1017e974bc'],
      },
    };
    const attackPattern = await queryAsAdmin({
      query: CREATE_QUERY,
      variables: ATTACK_PATTERN_TO_CREATE,
    });
    expect(attackPattern).not.toBeNull();
    expect(attackPattern.data.attackPatternAdd).not.toBeNull();
    expect(attackPattern.data.attackPatternAdd.name).toEqual('AttackPattern');
    attackPatternInternalId = attackPattern.data.attackPatternAdd.id;
  });
  it('should attackPattern loaded by internal id', async () => {
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: attackPatternInternalId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.attackPattern).not.toBeNull();
    expect(queryResult.data.attackPattern.id).toEqual(attackPatternInternalId);
    expect(queryResult.data.attackPattern.toStix.length).toBeGreaterThan(5);
    expect(queryResult.data.attackPattern.killChainPhases.edges.length).toEqual(1);
    expect(queryResult.data.attackPattern.killChainPhases.edges[0].node.id).toEqual(
      '2a2202bd-1da6-4668-9fc5-ad1017e974bc'
    );
  });
  it('should attackPattern loaded by stix id', async () => {
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: attackPatternStixId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.attackPattern).not.toBeNull();
    expect(queryResult.data.attackPattern.id).toEqual(attackPatternInternalId);
  });
  it('should attackPattern coursesOfAction be accurate', async () => {
    const queryResult = await queryAsAdmin({
      query: READ_QUERY,
      variables: { id: 'dcbadcd2-9359-48ac-8b86-88e38a092a2b' },
    });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.attackPattern).not.toBeNull();
    expect(queryResult.data.attackPattern.id).toEqual('dcbadcd2-9359-48ac-8b86-88e38a092a2b');
    expect(queryResult.data.attackPattern.coursesOfAction.edges.length).toEqual(1);
    expect(queryResult.data.attackPattern.coursesOfAction.edges[0].node.id).toEqual(
      '326b7708-d4cf-4020-8cd1-9726b99895db'
    );
  });
  it('should list attackPatterns', async () => {
    const queryResult = await queryAsAdmin({ query: LIST_QUERY, variables: { first: 10 } });
    expect(queryResult.data.attackPatterns.edges.length).toEqual(3);
  });
  it('should update attackPattern', async () => {
    const UPDATE_QUERY = gql`
      mutation AttackPatternEdit($id: ID!, $input: EditInput!) {
        attackPatternEdit(id: $id) {
          fieldPatch(input: $input) {
            id
            name
          }
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: UPDATE_QUERY,
      variables: { id: attackPatternInternalId, input: { key: 'name', value: ['AttackPattern - test'] } },
    });
    expect(queryResult.data.attackPatternEdit.fieldPatch.name).toEqual('AttackPattern - test');
  });
  it('should context patch attackPattern', async () => {
    const CONTEXT_PATCH_QUERY = gql`
      mutation AttackPatternEdit($id: ID!, $input: EditContext) {
        attackPatternEdit(id: $id) {
          contextPatch(input: $input) {
            id
          }
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: CONTEXT_PATCH_QUERY,
      variables: { id: attackPatternInternalId, input: { focusOn: 'description' } },
    });
    expect(queryResult.data.attackPatternEdit.contextPatch.id).toEqual(attackPatternInternalId);
  });
  it('should context clean attackPattern', async () => {
    const CONTEXT_PATCH_QUERY = gql`
      mutation AttackPatternEdit($id: ID!) {
        attackPatternEdit(id: $id) {
          contextClean {
            id
          }
        }
      }
    `;
    const queryResult = await queryAsAdmin({
      query: CONTEXT_PATCH_QUERY,
      variables: { id: attackPatternInternalId },
    });
    expect(queryResult.data.attackPatternEdit.contextClean.id).toEqual(attackPatternInternalId);
  });
  it('should add relation in attackPattern', async () => {
    const RELATION_ADD_QUERY = gql`
      mutation AttackPatternEdit($id: ID!, $input: RelationAddInput!) {
        attackPatternEdit(id: $id) {
          relationAdd(input: $input) {
            id
            from {
              ... on AttackPattern {
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
        id: attackPatternInternalId,
        input: {
          fromRole: 'so',
          toRole: 'marking',
          toId: '43f586bc-bcbc-43d1-ab46-43e5ab1a2c46',
          through: 'object_marking_refs',
        },
      },
    });
    expect(queryResult.data.attackPatternEdit.relationAdd.from.markingDefinitions.edges.length).toEqual(1);
    attackPatternMarkingDefinitionRelationId =
      queryResult.data.attackPatternEdit.relationAdd.from.markingDefinitions.edges[0].relation.id;
  });
  it('should delete relation in attackPattern', async () => {
    const RELATION_DELETE_QUERY = gql`
      mutation AttackPatternEdit($id: ID!, $relationId: ID!) {
        attackPatternEdit(id: $id) {
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
        id: attackPatternInternalId,
        relationId: attackPatternMarkingDefinitionRelationId,
      },
    });
    expect(queryResult.data.attackPatternEdit.relationDelete.markingDefinitions.edges.length).toEqual(0);
  });
  it('should attackPattern deleted', async () => {
    const DELETE_QUERY = gql`
      mutation attackPatternDelete($id: ID!) {
        attackPatternEdit(id: $id) {
          delete
        }
      }
    `;
    // Delete the attackPattern
    await queryAsAdmin({
      query: DELETE_QUERY,
      variables: { id: attackPatternInternalId },
    });
    // Verify is no longer found
    const queryResult = await queryAsAdmin({ query: READ_QUERY, variables: { id: attackPatternStixId } });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.attackPattern).toBeNull();
  });
});
