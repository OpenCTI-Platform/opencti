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
          standard_id
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
      standard_id
      name
      description
      killChainPhases {
        edges {
          node {
            id
            standard_id
          }
        }
      }
      coursesOfAction {
        edges {
          node {
            id
            standard_id
          }
        }
      }
      toStix
    }
  }
`;

describe('AttackPattern resolver standard behavior', () => {
  let attackPatternInternalId;
  const attackPatternStixId = 'attack-pattern--7dd8142a-e21b-4a29-b241-e63dac6a23ea';
  it('should attackPattern created', async () => {
    const CREATE_QUERY = gql`
      mutation AttackPatternAdd($input: AttackPatternAddInput) {
        attackPatternAdd(input: $input) {
          id
          standard_id
          name
          description
        }
      }
    `;
    // Create the attackPattern
    const ATTACK_PATTERN_TO_CREATE = {
      input: {
        name: 'AttackPattern',
        x_mitre_id: 'T001',
        stix_id: attackPatternStixId,
        description: 'AttackPattern description',
        killChainPhases: ['kill-chain-phase--56330302-292c-5ad4-bece-bacaa99c16e0'],
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
    expect(queryResult.data.attackPattern.killChainPhases.edges[0].node.standard_id).toEqual(
      'kill-chain-phase--56330302-292c-5ad4-bece-bacaa99c16e0'
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
      variables: { id: 'attack-pattern--2fc04aa5-48c1-49ec-919a-b88241ef1d17' },
    });
    expect(queryResult).not.toBeNull();
    expect(queryResult.data.attackPattern).not.toBeNull();
    expect(queryResult.data.attackPattern.standard_id).toEqual('attack-pattern--a01046cc-192f-5d52-8e75-6e447fae3890');
    expect(queryResult.data.attackPattern.coursesOfAction.edges.length).toEqual(1);
    expect(queryResult.data.attackPattern.coursesOfAction.edges[0].node.standard_id).toEqual(
      'course-of-action--2d3af28d-aa36-59ad-ac57-65aa27664752'
    );
  });
  it('should list attackPatterns', async () => {
    const queryResult = await queryAsAdmin({ query: LIST_QUERY, variables: { first: 10 } });
    expect(queryResult.data.attackPatterns.edges.length).toEqual(3);
  });
  it('should update attackPattern', async () => {
    const UPDATE_QUERY = gql`
      mutation AttackPatternEdit($id: ID!, $input: [EditInput]!) {
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
      mutation AttackPatternEdit($id: ID!, $input: StixMetaRelationshipAddInput!) {
        attackPatternEdit(id: $id) {
          relationAdd(input: $input) {
            id
            from {
              ... on AttackPattern {
                objectMarking {
                  edges {
                    node {
                      id
                      standard_id
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
          toId: 'marking-definition--78ca4366-f5b8-4764-83f7-34ce38198e27',
          relationship_type: 'object-marking',
        },
      },
    });
    expect(queryResult.data.attackPatternEdit.relationAdd.from.objectMarking.edges.length).toEqual(1);
  });
  it('should delete relation in attackPattern', async () => {
    const RELATION_DELETE_QUERY = gql`
      mutation AttackPatternEdit($id: ID!, $toId: StixRef!, $relationship_type: String!) {
        attackPatternEdit(id: $id) {
          relationDelete(toId: $toId, relationship_type: $relationship_type) {
            id
            objectMarking {
              edges {
                node {
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
      query: RELATION_DELETE_QUERY,
      variables: {
        id: attackPatternInternalId,
        toId: 'marking-definition--78ca4366-f5b8-4764-83f7-34ce38198e27',
        relationship_type: 'object-marking',
      },
    });
    expect(queryResult.data.attackPatternEdit.relationDelete.objectMarking.edges.length).toEqual(0);
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
