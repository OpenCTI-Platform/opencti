import { describe, expect, it } from 'vitest';
import gql from 'graphql-tag';
import { queryAsAdmin } from '../../utils/testQuery';

const LIST_QUERY = gql`
  query attackPatterns(
    $first: Int
    $after: ID
    $orderBy: AttackPatternsOrdering
    $orderMode: OrderingMode
    $filters: FilterGroup
    $search: String
  ) {
    attackPatterns(
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

const MATRIX_QUERY = gql`
  query attackPatternsMatrix {
    attackPatternsMatrix {
      attackPatternsOfPhases {
        kill_chain_id
        kill_chain_name
        phase_name
        x_opencti_order
        attackPatterns {
          attack_pattern_id
          name
          description
          x_mitre_id
          subAttackPatterns {
            attack_pattern_id
            name
            description
          }
          subAttackPatternsSearchText
          killChainPhasesIds
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
        id
        standard_id
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
      mutation AttackPatternAdd($input: AttackPatternAddInput!) {
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
    expect(queryResult.data.attackPattern.killChainPhases.length).toEqual(1);
    expect(queryResult.data.attackPattern.killChainPhases[0].standard_id).toEqual(
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
  it('should query attackPatterns matrix', async () => {
    const queryResult = await queryAsAdmin({ query: MATRIX_QUERY });
    expect(queryResult.data.attackPatternsMatrix).not.toBeNull();
    expect(queryResult.data.attackPatternsMatrix.attackPatternsOfPhases).not.toBeNull();
    expect(queryResult.data.attackPatternsMatrix.attackPatternsOfPhases.length).toEqual(2);
    expect(queryResult.data.attackPatternsMatrix.attackPatternsOfPhases[0].kill_chain_name).toEqual('mitre-pre-attack');
    expect(queryResult.data.attackPatternsMatrix.attackPatternsOfPhases[0].phase_name).toEqual('launch');
    expect(queryResult.data.attackPatternsMatrix.attackPatternsOfPhases[0].x_opencti_order).toEqual(0);
    expect(queryResult.data.attackPatternsMatrix.attackPatternsOfPhases[0].attackPatterns.length).toEqual(2);
    expect(queryResult.data.attackPatternsMatrix.attackPatternsOfPhases[1].kill_chain_name).toEqual('mitre-attack');
    expect(queryResult.data.attackPatternsMatrix.attackPatternsOfPhases[1].phase_name).toEqual('persistence');
    expect(queryResult.data.attackPatternsMatrix.attackPatternsOfPhases[1].x_opencti_order).toEqual(20);
    expect(queryResult.data.attackPatternsMatrix.attackPatternsOfPhases[1].attackPatterns.length).toEqual(1);
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
      mutation AttackPatternEdit($id: ID!, $input: StixRefRelationshipAddInput!) {
        attackPatternEdit(id: $id) {
          relationAdd(input: $input) {
            id
            from {
              ... on AttackPattern {
                objectMarking {
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
      query: RELATION_ADD_QUERY,
      variables: {
        id: attackPatternInternalId,
        input: {
          toId: 'marking-definition--78ca4366-f5b8-4764-83f7-34ce38198e27',
          relationship_type: 'object-marking',
        },
      },
    });
    expect(queryResult.data.attackPatternEdit.relationAdd.from.objectMarking.length).toEqual(1);
  });
  it('should delete relation in attackPattern', async () => {
    const RELATION_DELETE_QUERY = gql`
      mutation AttackPatternEdit($id: ID!, $toId: StixRef!, $relationship_type: String!) {
        attackPatternEdit(id: $id) {
          relationDelete(toId: $toId, relationship_type: $relationship_type) {
            id
            objectMarking {
              id
              standard_id
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
    expect(queryResult.data.attackPatternEdit.relationDelete.objectMarking.length).toEqual(0);
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
