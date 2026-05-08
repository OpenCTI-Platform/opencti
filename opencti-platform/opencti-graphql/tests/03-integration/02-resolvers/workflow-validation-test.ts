import gql from 'graphql-tag';
import { describe, expect, it } from 'vitest';
import { queryAsAdmin } from '../../utils/testQueryHelper';

const WORKFLOW_DEFINITION_SET_MUTATION = gql`
  mutation WorkflowDefinitionSet($entityType: String!, $definition: String!) {
    workflowDefinitionSet(entityType: $entityType, definition: $definition) {
      id
    }
  }
`;

describe('Workflow Validation Resolver', () => {
  const entityType = 'DraftWorkspace';

  it('should reject invalid JSON', async () => {
    const result = await queryAsAdmin({
      query: WORKFLOW_DEFINITION_SET_MUTATION,
      variables: {
        entityType,
        definition: 'invalid-json',
      },
    });
    expect(result.errors?.[0].message).toBe('Invalid workflow definition JSON');
  });

  it('should reject workflow with invalid schema', async () => {
    const invalidDefinition = JSON.stringify({
      // Missing initialState and transitions
      name: 'Incomplete Workflow',
      states: [{ statusId: 'open' }],
    });
    const result = await queryAsAdmin({
      query: WORKFLOW_DEFINITION_SET_MUTATION,
      variables: {
        entityType,
        definition: invalidDefinition,
      },
    });
    expect(result.errors?.[0].message).toContain('Workflow definition schema validation failed');
  });

  it('should reject workflow for a non-basic object type', async () => {
    const definition = JSON.stringify({
      id: 'test-validation-1',
      initialState: 'open',
      states: [{ statusId: 'open' }],
      transitions: [],
    });
    const result = await queryAsAdmin({
      query: WORKFLOW_DEFINITION_SET_MUTATION,
      variables: {
        entityType: 'Malware', // Not a basic object
        definition,
      },
    });
    expect(result.errors?.[0].message).toContain('This setting is not available for this entity');
  });

  it('should reject workflow with an existing ID', async () => {
    const definition1 = JSON.stringify({
      id: 'duplicate-id',
      name: 'Workflow 1',
      initialState: 'open',
      states: [{ statusId: 'open' }],
      transitions: [],
    });
    await queryAsAdmin({
      query: WORKFLOW_DEFINITION_SET_MUTATION,
      variables: { entityType, definition: definition1 },
    });

    const definition2 = JSON.stringify({
      id: 'duplicate-id',
      name: 'Workflow 2',
      initialState: 'open',
      states: [{ statusId: 'open' }],
      transitions: [],
    });
    const result = await queryAsAdmin({
      query: WORKFLOW_DEFINITION_SET_MUTATION,
      variables: { entityType, definition: definition2 },
    });
    expect(result.errors?.[0].message).toBe('DraftWorkspace workflow must contain at least one validateDraft action');
  });

  it('should reject workflow with invalid action type', async () => {
    const definition = JSON.stringify({
      id: 'invalid-action-workflow',
      initialState: 'open',
      states: [
        {
          statusId: 'open',
          onEnter: [{ type: 'non_existent_action' }],
        },
      ],
      transitions: [],
    });
    const result = await queryAsAdmin({
      query: WORKFLOW_DEFINITION_SET_MUTATION,
      variables: { entityType, definition },
    });
    expect(result.errors?.[0].message).toContain('Side effect (action) type \'non_existent_action\' doesn\'t exist');
  });

  it('should reject workflow with invalid action mode', async () => {
    const definition = JSON.stringify({
      id: 'invalid-action-mode-workflow',
      initialState: 'open',
      states: [{ statusId: 'open' }],
      transitions: [
        {
          from: 'open',
          to: 'validated',
          event: 'validate',
          actions: [{ type: 'validateDraft', mode: 'invalid_mode' }],
        },
      ],
    });
    const result = await queryAsAdmin({
      query: WORKFLOW_DEFINITION_SET_MUTATION,
      variables: { entityType, definition },
    });
    expect(result.errors?.[0].message).toContain('Workflow definition schema validation failed');
  });

  it('should reject workflow with invalid action params', async () => {
    const definition = JSON.stringify({
      id: 'invalid-action-params-workflow',
      initialState: 'open',
      states: [
        {
          statusId: 'open',
          onEnter: [
            {
              type: 'updateAuthorizedMembers',
              params: { authorized_members: 'not-an-array' },
            },
          ],
        },
      ],
      transitions: [],
    });
    const result = await queryAsAdmin({
      query: WORKFLOW_DEFINITION_SET_MUTATION,
      variables: { entityType, definition },
    });
    expect(result.errors?.[0].message).toContain('Invalid params for action \'updateAuthorizedMembers\'');
  });

  it('should reject workflow with duplicate transition event', async () => {
    const definition = JSON.stringify({
      id: 'duplicate-event-workflow',
      initialState: 'open',
      states: [{ statusId: 'open' }, { statusId: 'state2' }],
      transitions: [
        { from: 'open', to: 'state2', event: 'my_event' },
        { from: 'open', to: 'state2', event: 'my_event' },
      ],
    });
    const result = await queryAsAdmin({
      query: WORKFLOW_DEFINITION_SET_MUTATION,
      variables: { entityType, definition },
    });
    expect(result.errors?.[0].message).toContain('Transition \'my_event\' referenced in multiple transitions');
  });

  it('should reject workflow with unreachable states', async () => {
    const definition = JSON.stringify({
      id: 'unreachable-state-workflow',
      initialState: 'open',
      states: [{ statusId: 'open' }, { statusId: 'unreachable' }],
      transitions: [],
    });
    const result = await queryAsAdmin({
      query: WORKFLOW_DEFINITION_SET_MUTATION,
      variables: { entityType, definition },
    });
    expect(result.errors?.[0].message).toContain('DraftWorkspace workflow must contain at least one validateDraft action');
  });

  it('should reject workflow with undefined transition state', async () => {
    const definition = JSON.stringify({
      id: 'undefined-state-workflow',
      initialState: 'open',
      states: [{ statusId: 'open' }],
      transitions: [{ from: 'open', to: 'undefined_state', event: 'go' }],
    });
    const result = await queryAsAdmin({
      query: WORKFLOW_DEFINITION_SET_MUTATION,
      variables: { entityType, definition },
    });
    expect(result.errors?.[0].message).toContain('DraftWorkspace workflow must contain at least one validateDraft action');
  });
});
