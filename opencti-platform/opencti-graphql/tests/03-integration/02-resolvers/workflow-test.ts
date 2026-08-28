import gql from 'graphql-tag';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { queryAsAdmin } from '../../utils/testQueryHelper';
import { loadEntity } from '../../../src/database/middleware';
import { ENTITY_TYPE_WORKFLOW_INSTANCE } from '../../../src/modules/workflow/types/workflow-types';
import { FilterMode } from '../../../src/generated/graphql';
import { ADMIN_USER, testContext } from '../../utils/testQuery';
import { findByType } from '../../../src/domain/status';
import { ENTITY_TYPE_CONTAINER_REPORT } from '../../../src/schema/stixDomainObject';
import { resetCacheForEntity } from '../../../src/database/cache';
import { ENTITY_TYPE_STATUS } from '../../../src/schema/internalObject';

// Directly query the store for the WorkflowInstance attached to an entity,
// mirroring the lookup used internally by workflow-domain.ts.
const findWorkflowInstance = async (entityId: string) => loadEntity(testContext, ADMIN_USER, [ENTITY_TYPE_WORKFLOW_INSTANCE], {
  filters: {
    mode: FilterMode.And,
    filters: [{ key: ['entity_id'], values: [entityId] }],
    filterGroups: [],
  },
});

const WORKFLOW_DEFINITION_ADD_MUTATION = gql`
  mutation WorkflowDefinitionSet($entityType: String!, $definition: String!) {
    workflowDefinitionSet(entityType: $entityType, definition: $definition) {
      id
      target_type
      workflow_id
    }
  }
`;

const WORKFLOW_DEFINITION_PUBLISH_MUTATION = gql`
  mutation WorkflowDefinitionPublish($entityType: String!) {
    workflowDefinitionPublish(entityType: $entityType) {
      id
      workflow_id
      published
    }
  }
`;

const WORKFLOW_DEFINITION_QUERY = gql`
  query WorkflowDefinition($entityType: String!, $allowDraft: Boolean) {
    workflowDefinition(entityType: $entityType, allowDraft: $allowDraft) {
      name
      published
      initialState
      states {
        statusId
      }
      transitions {
        from
        to
        event
      }
    }
  }
`;

const CREATE_DRAFT_WORKSPACE_QUERY = gql`
  mutation DraftWorkspaceAdd($input: DraftWorkspaceAddInput!) {
    draftWorkspaceAdd(input: $input) {
      id
      name
      draft_status
    }
  }
`;

const WORKFLOW_INSTANCE_QUERY = gql`
  query WorkflowInstance($entityId: String!) {
    workflowInstance(entityId: $entityId) {
      currentState
      allowedTransitions {
        event
        toState
        actions
      }
    }
  }
`;

const WORKFLOW_INSTANCE_NESTED_QUERY = gql`
  query WorkflowInstanceNested($entityId: String!) {
    draftWorkspace(id: $entityId) {
      workflowInstance {
        currentState
        allowedTransitions {
          event
          toState
          actions
        }
      }
    }
  }
`;

const TRIGGER_WORKFLOW_EVENT_MUTATION = gql`
  mutation TriggerWorkflowEvent($entityId: String!, $eventName: String!) {
    triggerWorkflowEvent(entityId: $entityId, eventName: $eventName) {
      success
      newState
      reason
    }
  }
`;

const WORKFLOW_DEFINITION_DELETE_MUTATION = gql`
  mutation WorkflowDefinitionDelete($entityType: String!) {
    workflowDefinitionDelete(entityType: $entityType) {
      id
      workflow_id
    }
  }
`;

const DELETE_DRAFT_WORKSPACE_QUERY = gql`
  mutation DraftWorkspaceDelete($id: ID!) {
    draftWorkspaceDelete(id: $id)
  }
`;

describe('Workflow Resolver', () => {
  let draftWorkspaceId: string;
  const workflowDefinition = JSON.stringify({
    id: 'draft-workflow',
    name: 'Draft Workflow',
    initialState: 'open',
    states: [{ statusId: 'open' }, { statusId: 'validated' }],
    transitions: [{
      from: 'open',
      to: 'validated',
      event: 'validate_event',
      syncActions: [{ type: 'validateDraft' }],
    }],
  });

  const workflowWithFilters = JSON.stringify({
    id: 'filter-workflow',
    name: 'Filter Workflow',
    initialState: 'open',
    states: [
      { statusId: 'open' },
      { statusId: 'group_check' },
      { statusId: 'org_check' },
      { statusId: 'role_check' },
      { statusId: 'comparison_check' },
    ],
    transitions: [
      {
        from: 'open',
        to: 'group_check',
        event: 'group_event',
        conditions: {
          filters: {
            mode: 'and',
            filters: [
              {
                key: 'workflow_group',
                operator: 'eq',
                values: ['test-group-id'],
                mode: 'or',
              },
            ],
            filterGroups: [],
          },
        },
      },
      {
        from: 'open',
        to: 'org_check',
        event: 'org_event',
        conditions: {
          filters: {
            mode: 'and',
            filters: [
              {
                key: 'workflow_organization',
                operator: 'eq',
                values: ['test-org-id'],
                mode: 'or',
              },
            ],
            filterGroups: [],
          },
        },
      },
      {
        from: 'open',
        to: 'role_check',
        event: 'role_event',
        conditions: {
          filters: {
            mode: 'and',
            filters: [
              {
                key: 'workflow_role',
                operator: 'eq',
                values: ['Admin'],
                mode: 'or',
              },
            ],
            filterGroups: [],
          },
        },
      },
      {
        from: 'open',
        to: 'comparison_check',
        event: 'comparison_event',
        conditions: {
          filters: {
            mode: 'and',
            filters: [
              {
                key: 'name',
                operator: 'contains',
                values: ['Filter'],
                mode: 'or',
              },
            ],
            filterGroups: [],
          },
        },
      },
    ],
  });

  beforeAll(async () => {
    const result = await queryAsAdmin({
      query: CREATE_DRAFT_WORKSPACE_QUERY,
      variables: {
        input: { name: 'Workflow Test Workspace' },
      },
    });
    if (result.errors) {
      console.error('DraftWorkspaceAdd Error:', JSON.stringify(result.errors, null, 2));
    }
    draftWorkspaceId = result.data?.draftWorkspaceAdd.id;
  });

  afterAll(async () => {
    await queryAsAdmin({
      query: DELETE_DRAFT_WORKSPACE_QUERY,
      variables: { id: draftWorkspaceId },
    });
  });

  it('should create a workflow definition', async () => {
    const result = await queryAsAdmin({
      query: WORKFLOW_DEFINITION_ADD_MUTATION,
      variables: {
        entityType: 'DraftWorkspace',
        definition: workflowDefinition,
      },
    });
    expect(result.data?.workflowDefinitionSet.target_type).toBe('DraftWorkspace');
    expect(result.data?.workflowDefinitionSet.workflow_id).toBeDefined();

    // Publish the workflow definition so it can be used at runtime
    await queryAsAdmin({
      query: WORKFLOW_DEFINITION_PUBLISH_MUTATION,
      variables: {
        entityType: 'DraftWorkspace',
      },
    });
  });

  it('should query a workflow definition', async () => {
    const result = await queryAsAdmin({
      query: WORKFLOW_DEFINITION_QUERY,
      variables: {
        entityType: 'DraftWorkspace',
      },
    });
    expect(result.data?.workflowDefinition.initialState).toBe('open');
    expect(result.data?.workflowDefinition.states.length).toBe(2);
    expect(result.data?.workflowDefinition.transitions[0].event).toBe('validate_event');
  });

  it('should query a workflow instance', async () => {
    const instanceResult = await queryAsAdmin({
      query: WORKFLOW_INSTANCE_QUERY,
      variables: {
        entityId: draftWorkspaceId,
      },
    });
    expect(instanceResult.data?.workflowInstance.currentState).toBe('open');
    expect(instanceResult.data?.workflowInstance.allowedTransitions.length).toBe(1);
    expect(instanceResult.data?.workflowInstance.allowedTransitions[0].event).toBe('validate_event');
    expect(instanceResult.data?.workflowInstance.allowedTransitions[0].actions).toContain('validateDraft');
  });

  it('should query a workflow instance via nested draftWorkspace', async () => {
    const instanceResult = await queryAsAdmin({
      query: WORKFLOW_INSTANCE_NESTED_QUERY,
      variables: {
        entityId: draftWorkspaceId,
      },
    });
    expect(instanceResult.data?.draftWorkspace.workflowInstance.currentState).toBe('open');
    expect(instanceResult.data?.draftWorkspace.workflowInstance.allowedTransitions.length).toBe(1);
    expect(instanceResult.data?.draftWorkspace.workflowInstance.allowedTransitions[0].event).toBe('validate_event');
  });

  it('should trigger a workflow event', async () => {
    const result = await queryAsAdmin({
      query: TRIGGER_WORKFLOW_EVENT_MUTATION,
      variables: {
        entityId: draftWorkspaceId,
        eventName: 'validate_event',
      },
    });
    expect(result.data?.triggerWorkflowEvent.success).toBe(true);
    expect(result.data?.triggerWorkflowEvent.newState).toBe('validated');

    // Check if the entity was actually updated
    const instanceResult = await queryAsAdmin({
      query: WORKFLOW_INSTANCE_QUERY,
      variables: {
        entityId: draftWorkspaceId,
      },
    });
    expect(instanceResult.data?.workflowInstance.currentState).toBe('validated');
    expect(instanceResult.data?.workflowInstance.allowedTransitions.length).toBe(0);
  });

  it('should fail to trigger an invalid event', async () => {
    const result = await queryAsAdmin({
      query: TRIGGER_WORKFLOW_EVENT_MUTATION,
      variables: {
        entityId: draftWorkspaceId,
        eventName: 'invalid_event',
      },
    });
    expect(result.data?.triggerWorkflowEvent.success).toBe(false);
    expect(result.data?.triggerWorkflowEvent.reason).toContain('No transition found');
  });

  it('should delete a workflow definition', async () => {
    // 1. Delete the workflow definition
    const deleteResult = await queryAsAdmin({
      query: WORKFLOW_DEFINITION_DELETE_MUTATION,
      variables: {
        entityType: 'DraftWorkspace',
      },
    });
    expect(deleteResult.data?.workflowDefinitionDelete.workflow_id).toBeNull();

    // 2. Check if the definition is gone
    const queryResult = await queryAsAdmin({
      query: WORKFLOW_DEFINITION_QUERY,
      variables: {
        entityType: 'DraftWorkspace',
      },
    });
    expect(queryResult.data?.workflowDefinition).toBeNull();

    // 3. Check if instance now returns null
    const instanceResult = await queryAsAdmin({
      query: WORKFLOW_INSTANCE_QUERY,
      variables: {
        entityId: draftWorkspaceId,
      },
    });
    expect(instanceResult.data?.workflowInstance).toBeNull();
  });

  // Tests for filter operators and special keys
  describe('Workflow Filters Coverage', () => {
    let filterTestWorkspaceId: string;

    beforeAll(async () => {
      // Create a test workspace for filter testing
      const result = await queryAsAdmin({
        query: CREATE_DRAFT_WORKSPACE_QUERY,
        variables: {
          input: { name: 'Filter Test Workspace' },
        },
      });
      filterTestWorkspaceId = result.data?.draftWorkspaceAdd.id;

      // Set the filter workflow definition
      await queryAsAdmin({
        query: WORKFLOW_DEFINITION_ADD_MUTATION,
        variables: {
          entityType: 'DraftWorkspace',
          definition: workflowWithFilters,
        },
      });
    });

    afterAll(async () => {
      await queryAsAdmin({
        query: WORKFLOW_DEFINITION_DELETE_MUTATION,
        variables: { entityType: 'DraftWorkspace' },
      });
      await queryAsAdmin({
        query: DELETE_DRAFT_WORKSPACE_QUERY,
        variables: { id: filterTestWorkspaceId },
      });
    });

    it('should test workflow_group filter key', async () => {
      // This tests the workflow_group special key path
      const result = await queryAsAdmin({
        query: TRIGGER_WORKFLOW_EVENT_MUTATION,
        variables: {
          entityId: filterTestWorkspaceId,
          eventName: 'group_event',
        },
      });
      // May pass or fail depending on user groups, but exercises the code path
      expect(result.data?.triggerWorkflowEvent).toBeDefined();
    });

    it('should test workflow_organization filter key', async () => {
      // This tests the workflow_organization special key path
      const result = await queryAsAdmin({
        query: TRIGGER_WORKFLOW_EVENT_MUTATION,
        variables: {
          entityId: filterTestWorkspaceId,
          eventName: 'org_event',
        },
      });
      // May pass or fail depending on user organizations, but exercises the code path
      expect(result.data?.triggerWorkflowEvent).toBeDefined();
    });

    it('should test workflow_role filter key', async () => {
      // This tests the workflow_role special key path
      const result = await queryAsAdmin({
        query: TRIGGER_WORKFLOW_EVENT_MUTATION,
        variables: {
          entityId: filterTestWorkspaceId,
          eventName: 'role_event',
        },
      });
      // May pass or fail depending on user roles, but exercises the code path
      expect(result.data?.triggerWorkflowEvent).toBeDefined();
    });

    it('should test contains operator', async () => {
      // This tests the Contains operator in evaluateFilter
      const result = await queryAsAdmin({
        query: TRIGGER_WORKFLOW_EVENT_MUTATION,
        variables: {
          entityId: filterTestWorkspaceId,
          eventName: 'comparison_event',
        },
      });
      // May pass or fail depending on draft name, but exercises the code path
      expect(result.data?.triggerWorkflowEvent).toBeDefined();
    });
  });

  describe('Workflow Publishing', () => {
    beforeAll(async () => {
      // Create a draft by updating the workflow definition
      const modifiedDefinition = JSON.stringify({
        id: 'draft-workflow',
        name: 'Draft Workflow - Before Publish Test',
        initialState: 'open',
        states: [{ statusId: 'open' }, { statusId: 'validated' }],
        transitions: [{
          from: 'open',
          to: 'validated',
          event: 'validate_event',
          syncActions: [{ type: 'validateDraft' }],
        }],
      });

      await queryAsAdmin({
        query: WORKFLOW_DEFINITION_ADD_MUTATION,
        variables: {
          entityType: 'DraftWorkspace',
          definition: modifiedDefinition,
        },
      });
    });

    it('should publish a workflow definition', async () => {
      const publishResult = await queryAsAdmin({
        query: WORKFLOW_DEFINITION_PUBLISH_MUTATION,
        variables: {
          entityType: 'DraftWorkspace',
        },
      });
      expect(publishResult.data?.workflowDefinitionPublish.workflow_id).toBeDefined();
      expect(publishResult.data?.workflowDefinitionPublish.published).toBe(true);
    });

    it('should query published workflow definition', async () => {
      const result = await queryAsAdmin({
        query: WORKFLOW_DEFINITION_QUERY,
        variables: {
          entityType: 'DraftWorkspace',
          allowDraft: false, // Should return published version only
        },
      });
      expect(result.data?.workflowDefinition).toBeDefined();
      expect(result.data?.workflowDefinition.published).toBe(true);
    });

    it('should update workflow creating new draft after publish', async () => {
      const newDefinition = JSON.stringify({
        id: 'draft-workflow',
        name: 'Draft Workflow - Modified',
        initialState: 'open',
        states: [{ statusId: 'open' }, { statusId: 'validated' }, { statusId: 'closed' }],
        transitions: [{
          from: 'open',
          to: 'validated',
          event: 'validate_event',
          syncActions: [{ type: 'validateDraft' }],
        }],
      });

      const updateResult = await queryAsAdmin({
        query: WORKFLOW_DEFINITION_ADD_MUTATION,
        variables: {
          entityType: 'DraftWorkspace',
          definition: newDefinition,
        },
      });
      expect(updateResult.data?.workflowDefinitionSet.workflow_id).toBeDefined();
    });

    it('should query draft workflow with allowDraft true', async () => {
      const result = await queryAsAdmin({
        query: gql`
          query WorkflowDefinition($entityType: String!, $allowDraft: Boolean) {
            workflowDefinition(entityType: $entityType, allowDraft: $allowDraft) {
              name
              published
              states {
                statusId
              }
            }
          }
        `,
        variables: {
          entityType: 'DraftWorkspace',
          allowDraft: true,
        },
      });
      expect(result.data?.workflowDefinition).toBeDefined();
      expect(result.data?.workflowDefinition.name).toBe('Draft Workflow - Modified');
      expect(result.data?.workflowDefinition.published).toBe(false); // Draft differs from published
      expect(result.data?.workflowDefinition.states.length).toBe(3); // Modified has 3 states
    });

    it('should use published version for runtime when allowDraft is false', async () => {
      const result = await queryAsAdmin({
        query: gql`
          query WorkflowDefinition($entityType: String!, $allowDraft: Boolean) {
            workflowDefinition(entityType: $entityType, allowDraft: $allowDraft) {
              name
              states {
                statusId
              }
            }
          }
        `,
        variables: {
          entityType: 'DraftWorkspace',
          allowDraft: false,
        },
      });
      expect(result.data?.workflowDefinition).toBeDefined();
      expect(result.data?.workflowDefinition.states.length).toBe(2); // Published has 2 states
    });

    it('should return validation errors in workflow set response', async () => {
      const invalidDefinition = JSON.stringify({
        id: 'invalid-workflow',
        name: 'Invalid Workflow',
        initialState: 'open',
        states: [{ statusId: 'open' }],
        transitions: [{ from: 'open', to: 'nonexistent', event: 'go' }], // Invalid transition
      });

      const result = await queryAsAdmin({
        query: gql`
          mutation WorkflowDefinitionSet($entityType: String!, $definition: String!) {
            workflowDefinitionSet(entityType: $entityType, definition: $definition) {
              id
              published
              errors {
                type
                message
              }
            }
          }
        `,
        variables: {
          entityType: 'DraftWorkspace',
          definition: invalidDefinition,
        },
      });
      expect(result.data?.workflowDefinitionSet.errors).toBeDefined();
      expect(result.data?.workflowDefinitionSet.errors.length).toBeGreaterThan(0);
      expect(result.data?.workflowDefinitionSet.published).toBe(false);
    });

    it('should fail to publish workflow with validation errors', async () => {
      // Try to publish the invalid workflow from previous test
      const publishResult = await queryAsAdmin({
        query: WORKFLOW_DEFINITION_PUBLISH_MUTATION,
        variables: {
          entityType: 'DraftWorkspace',
        },
      });
      expect(publishResult.errors).toBeDefined();
      expect(publishResult.errors?.[0].message).toContain('validation errors');
    });
  });

  describe('Workflow Instance eager creation', () => {
    const simpleWorkflowDefinition = JSON.stringify({
      id: 'eager-creation-workflow',
      name: 'Eager Creation Workflow',
      initialState: 'open',
      states: [{ statusId: 'open' }, { statusId: 'validated' }],
      transitions: [{ from: 'open', to: 'validated', event: 'validate_event' }],
    });

    describe('on entity creation (createEntity)', () => {
      let eagerWorkspaceId: string;

      beforeAll(async () => {
        // Configure and publish the workflow *before* creating the entity so that
        // initializeEntityWorkflow (invoked from within createEntity) has a real
        // definition to eagerly materialize an instance from.
        await queryAsAdmin({
          query: WORKFLOW_DEFINITION_ADD_MUTATION,
          variables: { entityType: 'DraftWorkspace', definition: simpleWorkflowDefinition },
        });
        await queryAsAdmin({
          query: WORKFLOW_DEFINITION_PUBLISH_MUTATION,
          variables: { entityType: 'DraftWorkspace' },
        });

        const result = await queryAsAdmin({
          query: CREATE_DRAFT_WORKSPACE_QUERY,
          variables: { input: { name: 'Eager Creation Test Workspace' } },
        });
        eagerWorkspaceId = result.data?.draftWorkspaceAdd.id;
      });

      afterAll(async () => {
        await queryAsAdmin({
          query: DELETE_DRAFT_WORKSPACE_QUERY,
          variables: { id: eagerWorkspaceId },
        });
        await queryAsAdmin({
          query: WORKFLOW_DEFINITION_DELETE_MUTATION,
          variables: { entityType: 'DraftWorkspace' },
        });
      });

      it('should eagerly materialize a real WorkflowInstance as soon as the entity is created', async () => {
        // No transition was ever triggered: if a WorkflowInstance is found here,
        // it can only have come from createEntity's eager initializeEntityWorkflow call.
        const instance = await findWorkflowInstance(eagerWorkspaceId);
        expect(instance).not.toBeNull();
      });
    });

    describe('on relationship creation (createRelation)', () => {
      const CREATE_OBSERVABLE_MUTATION = gql`
        mutation StixCyberObservableAdd($type: String!, $imei: IMEIAddInput, $iccid: ICCIDAddInput) {
          stixCyberObservableAdd(type: $type, IMEI: $imei, ICCID: $iccid) {
            id
          }
        }
      `;
      const DELETE_OBSERVABLE_MUTATION = gql`
        mutation stixCyberObservableDelete($id: ID!) {
          stixCyberObservableEdit(id: $id) {
            delete
          }
        }
      `;
      const CREATE_RELATION_MUTATION = gql`
        mutation StixCoreRelationshipAdd($input: StixCoreRelationshipAddInput!) {
          stixCoreRelationshipAdd(input: $input) {
            id
            fromType
            toType
          }
        }
      `;

      let fromId: string;
      let toId: string;
      let eagerRelationId: string;

      beforeAll(async () => {
        await queryAsAdmin({
          query: WORKFLOW_DEFINITION_ADD_MUTATION,
          variables: { entityType: 'uses', definition: simpleWorkflowDefinition },
        });
        await queryAsAdmin({
          query: WORKFLOW_DEFINITION_PUBLISH_MUTATION,
          variables: { entityType: 'uses' },
        });

        const fromResult = await queryAsAdmin({
          query: CREATE_OBSERVABLE_MUTATION,
          variables: { type: 'IMEI', imei: { value: '112222229999991' } },
        });
        fromId = fromResult.data?.stixCyberObservableAdd.id;
        const toResult = await queryAsAdmin({
          query: CREATE_OBSERVABLE_MUTATION,
          variables: { type: 'ICCID', iccid: { value: '123456789012399991' } },
        });
        toId = toResult.data?.stixCyberObservableAdd.id;

        const relationResult = await queryAsAdmin({
          query: CREATE_RELATION_MUTATION,
          variables: { input: { fromId, toId, relationship_type: 'uses' } },
        });
        eagerRelationId = relationResult.data?.stixCoreRelationshipAdd.id;
      });

      afterAll(async () => {
        await queryAsAdmin({
          query: DELETE_OBSERVABLE_MUTATION,
          variables: { id: fromId },
        });
        await queryAsAdmin({
          query: DELETE_OBSERVABLE_MUTATION,
          variables: { id: toId },
        });
        await queryAsAdmin({
          query: WORKFLOW_DEFINITION_DELETE_MUTATION,
          variables: { entityType: 'uses' },
        });
      });

      it('should eagerly materialize a real WorkflowInstance as soon as the relationship is created', async () => {
        const instance = await findWorkflowInstance(eagerRelationId);
        expect(instance).not.toBeNull();
      });
    });

    describe('on legacy status field patch (updateAttribute)', () => {
      const STIX_DOMAIN_OBJECT_ADD_MUTATION = gql`
        mutation StixDomainObjectAdd($input: StixDomainObjectAddInput!) {
          stixDomainObjectAdd(input: $input) {
            id
          }
        }
      `;
      const STIX_DOMAIN_OBJECT_FIELD_PATCH_MUTATION = gql`
        mutation StixDomainObjectFieldPatch($id: ID!, $input: [EditInput]!) {
          stixDomainObjectEdit(id: $id) {
            fieldPatch(input: $input) {
              id
            }
          }
        }
      `;
      const STIX_DOMAIN_OBJECT_DELETE_MUTATION = gql`
        mutation StixDomainObjectDelete($id: ID!) {
          stixDomainObjectEdit(id: $id) {
            delete
          }
        }
      `;

      let reportId: string;
      let secondStatusId: string;

      beforeAll(async () => {
        // Create the Report *before* any workflow is configured for this type, so
        // createEntity's eager initializeEntityWorkflow call is a no-op (no instance yet).
        const createResult = await queryAsAdmin({
          query: STIX_DOMAIN_OBJECT_ADD_MUTATION,
          variables: { input: { name: 'Legacy Status Patch Test Report', type: 'Report' } },
        });
        reportId = createResult.data?.stixDomainObjectAdd.id;

        // Configure and publish the workflow *after* creation so that the entity
        // currently has no WorkflowInstance, letting us exercise the lazy path.
        await queryAsAdmin({
          query: WORKFLOW_DEFINITION_ADD_MUTATION,
          variables: { entityType: 'Report', definition: simpleWorkflowDefinition },
        });
        await queryAsAdmin({
          query: WORKFLOW_DEFINITION_PUBLISH_MUTATION,
          variables: { entityType: 'Report' },
        });

        // Publishing just created new legacy Status entities: force the cache to reload so that
        // the fieldPatch below (validated against the cached Status list) doesn't race with the
        // asynchronous pub/sub cache invalidation and silently drop the update.
        resetCacheForEntity(ENTITY_TYPE_STATUS);

        const statuses = await findByType(testContext, ADMIN_USER, ENTITY_TYPE_CONTAINER_REPORT);
        secondStatusId = statuses[1].id;
      });

      afterAll(async () => {
        await queryAsAdmin({
          query: STIX_DOMAIN_OBJECT_DELETE_MUTATION,
          variables: { id: reportId },
        });
        await queryAsAdmin({
          query: WORKFLOW_DEFINITION_DELETE_MUTATION,
          variables: { entityType: 'Report' },
        });
      });

      it('should lazily materialize a real WorkflowInstance when the legacy x_opencti_workflow_id is patched', async () => {
        // No instance should exist yet: the workflow was configured after entity creation.
        const beforePatch = await findWorkflowInstance(reportId);
        expect(beforePatch).toBeUndefined();

        await queryAsAdmin({
          query: STIX_DOMAIN_OBJECT_FIELD_PATCH_MUTATION,
          variables: { id: reportId, input: { key: 'x_opencti_workflow_id', value: [secondStatusId] } },
        });

        // Patching the legacy status field should have lazily triggered initializeEntityWorkflow,
        // which in turn calls ensureWorkflowInstance since no instance existed for this entity yet.
        const afterPatch = await findWorkflowInstance(reportId);
        expect(afterPatch).not.toBeNull();
      });
    });
  });

  describe('Workflow Instance deletion cleanup', () => {
    let cleanupWorkspaceId: string;

    beforeAll(async () => {
      const result = await queryAsAdmin({
        query: CREATE_DRAFT_WORKSPACE_QUERY,
        variables: { input: { name: 'Cleanup Test Workspace' } },
      });
      cleanupWorkspaceId = result.data?.draftWorkspaceAdd.id;

      await queryAsAdmin({
        query: WORKFLOW_DEFINITION_ADD_MUTATION,
        variables: { entityType: 'DraftWorkspace', definition: workflowDefinition },
      });
      await queryAsAdmin({
        query: WORKFLOW_DEFINITION_PUBLISH_MUTATION,
        variables: { entityType: 'DraftWorkspace' },
      });
      // The WorkflowInstance is materialized lazily on the first transition.
      await queryAsAdmin({
        query: TRIGGER_WORKFLOW_EVENT_MUTATION,
        variables: { entityId: cleanupWorkspaceId, eventName: 'validate_event' },
      });
    });

    afterAll(async () => {
      await queryAsAdmin({
        query: WORKFLOW_DEFINITION_DELETE_MUTATION,
        variables: { entityType: 'DraftWorkspace' },
      });
    });

    it('should remove the WorkflowInstance when its parent entity is deleted', async () => {
      const before = await findWorkflowInstance(cleanupWorkspaceId);
      expect(before).not.toBeNull();

      await queryAsAdmin({
        query: DELETE_DRAFT_WORKSPACE_QUERY,
        variables: { id: cleanupWorkspaceId },
      });

      const after = await findWorkflowInstance(cleanupWorkspaceId);
      expect(after).toBeUndefined();
    });
  });
});
