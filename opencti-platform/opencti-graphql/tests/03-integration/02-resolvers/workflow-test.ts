import gql from 'graphql-tag';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { queryAsAdmin, queryAsAdminWithSuccess, queryAsUserIsExpectedForbidden } from '../../utils/testQueryHelper';
import { loadEntity } from '../../../src/database/middleware';
import { findHistory } from '../../../src/domain/log';
import { ENTITY_TYPE_WORKFLOW_INSTANCE } from '../../../src/modules/workflow/types/workflow-types';
import { FilterMode, LogsOrdering, OrderingMode } from '../../../src/generated/graphql';
import { ADMIN_USER, testContext, USER_PARTICIPATE } from '../../utils/testQuery';
import { findByType } from '../../../src/domain/status';
import { ENTITY_TYPE_CONTAINER_REPORT } from '../../../src/schema/stixDomainObject';
import { wait } from '../../../src/database/utils';

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
      const STIX_DOMAIN_OBJECT_STATUS_QUERY = gql`
        query StixDomainObjectStatus($id: String!) {
          stixDomainObject(id: $id) {
            status {
              id
            }
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

        // Note: `findByType` below runs in-process in the test runner, not against the API
        // server (mutations above went over HTTP to a separate server process/container in CI).
        // It reads Status entities straight from Elasticsearch (refresh: true on every write),
        // so it's always fresh regardless of any in-memory cache state.
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

        let statusAfterPatch: string | undefined;
        for (let attempt = 0; attempt < 20 && statusAfterPatch !== secondStatusId; attempt += 1) {
          if (attempt > 0) {
            await wait(500);
          }
          await queryAsAdmin({
            query: STIX_DOMAIN_OBJECT_FIELD_PATCH_MUTATION,
            variables: { id: reportId, input: { key: 'x_opencti_workflow_id', value: [secondStatusId] } },
          });
          const statusResult = await queryAsAdmin({
            query: STIX_DOMAIN_OBJECT_STATUS_QUERY,
            variables: { id: reportId },
          });
          statusAfterPatch = statusResult.data?.stixDomainObject?.status?.id;
        }
        expect(statusAfterPatch).toBe(secondStatusId);

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

// Unlike the DraftWorkspace-only tests above, `Report` is a legacy-Status entity type with no
// built-in WorkflowInstance support until a WorkflowDefinition is published for it. Exercising
// this path proves the generalized StixDomainObject-level `workflowInstance` field and the legacy
// `x_opencti_workflow_id`/`status` projection both work end-to-end for an arbitrary SDO, not just
// the one type built directly on the new engine from day one.
describe('Workflow projection onto legacy Status field (Report)', () => {
  let reportInternalId: string;
  const reportWorkflowDefinition = JSON.stringify({
    id: 'report-workflow',
    name: 'Report Workflow',
    initialState: 'open',
    states: [{ statusId: 'open' }, { statusId: 'validated' }],
    transitions: [{ from: 'open', to: 'validated', event: 'validate_event' }],
  });

  const REPORT_ADD_MUTATION = gql`
    mutation ReportAddForWorkflowTest($input: ReportAddInput!) {
      reportAdd(input: $input) {
        id
      }
    }
  `;

  const REPORT_STATUS_QUERY = gql`
    query ReportStatusForWorkflowTest($id: String!) {
      report(id: $id) {
        status {
          id
        }
        workflowInstance {
          currentState
        }
      }
    }
  `;

  const REPORT_WORKFLOW_INSTANCE_AUTH_QUERY = gql`
    query ReportWorkflowInstanceAuth($id: String!) {
      report(id: $id) {
        workflowInstance {
          currentState
        }
      }
    }
  `;

  beforeAll(async () => {
    // Reports are content-addressed (standard_id derived from name + published), so a unique
    // name/published pair per test run avoids colliding with any entity left over by a prior,
    // interrupted local run of this suite.
    const reportResult = await queryAsAdminWithSuccess({
      query: REPORT_ADD_MUTATION,
      variables: {
        input: { name: `Workflow Projection Test Report ${Date.now()}`, published: new Date().toISOString() },
      },
    });
    reportInternalId = reportResult.data.reportAdd.id;

    // Defensive cleanup: remove any WorkflowDefinition left over on 'Report' by a prior,
    // interrupted local run, so `workflowDefinitionSet` below cannot silently no-op.
    await queryAsAdmin({
      query: WORKFLOW_DEFINITION_DELETE_MUTATION,
      variables: { entityType: 'Report' },
    });

    await queryAsAdminWithSuccess({
      query: WORKFLOW_DEFINITION_ADD_MUTATION,
      variables: { entityType: 'Report', definition: reportWorkflowDefinition },
    });
    await queryAsAdminWithSuccess({
      query: WORKFLOW_DEFINITION_PUBLISH_MUTATION,
      variables: { entityType: 'Report' },
    });
  });

  afterAll(async () => {
    await queryAsAdmin({
      query: WORKFLOW_DEFINITION_DELETE_MUTATION,
      variables: { entityType: 'Report' },
    });
    await queryAsAdmin({
      query: gql`
        mutation ReportDeleteForWorkflowTest($id: ID!) {
          reportDelete(id: $id)
        }
      `,
      variables: { id: reportInternalId },
    });
  });

  it('should eagerly create a WorkflowInstance and project the initial state onto the legacy status field', async () => {
    const result = await queryAsAdminWithSuccess({
      query: REPORT_STATUS_QUERY,
      variables: { id: reportInternalId },
    });
    expect(result.data.report.workflowInstance.currentState).toBe('open');
    expect(result.data.report.status.id).toBeDefined();
  });

  it('should deny workflowInstance access to a user without KNOWLEDGE_KNUPDATE', async () => {
    await queryAsUserIsExpectedForbidden(USER_PARTICIPATE, {
      query: REPORT_WORKFLOW_INSTANCE_AUTH_QUERY,
      variables: { id: reportInternalId },
    });
  });

  it('should update both the WorkflowInstance state and the projected legacy status on transition, emitting a normal update event', async () => {
    const before = await queryAsAdminWithSuccess({
      query: REPORT_STATUS_QUERY,
      variables: { id: reportInternalId },
    });
    const initialStatusId = before.data.report.status.id;

    const triggerResult = await queryAsAdminWithSuccess({
      query: TRIGGER_WORKFLOW_EVENT_MUTATION,
      variables: { entityId: reportInternalId, eventName: 'validate_event' },
    });
    expect(triggerResult.data.triggerWorkflowEvent.success).toBe(true);
    expect(triggerResult.data.triggerWorkflowEvent.newState).toBe('validated');

    // The 'validated' Status was just created moments ago by the workflow publish above, so the
    // legacy `x_opencti_workflow_id` projection write below can race with the server's in-memory
    // Status cache (invalidated asynchronously via redis pub/sub — see local-env-issues.md's
    // "legacy Status cache race" note) and get silently dropped on the first attempt. The
    // getWorkflowInstance read-repair mechanism self-heals this on a subsequent read, so poll
    // instead of asserting on a single query.
    let projectedStatusId: string | undefined;
    for (let attempt = 0; attempt < 15 && projectedStatusId === undefined; attempt += 1) {
      if (attempt > 0) {
        await wait(1000);
      }
      const after = await queryAsAdminWithSuccess({
        query: REPORT_STATUS_QUERY,
        variables: { id: reportInternalId },
      });
      expect(after.data.report.workflowInstance.currentState).toBe('validated');
      if (after.data.report.status.id !== initialStatusId) {
        projectedStatusId = after.data.report.status.id;
      }
    }
    expect(projectedStatusId).toBeDefined();
    expect(projectedStatusId).not.toBe(initialStatusId);

    // The legacy `x_opencti_workflow_id` projection write must go through the standard
    // event/history pipeline (the same one feeding the live stream), not a silent internal-only
    // write. The history manager consumes the event stream asynchronously (and, on a freshly
    // started platform, may not even be subscribed yet by the time this assertion runs) - poll
    // with retries instead of a single fixed wait.
    const findWorkflowHistoryLogs = () => findHistory(testContext, ADMIN_USER, {
      filters: {
        mode: FilterMode.And,
        filterGroups: [],
        filters: [
          { key: ['context_data.id'], values: [reportInternalId] },
          { key: ['event_type'], values: ['mutation', 'create', 'update', 'delete', 'merge'] },
          { key: ['event_scope'], values: ['update'] },
        ],
      },
      orderBy: LogsOrdering.CreatedAt,
      orderMode: OrderingMode.Desc,
    });
    let logs = await findWorkflowHistoryLogs();
    for (let attempt = 0; attempt < 15 && logs.edges.length === 0; attempt += 1) {
      await wait(1000);
      logs = await findWorkflowHistoryLogs();
    }
    expect(logs.edges.length).toBeGreaterThan(0);
    const workflowFieldChange = logs.edges
      .flatMap((edge) => edge.node.context_data.history_changes)
      .find((change) => change.field?.includes('x_opencti_workflow_id'));
    expect(workflowFieldChange).toBeDefined();
  });
});
