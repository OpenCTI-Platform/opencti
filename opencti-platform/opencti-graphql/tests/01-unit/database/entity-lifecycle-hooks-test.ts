import { beforeEach, describe, expect, it } from 'vitest';
import {
    __resetPostAttributeUpdateHooksForTest,
    __resetPostEntityCreationHooksForTest,
    registerPostAttributeUpdateHook,
    registerPostEntityCreationHook,
    runPostAttributeUpdateHooks,
    runPostEntityCreationHooks,
} from '../../../src/database/entity-lifecycle-hooks';

const mockContext = { user: { id: 'ctx-user-id' } } as any;
const mockUser = { id: 'user-id' } as any;

describe('entity-lifecycle-hooks', () => {
  beforeEach(() => {
    __resetPostEntityCreationHooksForTest();
  });

  it('should invoke a registered hook with the created entity after creation', async () => {
    const calls: any[] = [];
    const hook = async (context: any, user: any, entity: any) => {
      calls.push({ context, user, entity });
    };
    registerPostEntityCreationHook(hook);

    const entity = { id: 'entity-1', entity_type: 'Incident' };
    await runPostEntityCreationHooks(mockContext, mockUser, entity);

    expect(calls).toHaveLength(1);
    expect(calls[0]).toEqual({ context: mockContext, user: mockUser, entity });
  });

  it('should not affect creation when no hooks are registered', async () => {
    const entity = { id: 'entity-1', entity_type: 'Incident' };
    await expect(runPostEntityCreationHooks(mockContext, mockUser, entity)).resolves.toBeUndefined();
  });

  it('should invoke every registered hook, in registration order', async () => {
    const calls: string[] = [];
    registerPostEntityCreationHook(async () => {
      calls.push('first');
    });
    registerPostEntityCreationHook(async () => {
      calls.push('second');
    });

    await runPostEntityCreationHooks(mockContext, mockUser, { id: 'entity-1', entity_type: 'Incident' });

    expect(calls).toEqual(['first', 'second']);
  });

  it('should de-dupe registration by function reference (idempotent registration)', async () => {
    const calls: string[] = [];
    const hook = async () => {
      calls.push('called');
    };
    registerPostEntityCreationHook(hook);
    registerPostEntityCreationHook(hook);
    registerPostEntityCreationHook(hook);

    await runPostEntityCreationHooks(mockContext, mockUser, { id: 'entity-1', entity_type: 'Incident' });

    expect(calls).toEqual(['called']);
  });
});

// ===========================================================================
// Task 8, Step 0.4: second, independent hook kind for post-attribute-update side
// effects (e.g. Task 8's syncWorkflowInstanceFromExternalWrite), with the same
// zero-feature-import, decoupled-registry property as the Task 3 registry above.
// ===========================================================================
describe('entity-lifecycle-hooks — post-attribute-update', () => {
  beforeEach(() => {
    __resetPostAttributeUpdateHooksForTest();
  });

  it('should invoke a registered hook with the updated entity, field and new value', async () => {
    const calls: any[] = [];
    const hook = async (context: any, user: any, entity: any, field: any, newValue: any) => {
      calls.push({
        context, user, entity, field, newValue,
      });
    };
    registerPostAttributeUpdateHook(hook);

    const entity = { id: 'entity-1', entity_type: 'Incident' };
    await runPostAttributeUpdateHooks(mockContext, mockUser, entity, 'x_opencti_workflow_id', 'status-id');

    expect(calls).toHaveLength(1);
    expect(calls[0]).toEqual({
      context: mockContext, user: mockUser, entity, field: 'x_opencti_workflow_id', newValue: 'status-id',
    });
  });

  it('should not affect the update when no hooks are registered', async () => {
    const entity = { id: 'entity-1', entity_type: 'Incident' };
    await expect(runPostAttributeUpdateHooks(mockContext, mockUser, entity, 'x_opencti_workflow_id', 'status-id')).resolves.toBeUndefined();
  });

  it('should invoke every registered hook, in registration order', async () => {
    const calls: string[] = [];
    registerPostAttributeUpdateHook(async () => {
      calls.push('first');
    });
    registerPostAttributeUpdateHook(async () => {
      calls.push('second');
    });

    await runPostAttributeUpdateHooks(mockContext, mockUser, { id: 'entity-1', entity_type: 'Incident' }, 'x_opencti_workflow_id', 'status-id');

    expect(calls).toEqual(['first', 'second']);
  });

  it('should de-dupe registration by function reference (idempotent registration)', async () => {
    const calls: string[] = [];
    const hook = async () => {
      calls.push('called');
    };
    registerPostAttributeUpdateHook(hook);
    registerPostAttributeUpdateHook(hook);
    registerPostAttributeUpdateHook(hook);

    await runPostAttributeUpdateHooks(mockContext, mockUser, { id: 'entity-1', entity_type: 'Incident' }, 'x_opencti_workflow_id', 'status-id');

    expect(calls).toEqual(['called']);
  });

  it('should be independent from the post-entity-creation hook registry (separate reset, separate registration)', async () => {
    __resetPostEntityCreationHooksForTest();
    const creationCalls: string[] = [];
    const attributeCalls: string[] = [];
    registerPostEntityCreationHook(async () => {
      creationCalls.push('creation');
    });
    registerPostAttributeUpdateHook(async () => {
      attributeCalls.push('attribute');
    });

    await runPostAttributeUpdateHooks(mockContext, mockUser, { id: 'entity-1', entity_type: 'Incident' }, 'x_opencti_workflow_id', 'status-id');

    expect(attributeCalls).toEqual(['attribute']);
    expect(creationCalls).toEqual([]);
  });
});
