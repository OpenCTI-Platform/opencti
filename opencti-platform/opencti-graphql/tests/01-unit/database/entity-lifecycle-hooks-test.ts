import { beforeEach, describe, expect, it } from 'vitest';
import { __resetPostEntityCreationHooksForTest, registerPostEntityCreationHook, runPostEntityCreationHooks } from '../../../src/database/entity-lifecycle-hooks';

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
