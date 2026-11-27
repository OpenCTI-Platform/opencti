import { describe, expect, it } from 'vitest';
import { commitLocalUpdate, commitMutation } from 'relay-runtime';
import { createMockEnvironment, MockPayloadGenerator } from 'relay-test-utils';
import { workflowStatusTriggerMutation } from './WorkflowStatus.graphql';

const ENTITY_ID = 'entity-1';

const setupRestrictedEntity = (typename: string) => {
  const environment = createMockEnvironment();
  commitLocalUpdate(environment, (store) => {
    const entity = store.create(ENTITY_ID, typename);
    entity.setValue(ENTITY_ID, 'id');
    const member = store.create(`${ENTITY_ID}_admin_0`, 'MemberAccess');
    member.setValue(`${ENTITY_ID}_admin_0`, 'id');
    member.setValue('admin', 'member_id');
    member.setValue('admin', 'access_right');
    entity.setLinkedRecords([member], 'authorized_members');
  });
  return environment;
};

const readEntity = (environment: ReturnType<typeof createMockEnvironment>) => {
  let entity: { updatedAt: unknown; memberIds: unknown[] } | undefined;
  commitLocalUpdate(environment, (store) => {
    const record = store.get(ENTITY_ID);
    entity = {
      updatedAt: record?.getValue('updated_at'),
      memberIds: (record?.getLinkedRecords('authorized_members') ?? []).map((member) => member?.getValue('member_id')),
    };
  });
  return entity;
};

describe('WorkflowStatusTriggerMutation', () => {
  it.each([
    { typename: 'Report', abstractKeys: ['__isStixDomainObject', '__isContainer'] },
    { typename: 'Organization', abstractKeys: ['__isStixDomainObject', '__isIdentity'] },
  ])('should clear the access restriction of a $typename in the store when a transition resets authorized members', ({ typename, abstractKeys }) => {
    const environment = setupRestrictedEntity(typename);
    expect(readEntity(environment)?.memberIds).toEqual(['admin']);

    commitMutation(environment, {
      mutation: workflowStatusTriggerMutation,
      variables: { entityId: ENTITY_ID, eventName: 'analyze' },
    });
    environment.mock.resolveMostRecentOperation((operation) => {
      const payload = MockPayloadGenerator.generate(operation, { WorkflowInstance: () => ({ id: 'workflow-instance-1' }) });
      // The generator picks the first concrete type (DraftWorkspace) for the abstract `entity`: the backend returns the real entity
      const result = (payload.data as { triggerWorkflowEvent: { entity: Record<string, unknown> } }).triggerWorkflowEvent;
      // Drop the generated abstract-type keys: a stale one would match a fragment branch the real entity does not implement
      const generatedFields = Object.fromEntries(Object.entries(result.entity).filter(([key]) => !key.startsWith('__is')));
      result.entity = {
        ...generatedFields,
        ...Object.fromEntries(abstractKeys.map((key) => [key, typename])),
        __typename: typename,
        id: ENTITY_ID,
        updated_at: '2026-11-27T08:21:40.579Z',
        authorized_members: [],
      };
      return payload;
    });

    const entity = readEntity(environment);
    expect(entity?.updatedAt).toBe('2026-11-27T08:21:40.579Z');
    expect(entity?.memberIds).toEqual([]);
  });
});
