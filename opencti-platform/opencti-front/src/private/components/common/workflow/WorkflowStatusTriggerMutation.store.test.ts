import { describe, expect, it } from 'vitest';
import { commitLocalUpdate, commitMutation } from 'relay-runtime';
import { createMockEnvironment, MockPayloadGenerator } from 'relay-test-utils';
import { workflowStatusTriggerMutation } from './WorkflowStatus.graphql';

const ENTITY_ID = 'entity-1';

const setupRestrictedEntity = (typename: string, membersField: string) => {
  const environment = createMockEnvironment();
  commitLocalUpdate(environment, (store) => {
    const entity = store.create(ENTITY_ID, typename);
    entity.setValue(ENTITY_ID, 'id');
    const member = store.create(`${ENTITY_ID}_admin_0`, 'MemberAccess');
    member.setValue(`${ENTITY_ID}_admin_0`, 'id');
    member.setValue('admin', 'member_id');
    member.setValue('admin', 'access_right');
    entity.setLinkedRecords([member], membersField);
  });
  return environment;
};

const readMemberIds = (environment: ReturnType<typeof createMockEnvironment>, membersField: string) => {
  let memberIds: unknown[] | undefined;
  commitLocalUpdate(environment, (store) => {
    memberIds = (store.get(ENTITY_ID)?.getLinkedRecords(membersField) ?? []).map((member) => member?.getValue('member_id'));
  });
  return memberIds;
};

describe('WorkflowStatusTriggerMutation', () => {
  it.each([
    { typename: 'Report', membersField: 'authorized_members', abstractKeys: ['__isStixDomainObject', '__isContainer'] },
    { typename: 'Organization', membersField: 'authorized_members', abstractKeys: ['__isStixDomainObject', '__isIdentity'] },
    { typename: 'DraftWorkspace', membersField: 'authorizedMembers', abstractKeys: [] },
  ])('should clear the access restriction of a $typename in the store when a transition resets authorized members', ({ typename, membersField, abstractKeys }) => {
    const environment = setupRestrictedEntity(typename, membersField);
    expect(readMemberIds(environment, membersField)).toEqual(['admin']);

    commitMutation(environment, {
      mutation: workflowStatusTriggerMutation,
      variables: { entityId: ENTITY_ID, eventName: 'analyze' },
    });
    environment.mock.resolveMostRecentOperation((operation) => {
      const payload = MockPayloadGenerator.generate(operation, { WorkflowInstance: () => ({ id: 'workflow-instance-1' }) });
      // The generator picks the first concrete type (DraftWorkspace) for the abstract `entity`: the backend returns the real entity,
      // reloaded after the sync actions ran
      const result = (payload.data as { triggerWorkflowEvent: { entity: Record<string, unknown> } }).triggerWorkflowEvent;
      // Drop the generated abstract-type keys: a stale one would match a fragment branch the real entity does not implement
      const generatedFields = Object.fromEntries(Object.entries(result.entity).filter(([key]) => !key.startsWith('__is')));
      result.entity = {
        ...generatedFields,
        ...Object.fromEntries(abstractKeys.map((key) => [key, typename])),
        __typename: typename,
        id: ENTITY_ID,
        [membersField]: [],
      };
      return payload;
    });

    expect(readMemberIds(environment, membersField)).toEqual([]);
  });
});
