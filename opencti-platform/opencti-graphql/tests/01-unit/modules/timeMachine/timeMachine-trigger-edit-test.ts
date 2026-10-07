import { afterEach, describe, expect, it, vi } from 'vitest';
import '../../../../src/modules/index';
import type { AuthContext } from '../../../../src/types/user';

// The trigger store is canned: the validation and normalization of a change digest edit are under test.
const triggerGetMock = vi.fn();
const triggerEditMock = vi.fn();
vi.mock('../../../../src/modules/notification/notification-domain', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/modules/notification/notification-domain')>()),
  triggerGet: (...args: unknown[]) => triggerGetMock(...args),
  triggerEdit: (...args: unknown[]) => triggerEditMock(...args),
}));

import { triggerKnowledgeEdit } from '../../../../src/modules/timeMachine/timeMachine-triggers';
import { EditOperation } from '../../../../src/generated/graphql';
import { SYSTEM_USER } from '../../../../src/utils/access';

const context = {} as AuthContext;
const intrusionSetFilters = JSON.stringify({ mode: 'and', filters: [{ key: ['entity_type'], values: ['Intrusion-Set'], operator: 'eq', mode: 'or' }], filterGroups: [] });
const changeDigest = {
  id: 'trigger-1',
  trigger_type: 'change_digest',
  notifiers: ['notifier-email'],
  filters: intrusionSetFilters,
  scope_entity_types: ['Intrusion-Set'],
};

describe('Edit of a change digest', () => {
  afterEach(() => {
    vi.clearAllMocks();
  });

  it('should refuse an edit that leaves a change digest without notifier', async () => {
    triggerGetMock.mockResolvedValue(changeDigest);
    await expect(triggerKnowledgeEdit(context, SYSTEM_USER, 'trigger-1', [{ key: 'notifiers', value: [] }]))
      .rejects.toThrow('A change digest needs at least one notifier');
    await expect(triggerKnowledgeEdit(context, SYSTEM_USER, 'trigger-1', [{ key: 'notifiers', value: ['notifier-email'], operation: EditOperation.Remove }]))
      .rejects.toThrow('A change digest needs at least one notifier');
    expect(triggerEditMock).not.toHaveBeenCalled();
  });

  it('should refuse a recipient change, the recipient being authorized and stored at creation', async () => {
    triggerGetMock.mockResolvedValue(changeDigest);
    await expect(triggerKnowledgeEdit(context, SYSTEM_USER, 'trigger-1', [{ key: 'recipients', value: ['user-2'] }]))
      .rejects.toThrow('The recipient of a change digest is set at its creation');
    await expect(triggerKnowledgeEdit(context, SYSTEM_USER, 'trigger-1', [{ key: 'restricted_members', value: [{ id: 'user-2', access_right: 'admin' }] }]))
      .rejects.toThrow('The recipient of a change digest is set at its creation');
    expect(triggerEditMock).not.toHaveBeenCalled();
  });

  it('should accept a notifier change that keeps one notifier', async () => {
    triggerGetMock.mockResolvedValue(changeDigest);
    const input = [{ key: 'notifiers', value: ['notifier-webhook'], operation: EditOperation.Add }];
    await triggerKnowledgeEdit(context, SYSTEM_USER, 'trigger-1', input);
    expect(triggerEditMock).toHaveBeenCalledWith(context, SYSTEM_USER, 'trigger-1', input);
  });

  it('should refuse a malformed scope and store a valid one with its entity types', async () => {
    triggerGetMock.mockResolvedValue(changeDigest);
    await expect(triggerKnowledgeEdit(context, SYSTEM_USER, 'trigger-1', [{ key: 'scope_entity_types', value: ['Not-An-Entity-Type'] }]))
      .rejects.toThrow();
    await expect(triggerKnowledgeEdit(context, SYSTEM_USER, 'trigger-1', [{ key: 'filters', value: ['{not json'] }]))
      .rejects.toThrow();
    expect(triggerEditMock).not.toHaveBeenCalled();
    await triggerKnowledgeEdit(context, SYSTEM_USER, 'trigger-1', [{ key: 'name', value: ['Weekly'] }, { key: 'scope_entity_types', value: ['Malware'] }]);
    const [, , , storedInput] = triggerEditMock.mock.calls[0];
    expect(storedInput).toEqual([
      { key: 'name', value: ['Weekly'] },
      { key: 'filters', value: [intrusionSetFilters] },
      { key: 'scope_entity_types', value: ['Malware'] },
    ]);
  });

  it('should leave the edits of the other triggers to the generic trigger edit', async () => {
    triggerGetMock.mockResolvedValue({ id: 'trigger-2', trigger_type: 'digest', notifiers: ['notifier-email'] });
    const input = [{ key: 'notifiers', value: [] }];
    await triggerKnowledgeEdit(context, SYSTEM_USER, 'trigger-2', input);
    expect(triggerEditMock).toHaveBeenCalledWith(context, SYSTEM_USER, 'trigger-2', input);
  });
});
