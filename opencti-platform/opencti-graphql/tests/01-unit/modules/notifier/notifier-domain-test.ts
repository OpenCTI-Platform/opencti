import { describe, it, expect, vi, beforeEach } from 'vitest';
import * as middleware from '../../../../src/database/middleware';
import * as redis from '../../../../src/database/redis';
import * as userActionListener from '../../../../src/listener/UserActionListener';
import type { AuthContext, AuthUser } from '../../../../src/types/user';
import type { EditInput } from '../../../../src/generated/graphql';
import { notifierEdit } from '../../../../src/modules/notifier/notifier-domain';
import { NOTIFIER_CONNECTOR_WEBHOOK } from '../../../../src/modules/notifier/notifier-statics';

const mockContext = { id: 'context' } as unknown as AuthContext;
const mockUser = { id: 'user-1' } as unknown as AuthUser;
const notifierId = 'notifier-123';

const validConfiguration = JSON.stringify({
  url: 'https://example.com/webhook',
  verb: 'POST',
  template: '{}',
});

const baseInput: EditInput[] = [
  { key: 'name', value: ['My Notifier'] },
  { key: 'description', value: ['A description'] },
  { key: 'notifier_connector_id', value: [NOTIFIER_CONNECTOR_WEBHOOK] },
  { key: 'notifier_configuration', value: [validConfiguration] },
  { key: 'restricted_members', value: [] },
];

describe('notifierEdit', () => {
  beforeEach(() => {
    vi.clearAllMocks();

    vi.spyOn(middleware, 'updateAttribute').mockResolvedValue({
      element: { id: notifierId, name: 'My Notifier' },
      event: undefined,
    } as any);

    vi.spyOn(redis, 'notify').mockResolvedValue(undefined as any);
    vi.spyOn(userActionListener, 'publishUserAction').mockResolvedValue([] as any);
  });

  it('should call updateAttribute with the correct input for a valid notifier', async () => {
    await notifierEdit(mockContext, mockUser, notifierId, baseInput);

    expect(middleware.updateAttribute).toHaveBeenCalledOnce();
  });

  it('should NOT crash when notifier_configuration key is missing from input (find vs filter bug)', async () => {
    const inputWithoutConfig: EditInput[] = baseInput.filter((i) => i.key !== 'notifier_configuration');

    await expect(notifierEdit(mockContext, mockUser, notifierId, inputWithoutConfig))
      .rejects.toThrow('This configuration is invalid');
  });

  it('should NOT crash when notifier_connector_id key is missing from input (find vs filter bug)', async () => {
    const inputWithoutConnectorId: EditInput[] = baseInput.filter((i) => i.key !== 'notifier_connector_id');

    await expect(notifierEdit(mockContext, mockUser, notifierId, inputWithoutConnectorId))
      .rejects.toThrow('Invalid notifier connector');
  });

  it('should NOT crash when restricted_members value is null (value.map bug)', async () => {
    const inputWithNullMembers: EditInput[] = [
      ...baseInput.filter((i) => i.key !== 'restricted_members'),
      { key: 'restricted_members', value: null as any },
    ];

    await expect(notifierEdit(mockContext, mockUser, notifierId, inputWithNullMembers))
      .resolves.not.toThrow();
  });

  it('should correctly map restricted_members to authorized member objects', async () => {
    const inputWithMembers: EditInput[] = [
      ...baseInput.filter((i) => i.key !== 'restricted_members'),
      { key: 'restricted_members', value: ['user-a', 'user-b'] },
    ];

    await notifierEdit(mockContext, mockUser, notifierId, inputWithMembers);

    const callArgs = (middleware.updateAttribute as any).mock.calls[0];
    const finalInput: EditInput[] = callArgs[4];
    const membersField = finalInput.find((i) => i.key === 'restricted_members');

    expect(membersField?.value).toEqual([
      { id: 'user-a', access_right: 'view' },
      { id: 'user-b', access_right: 'view' },
    ]);
  });
});
