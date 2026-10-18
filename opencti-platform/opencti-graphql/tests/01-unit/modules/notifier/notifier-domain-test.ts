import { describe, it, expect, vi, beforeEach } from 'vitest';
import * as middleware from '../../../../src/database/middleware';
import * as middlewareLoader from '../../../../src/database/middleware-loader';
import * as redis from '../../../../src/database/redis';
import * as userActionListener from '../../../../src/listener/UserActionListener';
import * as uriDenyListConfig from '../../../../src/config/uriDenyList';
import type { AuthContext, AuthUser } from '../../../../src/types/user';
import type { EditInput } from '../../../../src/generated/graphql';
import { notifierEdit } from '../../../../src/modules/notifier/notifier-domain';
import { NOTIFIER_CONNECTOR_EMAIL, NOTIFIER_CONNECTOR_WEBHOOK } from '../../../../src/modules/notifier/notifier-statics';

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

    vi.spyOn(middlewareLoader, 'storeLoadById').mockResolvedValue({
      id: notifierId,
      notifier_connector_id: NOTIFIER_CONNECTOR_WEBHOOK,
      notifier_configuration: validConfiguration,
    } as any);

    vi.spyOn(redis, 'notify').mockResolvedValue(undefined as any);
    vi.spyOn(userActionListener, 'publishUserAction').mockResolvedValue([] as any);
  });

  it('should call updateAttribute with the correct input for a valid notifier', async () => {
    await notifierEdit(mockContext, mockUser, notifierId, baseInput);

    expect(middleware.updateAttribute).toHaveBeenCalledOnce();
  });

  it('should not validate an edit without connector nor configuration', async () => {
    await notifierEdit(mockContext, mockUser, notifierId, [{ key: 'name', value: ['New name'] }]);

    expect(middlewareLoader.storeLoadById).not.toHaveBeenCalled();
    expect(middleware.updateAttribute).toHaveBeenCalledOnce();
  });

  it('should validate an edited configuration with the stored connector', async () => {
    const inputWithoutConnectorId: EditInput[] = baseInput.filter((i) => i.key !== 'notifier_connector_id');
    await notifierEdit(mockContext, mockUser, notifierId, inputWithoutConnectorId);
    expect(middleware.updateAttribute).toHaveBeenCalledOnce();

    vi.spyOn(middlewareLoader, 'storeLoadById').mockResolvedValue({ id: notifierId, notifier_connector_id: NOTIFIER_CONNECTOR_EMAIL } as any);
    await expect(notifierEdit(mockContext, mockUser, notifierId, inputWithoutConnectorId))
      .rejects.toThrow('This configuration is invalid');
  });

  it('should validate an edited connector with the stored configuration', async () => {
    const inputWithoutConfig: EditInput[] = baseInput.filter((i) => i.key !== 'notifier_configuration');
    await notifierEdit(mockContext, mockUser, notifierId, inputWithoutConfig);
    expect(middleware.updateAttribute).toHaveBeenCalledOnce();

    const inputWithEmailConnector: EditInput[] = [
      ...inputWithoutConfig.filter((i) => i.key !== 'notifier_connector_id'),
      { key: 'notifier_connector_id', value: [NOTIFIER_CONNECTOR_EMAIL] },
    ];
    await expect(notifierEdit(mockContext, mockUser, notifierId, inputWithEmailConnector))
      .rejects.toThrow('This configuration is invalid');
  });

  it('should reject the edit of a notifier that cannot be found', async () => {
    vi.spyOn(middlewareLoader, 'storeLoadById').mockResolvedValue(undefined as any);

    await expect(notifierEdit(mockContext, mockUser, notifierId, baseInput))
      .rejects.toThrow('Cant find element to update');
    expect(middleware.updateAttribute).not.toHaveBeenCalled();
  });

  it('should reject a configuration that is not valid JSON', async () => {
    const inputWithMalformedConfig: EditInput[] = [
      ...baseInput.filter((i) => i.key !== 'notifier_configuration'),
      { key: 'notifier_configuration', value: ['{not json'] },
    ];

    await expect(notifierEdit(mockContext, mockUser, notifierId, inputWithMalformedConfig))
      .rejects.toThrow('This configuration is invalid');
  });

  it.each(['not a url', 'example.com/webhook', 'ftp://example.com/webhook'])('should reject the webhook url %s', async (url) => {
    const inputWithInvalidUrl: EditInput[] = [
      ...baseInput.filter((i) => i.key !== 'notifier_configuration'),
      { key: 'notifier_configuration', value: [JSON.stringify({ url, verb: 'POST', template: '{}' })] },
    ];

    await expect(notifierEdit(mockContext, mockUser, notifierId, inputWithInvalidUrl))
      .rejects.toThrow('The webhook URL must be an http or https URL');
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

  it('should throw when webhook url is in the deny list', async () => {
    vi.spyOn(uriDenyListConfig, 'uriDenyList').mockReturnValue(['blocked.com']);
    const inputWithBlockedUrl: EditInput[] = [
      ...baseInput.filter((i) => i.key !== 'notifier_configuration'),
      { key: 'notifier_configuration', value: [JSON.stringify({ url: 'https://blocked.com/hook', verb: 'POST', template: '{}' })] },
    ];

    await expect(notifierEdit(mockContext, mockUser, notifierId, inputWithBlockedUrl))
      .rejects.toThrow('This URI is not allowed.');
  });

  it('should not throw when webhook url is not in the deny list', async () => {
    vi.spyOn(uriDenyListConfig, 'uriDenyList').mockReturnValue(['blocked.com']);

    await expect(notifierEdit(mockContext, mockUser, notifierId, baseInput))
      .resolves.not.toThrow();
  });
});
