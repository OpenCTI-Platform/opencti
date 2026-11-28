import { describe, it, expect, vi, beforeEach } from 'vitest';
import * as middleware from '../../../../src/database/middleware';
import * as redis from '../../../../src/database/redis';
import * as userActionListener from '../../../../src/listener/UserActionListener';
import * as uriDenyListConfig from '../../../../src/config/uriDenyList';
import type { AuthContext, AuthUser } from '../../../../src/types/user';
import type { EditInput, NotifierAddInput } from '../../../../src/generated/graphql';
import { addNotifier, notifierEdit } from '../../../../src/modules/notifier/notifier-domain';
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

  it('should store webhook headers normalized', async () => {
    const configuration = {
      url: 'https://example.com/webhook',
      verb: 'DELETE',
      template: '{}',
      headers: [
        { attribute: 'Authorization : ', value: 'Bearer token\n' },
        { attribute: ' X-API-Key', value: ' key ' },
      ],
    };
    const inputWithHeaders: EditInput[] = [
      ...baseInput.filter((i) => i.key !== 'notifier_configuration'),
      { key: 'notifier_configuration', value: [JSON.stringify(configuration)] },
    ];

    await notifierEdit(mockContext, mockUser, notifierId, inputWithHeaders);

    const finalInput: EditInput[] = (middleware.updateAttribute as any).mock.calls[0][4];
    const storedConfiguration = finalInput.find((i) => i.key === 'notifier_configuration')?.value[0];
    expect(JSON.parse(storedConfiguration)).toEqual({
      ...configuration,
      headers: [
        { attribute: 'Authorization', value: 'Bearer token' },
        { attribute: 'X-API-Key', value: 'key' },
      ],
    });
  });

  it.each([
    ['a name with a space', { attribute: 'X API Key', value: 'key' }],
    ['a name without any character', { attribute: ' : ', value: 'key' }],
    ['a value with a new line', { attribute: 'X-API-Key', value: 'first\nsecond' }],
    ['a value with a character out of latin-1', { attribute: 'X-API-Key', value: 'k€y' }],
  ])('should reject a webhook header with %s', async (_, header) => {
    const inputWithInvalidHeader: EditInput[] = [
      ...baseInput.filter((i) => i.key !== 'notifier_configuration'),
      { key: 'notifier_configuration', value: [JSON.stringify({ url: 'https://example.com/webhook', verb: 'POST', template: '{}', headers: [header] })] },
    ];

    await expect(notifierEdit(mockContext, mockUser, notifierId, inputWithInvalidHeader))
      .rejects.toThrow('This configuration is invalid');
    expect(middleware.updateAttribute).not.toHaveBeenCalled();
  });
});

describe('addNotifier', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.spyOn(middleware, 'createEntity').mockImplementation(async (_context, _user, input) => ({ id: notifierId, ...input }) as any);
    vi.spyOn(redis, 'notify').mockImplementation(async (_topic, instance) => instance as any);
    vi.spyOn(userActionListener, 'publishUserAction').mockResolvedValue([] as any);
  });

  it('should store webhook headers normalized', async () => {
    const notifier: NotifierAddInput = {
      name: 'My Notifier',
      notifier_connector_id: NOTIFIER_CONNECTOR_WEBHOOK,
      notifier_configuration: JSON.stringify({
        url: 'https://example.com/webhook',
        verb: 'POST',
        template: '{}',
        headers: [{ attribute: 'Authorization:', value: 'Bearer token' }],
      }),
    };

    const created = await addNotifier(mockContext, mockUser, notifier);

    expect(JSON.parse(created.notifier_configuration).headers).toEqual([{ attribute: 'Authorization', value: 'Bearer token' }]);
  });

  it('should keep a configuration without headers untouched', async () => {
    const notifier: NotifierAddInput = {
      name: 'My Notifier',
      notifier_connector_id: NOTIFIER_CONNECTOR_WEBHOOK,
      notifier_configuration: validConfiguration,
    };

    const created = await addNotifier(mockContext, mockUser, notifier);

    expect(created.notifier_configuration).toBe(validConfiguration);
  });
});
