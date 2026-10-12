import { readFileSync } from 'node:fs';
import path from 'node:path';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { Kind, parse, type ObjectTypeDefinitionNode, type StringValueNode } from 'graphql';
import { isFeatureEnabled } from '../../../src/config/conf';
import { patchAttribute } from '../../../src/database/middleware';
import { getEntityFromCache } from '../../../src/database/cache';
import { LOCAL_AUTH_LOCKOUT_DEFAULTS, updateLocalAuth } from '../../../src/domain/setting-auth';
import type { AuthContext, AuthUser } from '../../../src/types/user';
import type { BasicStoreSettings } from '../../../src/types/settings';

vi.mock('../../../src/config/conf', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../../src/config/conf')>();
  return {
    ...actual,
    isFeatureEnabled: vi.fn(() => true),
  };
});

vi.mock('../../../src/database/middleware', () => ({
  patchAttribute: vi.fn(async () => ({ element: { id: 'settings-id' } })),
}));

vi.mock('../../../src/database/cache', () => ({
  getEntityFromCache: vi.fn(async () => ({})),
}));

vi.mock('../../../src/database/redis', () => ({
  notify: vi.fn(async (_topic: string, element: unknown) => element),
}));

vi.mock('../../../src/listener/UserActionListener', () => ({
  publishUserAction: vi.fn(),
}));

vi.mock('../../../src/modules/user/user-domain', () => ({
  adjustAllUsersPasswordValidUntil: vi.fn(),
  clearAllUsersPasswordValidUntil: vi.fn(),
}));

const context = {} as AuthContext;
const user = { id: 'admin' } as AuthUser;
const LOCKOUT_INPUT = {
  local_auth_lockout_enabled: true,
  local_auth_lockout_max_attempts: 3,
  local_auth_lockout_window: 60,
  local_auth_lockout_duration: 10,
  local_auth_lockout_max_duration: 120,
};

const mockStoredSettings = (settings: Partial<BasicStoreSettings>) => vi.mocked(getEntityFromCache).mockResolvedValue(settings as BasicStoreSettings);
const patchSentToDatabase = () => vi.mocked(patchAttribute).mock.calls[0][4];

describe('updateLocalAuth - lockout policy', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    mockStoredSettings({});
  });

  it('should patch the lockout policy when the feature flag is enabled', async () => {
    vi.mocked(isFeatureEnabled).mockReturnValue(true);
    await updateLocalAuth(context, user, 'settings-id', { enabled: true, ...LOCKOUT_INPUT });
    expect(patchSentToDatabase()).toEqual({ local_auth: { enabled: true }, ...LOCKOUT_INPUT });
  });

  it('should ignore the lockout policy when the feature flag is disabled', async () => {
    vi.mocked(isFeatureEnabled).mockReturnValue(false);
    await updateLocalAuth(context, user, 'settings-id', { enabled: true, ...LOCKOUT_INPUT, local_auth_lockout_duration: 500 });
    expect(patchSentToDatabase()).toEqual({ local_auth: { enabled: true } });
  });

  it('should validate the input against the stored policy', async () => {
    vi.mocked(isFeatureEnabled).mockReturnValue(true);
    mockStoredSettings({ local_auth_lockout_max_duration: 30 });
    await expect(updateLocalAuth(context, user, 'settings-id', { enabled: true, local_auth_lockout_duration: 31 }))
      .rejects.toThrowError('Lockout duration must be lower or equal to lockout max duration');
    expect(patchAttribute).not.toHaveBeenCalled();
  });

  it('should validate a null input against the default policy', async () => {
    vi.mocked(isFeatureEnabled).mockReturnValue(true);
    mockStoredSettings({ local_auth_lockout_max_duration: 30 });
    await updateLocalAuth(context, user, 'settings-id', { enabled: true, local_auth_lockout_duration: 20, local_auth_lockout_max_duration: null });
    expect(patchSentToDatabase()).toEqual({ local_auth: { enabled: true }, local_auth_lockout_duration: 20, local_auth_lockout_max_duration: null });
  });
});

describe('Settings schema - lockout policy', () => {
  it('should soft fail with the domain defaults when the feature flag is disabled', () => {
    const schemaPath = path.join(__dirname, '../../../config/schema/opencti.graphql');
    const document = parse(readFileSync(schemaPath, 'utf8'));
    const settingsType = document.definitions.find(
      (definition): definition is ObjectTypeDefinitionNode => definition.kind === Kind.OBJECT_TYPE_DEFINITION && definition.name.value === 'Settings',
    );
    Object.entries(LOCAL_AUTH_LOCKOUT_DEFAULTS).forEach(([fieldName, defaultValue]) => {
      const field = settingsType?.fields?.find((f) => f.name.value === fieldName);
      const ffDirective = field?.directives?.find((directive) => directive.name.value === 'ff');
      const argument = (name: string) => ffDirective?.arguments?.find((arg) => arg.name.value === name)?.value;
      expect(argument('softFail')).toMatchObject({ kind: Kind.BOOLEAN, value: true });
      expect(JSON.parse((argument('defaultValue') as StringValueNode).value)).toEqual(defaultValue);
    });
  });
});
