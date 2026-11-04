import { beforeEach, describe, expect, it, vi } from 'vitest';
import { up } from '../../../src/migrations/1793786440000-add-custom-fields-capability';
import { createCapabilities } from '../../../src/database/data-initialization';
import { CUSTOM_FIELDS_CAPABILITY } from '../../../src/schema/capabilities';
import { createRelation } from '../../../src/database/middleware';
import { fullEntitiesList } from '../../../src/database/middleware-loader';
import { roleCapabilities } from '../../../src/modules/user/user-domain';
import { RELATION_HAS_CAPABILITY } from '../../../src/schema/internalRelationship';

vi.mock('../../../src/config/conf', async (importOriginal) => {
  const actual = await importOriginal<any>();
  return { ...actual, logMigration: { info: vi.fn(), error: vi.fn(), warn: vi.fn(), debug: vi.fn() } };
});
vi.mock('../../../src/utils/access', async (importOriginal) => {
  const actual = await importOriginal<any>();
  return { ...actual, executionContext: vi.fn(() => ({ source: 'migration' })) };
});
vi.mock('../../../src/database/middleware-loader', () => ({ fullEntitiesList: vi.fn() }));
vi.mock('../../../src/database/middleware', () => ({ createRelation: vi.fn() }));
vi.mock('../../../src/modules/user/user-domain', () => ({ roleCapabilities: vi.fn() }));
vi.mock('../../../src/database/data-initialization', () => ({ createCapabilities: vi.fn() }));

// capabilities of the roles, by role id
const setRoles = (roles: Record<string, string[]>) => {
  vi.mocked(fullEntitiesList).mockResolvedValue(Object.keys(roles).map((id) => ({ id })) as any);
  vi.mocked(roleCapabilities).mockImplementation((async (_context: any, _user: any, roleId: string) => {
    return roles[roleId].map((name) => ({ name }));
  }) as any);
};
const runMigration = () => new Promise<void>((resolve, reject) => {
  void up((error) => (error ? reject(error) : resolve()));
});
// [role id, scope] of every relation created, the capability being always the custom fields one
const grants = () => vi.mocked(createRelation).mock.calls.map(([, , input]) => {
  expect(input.toId).toBeDefined();
  return [input.fromId, input.relationship_type];
});

describe('migration add-custom-fields-capability', () => {
  beforeEach(() => {
    vi.mocked(createRelation).mockReset();
    vi.mocked(createCapabilities).mockReset();
  });

  it('should create the capability under SETTINGS', async () => {
    setRoles({});
    await runMigration();
    expect(createCapabilities).toHaveBeenCalledWith(expect.anything(), [CUSTOM_FIELDS_CAPABILITY], 'SETTINGS_');
    expect(createRelation).not.toHaveBeenCalled();
  });

  it('should grant the capability to the roles that can manage the customization', async () => {
    setRoles({
      customization: ['SETTINGS', 'SETTINGS_SETCUSTOMIZATION'],
      labels: ['SETTINGS', 'SETTINGS_SETLABELS'],
      knowledge: ['KNOWLEDGE', 'KNOWLEDGE_KNUPDATE'],
      empty: [],
    });
    await runMigration();
    expect(grants()).toEqual([['customization', RELATION_HAS_CAPABILITY]]);
  });

  it('should not grant the capability again when the role already has it', async () => {
    setRoles({ done: ['SETTINGS_SETCUSTOMIZATION', 'SETTINGS_SETCUSTOMFIELDS'] });
    await runMigration();
    expect(createRelation).not.toHaveBeenCalled();
  });
});
