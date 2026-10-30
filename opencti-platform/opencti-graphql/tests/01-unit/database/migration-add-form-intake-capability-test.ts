import { beforeEach, describe, expect, it, vi } from 'vitest';
import { up } from '../../../src/migrations/1793357318727-add-form-intake-capability';
import { createCapabilities, FORM_INTAKE_CAPABILITY } from '../../../src/database/data-initialization';
import { createRelation } from '../../../src/database/middleware';
import { fullEntitiesList } from '../../../src/database/middleware-loader';
import { roleCapabilities } from '../../../src/modules/user/user-domain';
import { RELATION_HAS_CAPABILITY, RELATION_HAS_CAPABILITY_IN_DRAFT } from '../../../src/schema/internalRelationship';

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
vi.mock('../../../src/database/data-initialization', () => ({
  createCapabilities: vi.fn(),
  FORM_INTAKE_CAPABILITY: { name: 'KNFORMINTAKE' },
}));

// capabilities of the roles, by role id then by scope
type Scopes = { main?: string[]; draft?: string[] };
const setRoles = (roles: Record<string, Scopes>) => {
  vi.mocked(fullEntitiesList).mockResolvedValue(Object.keys(roles).map((id) => ({ id })) as any);
  vi.mocked(roleCapabilities).mockImplementation((async (_context: any, _user: any, roleId: string, relationshipType: string) => {
    const names = (relationshipType === RELATION_HAS_CAPABILITY_IN_DRAFT ? roles[roleId].draft : roles[roleId].main) ?? [];
    return names.map((name) => ({ name }));
  }) as any);
};
const runMigration = () => new Promise<void>((resolve, reject) => {
  void up((error) => (error ? reject(error) : resolve()));
});
// [role id, scope] of every relation created, the capability being always the form one
const grants = () => vi.mocked(createRelation).mock.calls.map(([, , input]) => {
  expect(input.toId).toBeDefined();
  return [input.fromId, input.relationship_type];
});

describe('migration add-form-intake-capability', () => {
  beforeEach(() => {
    vi.mocked(createRelation).mockReset();
    vi.mocked(createCapabilities).mockReset();
  });

  it('should create the capability under KNOWLEDGE', async () => {
    setRoles({});
    await runMigration();
    expect(createCapabilities).toHaveBeenCalledWith(expect.anything(), [FORM_INTAKE_CAPABILITY], 'KNOWLEDGE_');
    expect(createRelation).not.toHaveBeenCalled();
  });

  it('should grant the capability in each scope where the role can create / update knowledge', async () => {
    setRoles({
      'main-only': { main: ['KNOWLEDGE_KNUPDATE'] },
      'draft-only': { draft: ['KNOWLEDGE_KNUPDATE'] },
      both: { main: ['KNOWLEDGE_KNUPDATE'], draft: ['KNOWLEDGE_KNUPDATE'] },
    });
    await runMigration();
    expect(grants()).toEqual([
      ['main-only', RELATION_HAS_CAPABILITY],
      ['draft-only', RELATION_HAS_CAPABILITY_IN_DRAFT],
      ['both', RELATION_HAS_CAPABILITY],
      ['both', RELATION_HAS_CAPABILITY_IN_DRAFT],
    ]);
  });

  it('should match the source capability by inclusion, like the runtime does', async () => {
    setRoles({ 'child-only': { main: ['KNOWLEDGE_KNUPDATE_KNDELETE'], draft: ['KNOWLEDGE_KNUPDATE_KNMERGE'] } });
    await runMigration();
    expect(grants()).toEqual([
      ['child-only', RELATION_HAS_CAPABILITY],
      ['child-only', RELATION_HAS_CAPABILITY_IN_DRAFT],
    ]);
  });

  it('should not grant anything to the roles that cannot create / update knowledge', async () => {
    setRoles({
      'import-only': { main: ['KNOWLEDGE_KNASKIMPORT'], draft: ['KNOWLEDGE_KNASKIMPORT'] },
      participate: { main: ['KNOWLEDGE_KNPARTICIPATE', 'KNOWLEDGE_KNUPLOAD'] },
      empty: {},
    });
    await runMigration();
    expect(createRelation).not.toHaveBeenCalled();
  });

  it('should not grant a scope again when the role already has the form capability in it', async () => {
    setRoles({
      done: { main: ['KNOWLEDGE_KNUPDATE', 'KNOWLEDGE_KNFORMINTAKE'], draft: ['KNOWLEDGE_KNUPDATE', 'KNOWLEDGE_KNFORMINTAKE'] },
      partial: { main: ['KNOWLEDGE_KNUPDATE', 'KNOWLEDGE_KNFORMINTAKE'], draft: ['KNOWLEDGE_KNUPDATE'] },
    });
    await runMigration();
    expect(grants()).toEqual([['partial', RELATION_HAS_CAPABILITY_IN_DRAFT]]);
    // the form capability is a sibling of KNUPDATE: holding it alone is not a reason to grant it again
    vi.mocked(createRelation).mockReset();
    setRoles({ 'form-only': { main: ['KNOWLEDGE_KNFORMINTAKE'] } });
    await runMigration();
    expect(createRelation).not.toHaveBeenCalled();
  });
});
