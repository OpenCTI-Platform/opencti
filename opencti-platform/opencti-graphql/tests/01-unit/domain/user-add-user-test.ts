import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../../src/database/middleware', () => ({
  createEntity: vi.fn(),
  createRelation: vi.fn().mockResolvedValue({}),
  deleteElementById: vi.fn(),
  deleteRelationsByFromAndTo: vi.fn(),
  patchAttribute: vi.fn(),
  updateAttribute: vi.fn(),
  updatedInputsToData: vi.fn(),
}));

vi.mock('../../../src/database/middleware-loader', () => ({
  fullEntitiesList: vi.fn(),
  fullEntitiesThoughAggregationConnection: vi.fn(),
  fullEntitiesThroughRelationsToList: vi.fn(),
  fullRelationsList: vi.fn(),
  internalFindByIds: vi.fn(),
  internalLoadById: vi.fn(),
  pageEntitiesConnection: vi.fn(),
  pageRegardingEntitiesConnection: vi.fn(),
  storeLoadById: vi.fn(),
}));

vi.mock('../../../src/database/engine', () => ({
  elLoadBy: vi.fn().mockResolvedValue(null),
  elRawDeleteByQuery: vi.fn(),
}));

vi.mock('../../../src/database/cache', () => ({
  getEntityFromCache: vi.fn().mockResolvedValue({}),
  getEntitiesListFromCache: vi.fn().mockResolvedValue([]),
  getEntitiesMapFromCache: vi.fn().mockResolvedValue(new Map()),
}));

vi.mock('../../../src/database/redis', () => ({
  delEditContext: vi.fn(),
  notify: vi.fn().mockResolvedValue({}),
  setEditContext: vi.fn(),
}));

vi.mock('../../../src/listener/UserActionListener', () => ({
  publishUserAction: vi.fn().mockResolvedValue({}),
}));

vi.mock('../../../src/domain/group', () => ({
  findGroupPaginated: vi.fn().mockResolvedValue({ edges: [] }),
}));

vi.mock('../../../src/utils/access', async () => {
  const actual: any = await vi.importActual('../../../src/utils/access');
  return {
    ...actual,
    isUserHasCapability: vi.fn().mockReturnValue(true),
  };
});

import { addUser } from '../../../src/domain/user';
import { createEntity, createRelation } from '../../../src/database/middleware';
import { elLoadBy } from '../../../src/database/engine';
import { publishUserAction } from '../../../src/listener/UserActionListener';
import { findGroupPaginated } from '../../../src/domain/group';
import { isUserHasCapability } from '../../../src/utils/access';

describe('addUser', () => {
  const context = {} as any;
  const adminUser = { id: 'admin-id', user_email: 'admin@opencti.io' } as any;

  beforeEach(() => {
    vi.clearAllMocks();
    (elLoadBy as any).mockResolvedValue(null);
    (createRelation as any).mockResolvedValue({});
    (publishUserAction as any).mockResolvedValue({});
    (findGroupPaginated as any).mockResolvedValue({ edges: [] });
    (isUserHasCapability as any).mockReturnValue(true);
    (createEntity as any).mockResolvedValue({
      element: { id: 'new-user-id', name: 'John Doe' },
      isCreation: true,
    });
  });

  it('should throw when no email and no service account is provided', async () => {
    const newUser = { name: 'John Doe', objectOrganization: [], groups: [] };
    await expect(addUser(context, adminUser, newUser)).rejects.toThrow('User cannot be created without email');
  });

  it('should throw when the provided email is not valid (blank after normalization)', async () => {
    const newUser = { name: 'John Doe', user_email: '   ', objectOrganization: [], groups: [] };
    await expect(addUser(context, adminUser, newUser)).rejects.toThrow('The email you have provided is not valid');
  });

  it('should throw when a user already exists with the same email', async () => {
    (elLoadBy as any).mockResolvedValue({ internal_id: 'existing-user-id' });
    const newUser = { name: 'John Doe', user_email: 'John.Doe@OpenCTI.io', objectOrganization: [], groups: [] };
    await expect(addUser(context, adminUser, newUser)).rejects.toThrow('User already exists');
  });

  it('should normalize the email (trim + lowercase) before checking existence and creating', async () => {
    const newUser = {
      name: 'John Doe',
      user_email: '  John.Doe@OpenCTI.io  ',
      password: 'Sup3rSecret!Password',
      objectOrganization: [],
      groups: [],
    };
    await addUser(context, adminUser, newUser);
    expect(elLoadBy).toHaveBeenCalledWith(context, expect.anything(), 'user_email', 'john.doe@opencti.io', expect.anything());
    expect(createEntity).toHaveBeenCalledWith(
      context,
      adminUser,
      expect.objectContaining({ user_email: 'john.doe@opencti.io' }),
      expect.anything(),
      expect.anything(),
    );
  });

  it('should auto-generate an email for a service account without email and skip existing-user check', async () => {
    const newUser = { name: 'svc-account', user_service_account: true, objectOrganization: [], groups: [] };
    const result = await addUser(context, adminUser, newUser);
    expect(elLoadBy).not.toHaveBeenCalled();
    expect(createEntity).toHaveBeenCalledWith(
      context,
      adminUser,
      expect.objectContaining({
        user_service_account: true,
        password: undefined,
        user_email: expect.stringMatching(/^automatic\+.+@opencti\.invalid$/),
      }),
      expect.anything(),
      expect.anything(),
    );
    expect(result).toEqual({ id: 'new-user-id', name: 'John Doe' });
  });

  it('should throw ForbiddenAccess when an organization admin creates a user outside their organizations', async () => {
    (isUserHasCapability as any).mockImplementation((_user: any, capability: string) => capability === 'VIRTUAL_ORGANIZATION_ADMIN');
    const orgAdmin = {
      id: 'org-admin-id',
      user_email: 'org-admin@opencti.io',
      administrated_organizations: [{ id: 'org-1', grantable_groups: [] }],
    } as any;
    const newUser = { name: 'John Doe', user_email: 'john.doe@opencti.io', objectOrganization: ['org-2'], groups: [] };
    await expect(addUser(context, orgAdmin, newUser)).rejects.toThrow();
    expect(createEntity).not.toHaveBeenCalled();
  });

  it('should allow an organization admin to create a user within their administrated organizations and groups', async () => {
    (isUserHasCapability as any).mockImplementation((_user: any, capability: string) => capability === 'VIRTUAL_ORGANIZATION_ADMIN');
    const orgAdmin = {
      id: 'org-admin-id',
      user_email: 'org-admin@opencti.io',
      administrated_organizations: [{ id: 'org-1', grantable_groups: ['group-1'] }],
    } as any;
    const newUser = {
      name: 'John Doe',
      user_email: 'john.doe@opencti.io',
      password: 'Sup3rSecret!Password',
      objectOrganization: ['org-1'],
      groups: ['group-1'],
    };
    const result = await addUser(context, orgAdmin, newUser);
    expect(result).toBeDefined();
    expect(createEntity).toHaveBeenCalled();
  });

  it('should create relations for organizations and provided groups, and publish a create action', async () => {
    const newUser = {
      name: 'John Doe',
      user_email: 'john.doe@opencti.io',
      password: 'Sup3rSecret!Password',
      objectOrganization: ['org-1', 'org-2'],
      groups: ['group-1'],
      prevent_default_groups: true,
    };
    await addUser(context, adminUser, newUser);
    expect(createRelation).toHaveBeenCalledWith(context, adminUser, expect.objectContaining({ toId: 'org-1' }));
    expect(createRelation).toHaveBeenCalledWith(context, adminUser, expect.objectContaining({ toId: 'org-2' }));
    expect(createRelation).toHaveBeenCalledWith(context, adminUser, expect.objectContaining({ toId: 'group-1' }));
    expect(publishUserAction).toHaveBeenCalledWith(expect.objectContaining({
      event_type: 'mutation',
      event_scope: 'create',
    }));
  });

  it('should also assign default groups when prevent_default_groups is not true', async () => {
    (findGroupPaginated as any).mockResolvedValue({
      edges: [{ node: { internal_id: 'default-group-1' } }, { node: { internal_id: 'group-1' } }],
    });
    const newUser = {
      name: 'John Doe',
      user_email: 'john.doe@opencti.io',
      password: 'Sup3rSecret!Password',
      objectOrganization: [],
      groups: ['group-1'],
    };
    await addUser(context, adminUser, newUser);
    // default-group-1 is not already in newUser.groups so it should be linked
    expect(createRelation).toHaveBeenCalledWith(context, adminUser, expect.objectContaining({ toId: 'default-group-1' }));
    // group-1 is already provided explicitly, should only be linked once (from the explicit groups list)
    const groupOneCalls = (createRelation as any).mock.calls.filter(([, , relation]: any[]) => relation.toId === 'group-1');
    expect(groupOneCalls.length).toBe(1);
  });

  it('should assign a random password for external users without a provided password', async () => {
    const newUser = {
      name: 'John Doe',
      user_email: 'external@opencti.io',
      external: true,
      objectOrganization: [],
      groups: [],
    };
    await addUser(context, adminUser, newUser);
    expect(createEntity).toHaveBeenCalledWith(
      context,
      adminUser,
      expect.objectContaining({ password: expect.any(String) }),
      expect.anything(),
      expect.anything(),
    );
  });
});
