import { describe, expect, it, vi } from 'vitest';
import { getAuthorizedMembers } from '../../../src/utils/authorizedMembers';
import { findAllMembers } from '../../../src/modules/user/user-domain';
import type { BasicStoreEntity } from '../../../src/types/store';

vi.mock('../../../src/modules/user/user-domain', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../src/modules/user/user-domain')>()),
  findAllMembers: vi.fn(),
}));
vi.mock('../../../src/utils/draftContext', () => ({ getDraftContext: () => undefined }));
vi.mock('../../../src/utils/access', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../src/utils/access')>()),
  validateUserAccessOperation: () => true,
}));

const ORGANIZATION = { id: 'organization-x', name: 'Org X', entity_type: 'Organization' };
const GROUP_G = { id: 'group-g', name: 'Group G', entity_type: 'Group' };
const GROUP_H = { id: 'group-h', name: 'Group H', entity_type: 'Group' };

const savedFilter = (internalId: string, groupId: string) => ({
  internal_id: internalId,
  id: internalId,
  restricted_members: [{ id: ORGANIZATION.id, access_right: 'view', groups_restriction_ids: [groupId] }],
} as unknown as BasicStoreEntity);

describe('getAuthorizedMembers', () => {
  // Relay normalizes the access rules by id: two entities sharing one would display and submit each other's rules
  it('should give a different id to the same member at the same index of two entities', async () => {
    vi.mocked(findAllMembers).mockResolvedValue([ORGANIZATION, GROUP_G, GROUP_H] as any);

    const [firstRule] = await getAuthorizedMembers({} as any, {} as any, savedFilter('saved-filter-1', GROUP_G.id));
    const [secondRule] = await getAuthorizedMembers({} as any, {} as any, savedFilter('saved-filter-2', GROUP_H.id));

    expect(firstRule.id).not.toEqual(secondRule.id);
    // The member id stays the member itself, for the conversion back to an input
    expect(firstRule).toMatchObject({ member_id: ORGANIZATION.id, groups_restriction: [{ id: GROUP_G.id, name: GROUP_G.name }] });
    expect(secondRule).toMatchObject({ member_id: ORGANIZATION.id, groups_restriction: [{ id: GROUP_H.id, name: GROUP_H.name }] });
  });
});
