import { beforeEach, describe, expect, it, vi } from 'vitest';
import * as access from '../../../../src/utils/access';
import * as loader from '../../../../src/database/middleware-loader';
import {
  canEditRequirement,
  canManageRequirement,
  IR_ACCESS_EDIT,
  IR_ACCESS_MANAGE,
  IR_ACCESS_READ,
  loadRequirementWithAccess,
} from '../../../../src/modules/intelligenceRequirement/intelligenceRequirement-access';
import type { AuthContext, AuthUser } from '../../../../src/types/user';
import type { BasicStoreEntityIntelligenceRequirement } from '../../../../src/modules/intelligenceRequirement/intelligenceRequirement-types';

const user = { id: 'restricted-user' } as AuthUser;
const context = {} as AuthContext;
const ir = { id: 'ir-1', internal_id: 'ir-1', restricted_members: [{ id: 'someone', access_right: 'admin' }] } as unknown as BasicStoreEntityIntelligenceRequirement;

const withRight = (right: string | null) => vi.spyOn(access, 'getUserAccessRight').mockReturnValue(right as never);

describe('Intelligence requirement authorized members: view, edit, manage', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it('a "Can view" member reads but neither triages nor manages', async () => {
    withRight(access.MEMBER_ACCESS_RIGHT_VIEW);
    vi.spyOn(loader, 'storeLoadById').mockResolvedValue(ir as never);
    expect(canEditRequirement(user, ir)).toBe(false);
    expect(canManageRequirement(user, ir)).toBe(false);
    await expect(loadRequirementWithAccess(context, user, 'ir-1', IR_ACCESS_READ)).resolves.toBe(ir);
    await expect(loadRequirementWithAccess(context, user, 'ir-1', IR_ACCESS_EDIT)).rejects.toThrow();
    await expect(loadRequirementWithAccess(context, user, 'ir-1', IR_ACCESS_MANAGE)).rejects.toThrow();
  });

  it('a "Can edit" member triages but does not manage (configuration, status, members, deletion)', async () => {
    withRight(access.MEMBER_ACCESS_RIGHT_EDIT);
    vi.spyOn(loader, 'storeLoadById').mockResolvedValue(ir as never);
    expect(canEditRequirement(user, ir)).toBe(true);
    expect(canManageRequirement(user, ir)).toBe(false);
    await expect(loadRequirementWithAccess(context, user, 'ir-1', IR_ACCESS_EDIT)).resolves.toBe(ir);
    await expect(loadRequirementWithAccess(context, user, 'ir-1', IR_ACCESS_MANAGE)).rejects.toThrow();
  });

  it('a "Can manage" member does everything', async () => {
    withRight(access.MEMBER_ACCESS_RIGHT_ADMIN);
    vi.spyOn(loader, 'storeLoadById').mockResolvedValue(ir as never);
    expect(canEditRequirement(user, ir)).toBe(true);
    expect(canManageRequirement(user, ir)).toBe(true);
    await expect(loadRequirementWithAccess(context, user, 'ir-1', IR_ACCESS_MANAGE)).resolves.toBe(ir);
  });

  it('a requirement the user cannot load is hidden on a read and refused on a change', async () => {
    vi.spyOn(loader, 'storeLoadById').mockResolvedValue(undefined as never);
    await expect(loadRequirementWithAccess(context, user, 'ir-1', IR_ACCESS_READ)).resolves.toBeNull();
    await expect(loadRequirementWithAccess(context, user, 'ir-1', IR_ACCESS_EDIT)).rejects.toThrow('Intelligence requirement not found');
    await expect(loadRequirementWithAccess(context, user, 'ir-1', IR_ACCESS_MANAGE)).rejects.toThrow('Intelligence requirement not found');
  });
});
