import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../../../../src/modules/user/role-import', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../../src/modules/user/role-import')>()),
  importRole: vi.fn(),
}));
vi.mock('../../../../../src/modules/user/group-import', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../../src/modules/user/group-import')>()),
  importGroup: vi.fn(),
}));

import { importRole, roleStandardId } from '../../../../../src/modules/user/role-import';
import { groupStandardId, importGroup } from '../../../../../src/modules/user/group-import';
import { CONFIG_PRESET_FAMILIES } from '../../../../../src/modules/configPreset/configPreset-registry';
import { configPresetTargets, type ConfigPresetBundleItem, type ConfigPresetImportPlan } from '../../../../../src/modules/configPreset/import/configPreset-import-types';
import { ConfigImportMode } from '../../../../../src/modules/configImport/configImport-types';
import type { AuthContext, AuthUser } from '../../../../../src/types/user';

const context = { source: 'test' } as AuthContext;
const user = { id: 'user-id' } as AuthUser;

const importerOf = (type: string) => CONFIG_PRESET_FAMILIES.find((family) => family.id === type)!.importer!;
const roleItem: ConfigPresetBundleItem = { type: 'roles', id: roleStandardId('Analyst'), path: 'analyst.json', configuration: { name: 'Analyst' } };
const groupItem: ConfigPresetBundleItem = { type: 'groups', id: groupStandardId('SOC'), path: 'soc.json', configuration: { name: 'SOC' } };
const copyId = roleStandardId('Analyst (1)');

const newPlan = (): ConfigPresetImportPlan => ({ created: new Set(), roleSensitiveRights: new Map(), targets: new Map() });

beforeEach(() => {
  vi.resetAllMocks();
  vi.mocked(importGroup).mockResolvedValue({ status: 'created', exists: false });
});

describe('A role imported as COPY and a group of the same import that depends on it', () => {
  it('records the copy in the plan, with its rights, under the bundle id of the role', async () => {
    vi.mocked(importRole).mockResolvedValue({ status: 'created', exists: true, targetId: copyId, grantsSensitiveRights: false });
    const plan = newPlan();
    await importerOf('roles').compute(context, user, roleItem, plan, ConfigImportMode.Copy);
    expect(plan.targets).toEqual(new Map([[`roles/${roleItem.id}`, copyId]]));
    expect(configPresetTargets(plan, 'roles')).toEqual(new Map([[roleItem.id, copyId]]));
    expect(plan.roleSensitiveRights).toEqual(new Map([[copyId, false]]));
  });

  it('gives the group the copy, in the preview and when the import writes it', async () => {
    const plan = newPlan();
    plan.targets!.set(`roles/${roleItem.id}`, copyId);
    plan.roleSensitiveRights!.set(copyId, false);
    const roleTargets = new Map([[roleItem.id, copyId]]);
    const computed = await importerOf('groups').compute(context, user, groupItem, plan, ConfigImportMode.Overwrite);
    expect(importGroup).toHaveBeenCalledWith(context, user, groupItem.configuration, expect.objectContaining({
      dryRun: true,
      roleTargets,
      plannedRoles: new Map([[copyId, { grantsSensitiveRights: false }]]),
    }));
    await importerOf('groups').apply(context, user, groupItem, computed, ConfigImportMode.Overwrite, plan);
    expect(importGroup).toHaveBeenLastCalledWith(context, user, groupItem.configuration, { mode: ConfigImportMode.Overwrite, roleTargets });
  });

  it('records that a role that fails is not written, whatever its mode, so that its groups fail with it', async () => {
    vi.mocked(importRole).mockResolvedValue({ status: 'failed', code: 'name_conflict', reason: 'Role name already exists', exists: true });
    await Promise.all([ConfigImportMode.Copy, ConfigImportMode.Overwrite].map(async (mode) => {
      const plan = newPlan();
      await importerOf('roles').compute(context, user, roleItem, plan, mode);
      expect(configPresetTargets(plan, 'roles')).toEqual(new Map([[roleItem.id, null]]));
    }));
  });
});
