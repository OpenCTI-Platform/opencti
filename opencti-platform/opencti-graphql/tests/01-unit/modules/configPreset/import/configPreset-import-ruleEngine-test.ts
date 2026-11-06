import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../../../../src/modules/rule/rule-import', () => ({ importConfigPresetRule: vi.fn() }));

import { importConfigPresetRule } from '../../../../../src/modules/rule/rule-import';
import { RULES_DECLARATION } from '../../../../../src/domain/rules';
import { CONFIG_PRESET_FAMILIES } from '../../../../../src/modules/configPreset/configPreset-registry';
import type { ConfigPresetBundleItem, ConfigPresetComputedItem, ConfigPresetImportPlan } from '../../../../../src/modules/configPreset/import/configPreset-import-types';
import type { AuthContext, AuthUser } from '../../../../../src/types/user';
import { ConfigImportMode } from '../../../../../src/modules/configImport/configImport-types';

const context = { source: 'test' } as AuthContext;
const user = { id: 'user-id' } as AuthUser;
const family = CONFIG_PRESET_FAMILIES.find(({ id }) => id === 'ruleEngine')!;
const plan: ConfigPresetImportPlan = { created: new Set() };
const [rule] = RULES_DECLARATION;
const item = (configuration: Record<string, unknown>, id = rule.id): ConfigPresetBundleItem => ({ type: 'ruleEngine', id, path: `${id}.json`, configuration });
const computed = {} as ConfigPresetComputedItem;

beforeEach(() => {
  vi.resetAllMocks();
});

describe('Rule engine import (registry)', () => {
  it('is importable, and offers no choice of mode: a rule has no copy', () => {
    expect(family.importer).toBeDefined();
    expect(family.importModes).toBeUndefined();
    expect(family.requiresEnterpriseEdition).toBeUndefined();
  });

  it('computes the item with a dry run of the module, named by the rule, and previews whether the bundle turns it on', async () => {
    vi.mocked(importConfigPresetRule).mockResolvedValue({ status: 'overwritten', exists: true, configuration: { active: true }, reason: 'Activating the rule starts a scan of the knowledge base' });
    const result = await family.importer!.compute(context, user, item({ active: true }), plan, ConfigImportMode.Overwrite);
    expect(importConfigPresetRule).toHaveBeenCalledWith(context, user, rule.id, { active: true }, { mode: ConfigImportMode.Overwrite, dryRun: true });
    expect(result).toEqual({
      label: rule.name,
      translatable: true,
      status: 'overwritten',
      exists: true,
      conflict: true,
      reason: 'Activating the rule starts a scan of the knowledge base',
      code: undefined,
      fields: undefined,
      isEnabled: true,
    });
  });

  it('names a rule this platform does not declare by its id, and previews no state for a configuration the module refused', async () => {
    vi.mocked(importConfigPresetRule).mockResolvedValue({ status: 'failed', code: 'unknown_rule', reason: 'Unknown rule', exists: false, configuration: { active: false } });
    expect(await family.importer!.compute(context, user, item({ active: false }, 'unknown_rule'), plan, ConfigImportMode.Overwrite))
      .toMatchObject({ label: 'unknown_rule', translatable: false, status: 'failed', reason: 'Unknown rule', isEnabled: false });
    vi.mocked(importConfigPresetRule).mockResolvedValue({ status: 'failed', code: 'invalid', reason: 'active: Invalid input', exists: true });
    expect(await family.importer!.compute(context, user, item({}), plan, ConfigImportMode.Overwrite)).toMatchObject({ status: 'failed', isEnabled: null });
  });

  it('applies through the module, reports a status that differs from the computed one, and throws on a failure', async () => {
    vi.mocked(importConfigPresetRule).mockResolvedValueOnce({ status: 'overwritten', exists: true });
    expect(await family.importer!.apply(context, user, item({ active: true }), { ...computed, status: 'overwritten' }, ConfigImportMode.Overwrite, plan)).toBeUndefined();
    expect(importConfigPresetRule).toHaveBeenCalledWith(context, user, rule.id, { active: true }, { mode: ConfigImportMode.Overwrite });
    vi.mocked(importConfigPresetRule).mockResolvedValueOnce({ status: 'skipped', code: 'unchanged', exists: true });
    expect(await family.importer!.apply(context, user, item({ active: true }), { ...computed, status: 'overwritten' }, ConfigImportMode.Overwrite, plan)).toBe('skipped');
    vi.mocked(importConfigPresetRule).mockResolvedValueOnce({ status: 'failed', code: 'unknown_rule', reason: 'Unknown rule', exists: false });
    await expect(family.importer!.apply(context, user, item({ active: true }, 'unknown_rule'), computed, ConfigImportMode.Overwrite, plan)).rejects.toThrow('Unknown rule');
  });
});
