import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../../../../src/modules/emailTemplate/emailTemplate-import', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../../src/modules/emailTemplate/emailTemplate-import')>()),
  importEmailTemplate: vi.fn(),
}));

import { importEmailTemplate } from '../../../../../src/modules/emailTemplate/emailTemplate-import';
import { CONFIG_PRESET_FAMILIES } from '../../../../../src/modules/configPreset/configPreset-registry';
import type { ConfigPresetBundleItem, ConfigPresetComputedItem, ConfigPresetImportPlan } from '../../../../../src/modules/configPreset/import/configPreset-import-types';
import type { AuthContext, AuthUser } from '../../../../../src/types/user';
import { ConfigImportMode } from '../../../../../src/modules/configImport/configImport-types';

const context = { source: 'test' } as AuthContext;
const user = { id: 'user-id' } as AuthUser;
const family = CONFIG_PRESET_FAMILIES.find(({ id }) => id === 'emailTemplates')!;
const plan: ConfigPresetImportPlan = { created: new Set() };
// The id of a bundle item is the standard id of the platform it comes from: random, it says nothing of the content
const BUNDLE_ID = 'emailtemplate--5d2c1a7e-3b4f-4c6d-8e9f-0a1b2c3d4e5f';
const configuration = { name: 'Welcome analyst', email_object: 'Welcome', sender_email: 'CTI team', template_body: '<p>Hello</p>' };
const item = (config: Record<string, unknown> = configuration): ConfigPresetBundleItem => ({
  type: 'securityAccess.emailTemplates',
  id: BUNDLE_ID,
  path: `security_access/email_templates/${BUNDLE_ID}.json`,
  configuration: config,
});
const computed = {} as ConfigPresetComputedItem;

beforeEach(() => {
  vi.resetAllMocks();
});

describe('Email templates import (registry)', () => {
  it('is importable and offers the choice between overwriting a template and adding a copy of it', () => {
    expect(family.importer).toBeDefined();
    expect(family.importModes).toEqual([ConfigImportMode.Overwrite, ConfigImportMode.Copy]);
  });

  it('shares the names that the copies of a dry run reserve through the plan', async () => {
    const reservedNames = new Set<string>();
    vi.mocked(importEmailTemplate).mockResolvedValue({ status: 'created', exists: true, reason: 'Added as "Welcome analyst (1)"' });
    const result = await family.importer!.compute(context, user, item(), { ...plan, emailTemplateNames: reservedNames }, ConfigImportMode.Copy);
    expect(importEmailTemplate).toHaveBeenCalledWith(context, user, configuration, { mode: ConfigImportMode.Copy, dryRun: true, reservedNames });
    expect(result).toMatchObject({ status: 'created', exists: true, conflict: true, reason: 'Added as "Welcome analyst (1)"' });
  });

  it('computes the item with a dry run of the module, named by its name, whatever its bundle id', async () => {
    vi.mocked(importEmailTemplate).mockResolvedValue({ status: 'overwritten', exists: true });
    const result = await family.importer!.compute(context, user, item(), plan, ConfigImportMode.Overwrite);
    expect(importEmailTemplate).toHaveBeenCalledWith(context, user, configuration, { mode: ConfigImportMode.Overwrite, dryRun: true });
    expect(result).toMatchObject({ label: 'Welcome analyst', translatable: false, status: 'overwritten', exists: true, conflict: true });
  });

  it('reports a template that does not exist as created, without conflict', async () => {
    vi.mocked(importEmailTemplate).mockResolvedValue({ status: 'created', exists: false });
    expect(await family.importer!.compute(context, user, item(), plan, ConfigImportMode.Overwrite)).toMatchObject({ status: 'created', exists: false, conflict: false });
  });

  it('shows the code of a refusal of the module', async () => {
    vi.mocked(importEmailTemplate).mockResolvedValue({ status: 'failed', code: 'ambiguous', reason: 'Several email templates have this name', exists: true });
    expect(await family.importer!.compute(context, user, item(), plan, ConfigImportMode.Overwrite)).toMatchObject({ status: 'failed', code: 'ambiguous', reason: 'Several email templates have this name' });
  });

  it.each([
    ['without a name', {}],
    ['with a blank name', { name: '   ' }],
    ['with a name that is not a string', { name: 12 }],
  ])('leaves a configuration %s to the module, which refuses it, and names the item by its id', async (_name, config) => {
    vi.mocked(importEmailTemplate).mockResolvedValue({ status: 'failed', code: 'invalid', reason: 'name: Invalid input', exists: false });
    expect(await family.importer!.compute(context, user, item(config), plan, ConfigImportMode.Overwrite)).toMatchObject({ status: 'failed', label: BUNDLE_ID, reason: 'name: Invalid input' });
    expect(importEmailTemplate).toHaveBeenCalledOnce();
  });

  it('applies through the module, reports a status that differs from the computed one, and throws on a failure', async () => {
    vi.mocked(importEmailTemplate).mockResolvedValueOnce({ status: 'created', exists: false });
    expect(await family.importer!.apply(context, user, item(), { ...computed, status: 'created' }, ConfigImportMode.Overwrite, plan)).toBeUndefined();
    expect(importEmailTemplate).toHaveBeenCalledWith(context, user, configuration, { mode: ConfigImportMode.Overwrite });
    // Created by another import since the dry run
    vi.mocked(importEmailTemplate).mockResolvedValueOnce({ status: 'skipped', code: 'unchanged', exists: true });
    expect(await family.importer!.apply(context, user, item(), { ...computed, status: 'created' }, ConfigImportMode.Overwrite, plan)).toBe('skipped');
    vi.mocked(importEmailTemplate).mockResolvedValueOnce({ status: 'failed', code: 'invalid', reason: 'name: Invalid input', exists: false });
    await expect(family.importer!.apply(context, user, item(), { ...computed, status: 'created' }, ConfigImportMode.Overwrite, plan)).rejects.toThrow('name: Invalid input');
  });
});
