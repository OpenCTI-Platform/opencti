import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../../../../src/modules/fintelDesign/fintelDesign-import', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../../src/modules/fintelDesign/fintelDesign-import')>()),
  importFintelDesign: vi.fn(),
}));

import { importFintelDesign } from '../../../../../src/modules/fintelDesign/fintelDesign-import';
import { CONFIG_PRESET_FAMILIES } from '../../../../../src/modules/configPreset/configPreset-registry';
import { buildConfigPresetImportTypes } from '../../../../../src/modules/configPreset/import/configPreset-import-domain';
import type {
  ConfigPresetBundle,
  ConfigPresetBundleItem,
  ConfigPresetComputedItem,
  ConfigPresetImportPlan,
} from '../../../../../src/modules/configPreset/import/configPreset-import-types';
import type { AuthContext, AuthUser } from '../../../../../src/types/user';
import { ConfigImportMode } from '../../../../../src/modules/configImport/configImport-types';
import { defaultFintelDesign, nightFintelDesign } from '../configPreset-fintelDesigns-fixtures';
import { exportFintelDesign } from '../../../../../src/modules/fintelDesign/fintelDesign-export';

const context = { source: 'test' } as AuthContext;
const user = { id: 'user-id' } as AuthUser;
const family = CONFIG_PRESET_FAMILIES.find(({ id }) => id === 'fintelDesigns')!;
// The plan of the preview, which reserves the names of the earlier items; the one of a real import has none
const plan: ConfigPresetImportPlan = { created: new Set(), fintelDesignNames: new Set(), renamedFintelDesignIds: new Set() };
const bundleId = defaultFintelDesign.standard_id;
const configuration = exportFintelDesign(defaultFintelDesign);
const attachment = { path: `customization/fintel_designs/${bundleId}.logo`, read: vi.fn() };
const item = (config: Record<string, unknown>, id: string = bundleId): ConfigPresetBundleItem => ({
  type: 'fintelDesigns',
  id,
  path: `customization/fintel_designs/${id}.json`,
  configuration: config,
  attachment,
});
const computed = {} as ConfigPresetComputedItem;

beforeEach(() => {
  vi.resetAllMocks();
});

describe('Fintel designs import (registry)', () => {
  it('is importable, in the Customization group, for the Enterprise Edition only, and offers overwrite or a copy of a design that exists', () => {
    expect(family.importer).toBeDefined();
    expect(family.importModes).toEqual(['OVERWRITE', 'COPY']);
    expect(family.requiresEnterpriseEdition).toBe(true);
    expect(family.group).toEqual({ id: 'customization', label: 'Customization' });
    expect(family.directory).toBe('customization/fintel_designs');
  });

  it('reserves nothing during a real import: an item that fails leaves no name to the next ones, which read the platform', async () => {
    vi.mocked(importFintelDesign).mockResolvedValue({ status: 'created', exists: true });
    const realImportPlan: ConfigPresetImportPlan = { created: new Set(), targets: new Map() };
    await family.importer!.compute(context, user, item(configuration), realImportPlan, ConfigImportMode.Copy);
    expect(vi.mocked(importFintelDesign).mock.calls[0][4]).toMatchObject({ reservedNames: undefined, renamedIds: undefined });
    expect(realImportPlan).toEqual({ created: new Set(), targets: new Map() });
  });

  it('computes the item with a dry run of the module, with the logo of the item, named by its name and marked as the default it is', async () => {
    vi.mocked(importFintelDesign).mockResolvedValue({ status: 'overwritten', exists: true });
    const result = await family.importer!.compute(context, user, item(configuration), plan, ConfigImportMode.Overwrite);
    expect(importFintelDesign).toHaveBeenCalledWith(context, user, configuration, attachment, {
      mode: ConfigImportMode.Overwrite,
      dryRun: true,
      reservedNames: plan.fintelDesignNames,
      renamedIds: plan.renamedFintelDesignIds,
    });
    expect(result).toMatchObject({ label: 'Filigran report', translatable: false, isDefault: true, status: 'overwritten', exists: true, conflict: true });
    vi.mocked(importFintelDesign).mockResolvedValue({ status: 'created', exists: false });
    const night = exportFintelDesign(nightFintelDesign);
    expect(await family.importer!.compute(context, user, item(night, nightFintelDesign.standard_id), plan, ConfigImportMode.Overwrite))
      .toMatchObject({ label: 'Night briefing', isDefault: false, status: 'created', exists: false, conflict: false });
  });

  it('fails an item whose id is not the standard id of its design, without asking the module', async () => {
    const result = await family.importer!.compute(context, user, item(configuration, nightFintelDesign.standard_id), plan, ConfigImportMode.Overwrite);
    expect(result).toMatchObject({ status: 'failed', reason: 'The standard id of the fintel design does not match its id' });
    expect(await family.importer!.compute(context, user, item({ ...configuration, standard_id: 'x' }, 'x'), plan, ConfigImportMode.Overwrite)).toMatchObject({ status: 'failed' });
    expect(importFintelDesign).not.toHaveBeenCalled();
  });

  it('applies through the module with the logo, reports a status that differs from the computed one, and throws on a failure', async () => {
    vi.mocked(importFintelDesign).mockResolvedValueOnce({ status: 'created', exists: false });
    expect(await family.importer!.apply(context, user, item(configuration), { ...computed, status: 'created' }, ConfigImportMode.Copy, plan)).toBeUndefined();
    expect(importFintelDesign).toHaveBeenCalledWith(context, user, configuration, attachment, { mode: ConfigImportMode.Copy });
    vi.mocked(importFintelDesign).mockResolvedValueOnce({ status: 'skipped', code: 'unchanged', exists: true });
    expect(await family.importer!.apply(context, user, item(configuration), { ...computed, status: 'created' }, ConfigImportMode.Overwrite, plan)).toBe('skipped');
    vi.mocked(importFintelDesign).mockResolvedValueOnce({ status: 'failed', code: 'logo_too_large', reason: 'The logo of the fintel design is too large', exists: true });
    await expect(family.importer!.apply(context, user, item(configuration), { ...computed, status: 'created' }, ConfigImportMode.Overwrite, plan)).rejects.toThrow('too large');
  });

  it('shows the default design of the bundle as the default in the preview, and the other designs as depending on it', () => {
    const designPath = (id: string) => `customization/fintel_designs/${id}.json`;
    const bundle = {
      metadata: { openCTI_version: '1.0.0', generated_at: '2026-01-01T00:00:00.000Z', bundle_name: null },
      items: [item(configuration), { ...item(exportFintelDesign(nightFintelDesign), nightFintelDesign.standard_id) }],
      dependencies: { 'customization.fintelDesigns': { [nightFintelDesign.standard_id]: { [bundleId]: designPath(bundleId) } } },
      ignored: [],
    } as ConfigPresetBundle;
    const results = bundle.items.map((bundleItem) => ({
      item: bundleItem,
      computed: { label: bundleItem.id, translatable: false, exists: false, conflict: false, status: 'created', isDefault: bundleItem.configuration.default === true } as ConfigPresetComputedItem,
    }));
    const [type] = buildConfigPresetImportTypes(bundle, results, new Map([['fintelDesigns', true]]));
    expect(type.items.map(({ key, isDefault, dependsOn }) => [key, isDefault, dependsOn])).toEqual([
      [bundleId, true, []],
      [nightFintelDesign.standard_id, false, [{ type: 'fintelDesigns', key: bundleId }]],
    ]);
  });
});
