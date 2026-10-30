import { Readable } from 'node:stream';
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

const enterpriseEdition = vi.hoisted(() => ({ enabled: false }));
const FILE_ID = vi.hoisted(() => 'config_preset/import/bundle.zip');
const bundle = vi.hoisted(() => ({ items: [] as { type: string; id: string; path: string; configuration: Record<string, unknown> }[] }));
vi.mock('../../../../src/enterprise-edition/ee', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/enterprise-edition/ee')>()),
  isEnterpriseEdition: vi.fn(async () => enterpriseEdition.enabled),
}));
vi.mock('../../../../src/domain/settings', () => ({
  getSettings: vi.fn(),
  settingsEditField: vi.fn(),
  getPlatformDefaultTheme: vi.fn(),
}));
vi.mock('../../../../src/database/file-storage', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/database/file-storage')>()),
  loadFile: vi.fn(async () => ({ internal_id: FILE_ID, metaData: { creator_id: 'user-id' } })),
}));
vi.mock('../../../../src/database/raw-file-storage', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/database/raw-file-storage')>()),
  downloadFile: vi.fn(async () => Readable.from([Buffer.from('zip')])),
}));
vi.mock('../../../../src/modules/configPreset/import/configPreset-import-bundle', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/modules/configPreset/import/configPreset-import-bundle')>()),
  readConfigPresetBundle: vi.fn(async () => ({
    metadata: { openCTI_version: '1.0.0', generated_at: '2026-01-01T00:00:00.000Z', bundle_name: null },
    items: bundle.items,
    dependencies: {},
    ignored: [],
  })),
}));

import { CONFIG_PRESET_FAMILIES } from '../../../../src/modules/configPreset/configPreset-registry';
import type { ConfigPresetFamilyDefinition } from '../../../../src/modules/configPreset/configPreset-types';
import {
  addConfigPresetDependencies,
  findConfigPresetExportableTypes,
  resolveConfigPresetSelections,
} from '../../../../src/modules/configPreset/export/configPreset-export-domain';
import { computeConfigPresetItem, configPresetImportPreview } from '../../../../src/modules/configPreset/import/configPreset-import-domain';
import { CONFIG_PRESET_REASON_ENTERPRISE_EDITION_REQUIRED } from '../../../../src/modules/configPreset/import/configPreset-import-types';
import { platformSettingsGroup } from '../../../../src/modules/configPreset/registry/common-configPreset-registry';
import { ConfigImportMode } from '../../../../src/modules/configImport/configImport-types';
import type { AuthContext, AuthUser } from '../../../../src/types/user';

const context = { source: 'test' } as AuthContext;
const user = { id: 'user-id', capabilities: [{ name: 'BYPASS' }] } as unknown as AuthUser;

// What the domain of a family that requires the Enterprise Edition does without it: it refuses, whoever asks
const guarded = () => vi.fn(async () => {
  throw new Error('Enterprise edition is not enabled');
});
// A family that is not in the registry yet, standing for the next ones (the fintel designs): nothing of it may be reached without the license
const futureFamily = (): ConfigPresetFamilyDefinition => ({
  id: 'future',
  label: 'Future designs',
  description: 'Designs of a future family',
  group: platformSettingsGroup,
  directory: 'future',
  requiresEnterpriseEdition: true,
  listItems: guarded(),
  resolveItems: guarded(),
  importer: { compute: guarded(), apply: guarded() },
});

const registered = [...CONFIG_PRESET_FAMILIES];
// Every family that requires the Enterprise Edition, the registered ones and the one that stands for the next ones
const flagged = () => CONFIG_PRESET_FAMILIES.filter((family) => family.requiresEnterpriseEdition);

describe('Contract of a family that requires the Enterprise Edition, on a platform without it', () => {
  beforeAll(() => {
    // Only these families are in the registry: the contract is about them, not about what the others read
    CONFIG_PRESET_FAMILIES.splice(0, CONFIG_PRESET_FAMILIES.length, ...registered.filter((family) => family.requiresEnterpriseEdition), futureFamily());
  });

  afterAll(() => {
    CONFIG_PRESET_FAMILIES.splice(0, CONFIG_PRESET_FAMILIES.length, ...registered);
  });

  beforeEach(() => {
    enterpriseEdition.enabled = false;
    bundle.items = flagged().map((family) => ({ type: family.id, id: family.id, path: `${family.directory}/${family.id}.json`, configuration: {} }));
  });

  it('has at least the family that stands for the next ones, and the whitemark', () => {
    expect(flagged().map((family) => family.id)).toEqual(expect.arrayContaining(['whitemark', 'future']));
  });

  it('is listed by the export as a locked type, and its items are never read', async () => {
    const listItems = flagged().map((family) => vi.spyOn(family, 'listItems'));
    const types = await findConfigPresetExportableTypes(context, user);
    expect(types.map((type) => type.key)).toEqual(flagged().map((family) => family.id));
    types.forEach((type) => expect(type).toMatchObject({ requiresEnterpriseEdition: true, locked: true, items: [], itemsPageInfo: { hasNextPage: false, globalCount: 0 } }));
    listItems.forEach((spy) => expect(spy).not.toHaveBeenCalled());
  });

  it('cannot be exported, and its items are never read', async () => {
    for (let i = 0; i < flagged().length; i += 1) {
      const family = flagged()[i];
      const resolveItems = vi.spyOn(family, 'resolveItems');
      await expect(resolveConfigPresetSelections(context, user, [{ type: family.id, items: null }])).rejects.toThrow('Enterprise edition is not enabled');
      expect(resolveItems).not.toHaveBeenCalled();
    }
  });

  it('is not read to complete an export, whatever the item that depends on it', async () => {
    for (let i = 0; i < flagged().length; i += 1) {
      const family = flagged()[i];
      const resolveItems = vi.spyOn(family, 'resolveItems');
      const free = { ...CONFIG_PRESET_FAMILIES[0], items: [{ id: 'free', label: 'Free', translatable: false, exporter: vi.fn(), dependsOn: [{ type: family.id, id: 'item' }] }] };
      await expect(addConfigPresetDependencies(context, user, [free])).rejects.toThrow('A configuration preset dependency cannot be exported');
      expect(resolveItems).not.toHaveBeenCalled();
    }
  });

  it('is skipped by the import, and its importer is never called', async () => {
    for (let i = 0; i < flagged().length; i += 1) {
      const family = flagged()[i];
      const compute = vi.spyOn(family.importer!, 'compute');
      const item = { type: family.id, id: family.id, path: `${family.id}.json`, configuration: {} };
      const computed = await computeConfigPresetItem(context, user, family, item, { created: new Set() }, ConfigImportMode.Overwrite);
      expect(computed).toMatchObject({ status: 'skipped', reason: CONFIG_PRESET_REASON_ENTERPRISE_EDITION_REQUIRED, conflict: false });
      expect(compute).not.toHaveBeenCalled();
    }
  });

  it('is shown by the import preview as a locked type, without items', async () => {
    const preview = await configPresetImportPreview(context, user, FILE_ID);
    expect(preview.types.map((type) => type.key)).toEqual(flagged().map((family) => family.id));
    preview.types.forEach((type) => expect(type).toMatchObject({ requiresEnterpriseEdition: true, locked: true, items: [] }));
  });
});
