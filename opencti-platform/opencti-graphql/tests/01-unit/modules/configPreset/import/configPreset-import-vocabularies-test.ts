import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../../../../src/modules/vocabulary/vocabulary-import', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../../src/modules/vocabulary/vocabulary-import')>()),
  importVocabularyCategory: vi.fn(),
}));

// Registers the Vocabulary type, which the platform does at boot
import '../../../../../src/modules/vocabulary/vocabulary';
import { importVocabularyCategory } from '../../../../../src/modules/vocabulary/vocabulary-import';
import { CONFIG_PRESET_FAMILIES } from '../../../../../src/modules/configPreset/configPreset-registry';
import type { ConfigPresetBundleItem, ConfigPresetComputedItem, ConfigPresetImportPlan } from '../../../../../src/modules/configPreset/import/configPreset-import-types';
import type { AuthContext, AuthUser } from '../../../../../src/types/user';
import { ConfigImportMode } from '../../../../../src/modules/configImport/configImport-types';

const context = { source: 'test' } as AuthContext;
const user = { id: 'user-id' } as AuthUser;
const family = CONFIG_PRESET_FAMILIES.find(({ id }) => id === 'vocabularies')!;
const plan: ConfigPresetImportPlan = { created: new Set() };
const category = 'report_types_ov';
const configuration = { category, entries: [{ name: 'fimi-report', description: 'Foreign information manipulation', order: 5 }] };
const item = (itemConfiguration: Record<string, unknown>, id = category): ConfigPresetBundleItem => ({ type: 'vocabularies', id, path: `taxonomy/vocabularies/${id}.json`, configuration: itemConfiguration });
const computed = {} as ConfigPresetComputedItem;

beforeEach(() => {
  vi.resetAllMocks();
});

describe('Vocabularies import (registry)', () => {
  it('is importable and offers no choice of mode: a category has no copy', () => {
    expect(family.importer).toBeDefined();
    expect(family.importModes).toBeUndefined();
  });

  it('computes the item with a dry run of the module, named by its category', async () => {
    vi.mocked(importVocabularyCategory).mockResolvedValue({ status: 'overwritten', exists: true });
    const result = await family.importer!.compute(context, user, item(configuration), plan, ConfigImportMode.Overwrite);
    expect(importVocabularyCategory).toHaveBeenCalledWith(context, user, configuration, { mode: ConfigImportMode.Overwrite, dryRun: true });
    expect(result).toMatchObject({ label: 'report_types_ov', translatable: false, status: 'overwritten', exists: true, conflict: true });
  });

  it('fails an item whose id is not its category, without asking the module', async () => {
    const result = await family.importer!.compute(context, user, item(configuration, 'incident_type_ov'), plan, ConfigImportMode.Overwrite);
    expect(result).toMatchObject({ status: 'failed', label: 'report_types_ov', reason: 'The id of the vocabulary category does not match its category' });
    expect(importVocabularyCategory).not.toHaveBeenCalled();
  });

  it('leaves a configuration without category to the module, which refuses it, and names the item by its id', async () => {
    vi.mocked(importVocabularyCategory).mockResolvedValue({ status: 'failed', code: 'invalid', reason: 'category: Invalid input', exists: false });
    expect(await family.importer!.compute(context, user, item({ entries: configuration.entries }), plan, ConfigImportMode.Overwrite))
      .toMatchObject({ status: 'failed', label: category, reason: 'category: Invalid input' });
  });

  it('reports the failure of an entry as a failure of the item', async () => {
    vi.mocked(importVocabularyCategory).mockResolvedValue({ status: 'failed', code: 'category_closed', reason: 'my-own-opinion: This vocabulary category is closed, new values cannot be added', exists: false });
    const result = await family.importer!.compute(context, user, item({ category: 'opinion_ov', entries: [{ name: 'my-own-opinion' }] }, 'opinion_ov'), plan, ConfigImportMode.Overwrite);
    expect(result).toMatchObject({ status: 'failed', label: 'opinion_ov', code: 'category_closed', reason: expect.stringContaining('my-own-opinion') });
  });

  it('applies through the module, reports a status that differs from the computed one, and throws on a failure', async () => {
    vi.mocked(importVocabularyCategory).mockResolvedValueOnce({ status: 'created', exists: false });
    expect(await family.importer!.apply(context, user, item(configuration), { ...computed, status: 'created' }, ConfigImportMode.Overwrite, plan)).toBeUndefined();
    expect(importVocabularyCategory).toHaveBeenCalledWith(context, user, configuration, { mode: ConfigImportMode.Overwrite });
    vi.mocked(importVocabularyCategory).mockResolvedValueOnce({ status: 'skipped', code: 'exists', exists: true });
    expect(await family.importer!.apply(context, user, item(configuration), { ...computed, status: 'created' }, ConfigImportMode.Overwrite, plan)).toBe('skipped');
    vi.mocked(importVocabularyCategory).mockResolvedValueOnce({ status: 'failed', code: 'category_closed', reason: 'closed', exists: false });
    await expect(family.importer!.apply(context, user, item(configuration), { ...computed, status: 'created' }, ConfigImportMode.Overwrite, plan)).rejects.toThrow('closed');
  });
});
