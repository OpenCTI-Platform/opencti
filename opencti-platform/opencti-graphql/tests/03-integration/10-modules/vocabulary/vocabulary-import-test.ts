import { afterAll, describe, expect, it } from 'vitest';
import { ADMIN_USER, testContext } from '../../../utils/testQuery';
import { storeLoadById } from '../../../../src/database/middleware-loader';
import { VocabularyCategory } from '../../../../src/generated/graphql';
import { ConfigImportMode } from '../../../../src/modules/configImport/configImport-types';
import { deleteVocabulary, editVocabulary } from '../../../../src/modules/vocabulary/vocabulary-domain';
import { getVocabularyStandardId, importVocabularyCategory } from '../../../../src/modules/vocabulary/vocabulary-import';
import { ENTITY_TYPE_VOCABULARY, type BasicStoreEntityVocabulary } from '../../../../src/modules/vocabulary/vocabulary-types';
import { vocabulariesFamily } from '../../../../src/modules/configPreset/registry/vocabularies-configPreset-registry';
import { exportConfigPresetItem } from '../../../../src/modules/configPreset/configPreset-registry';

const CATEGORY = VocabularyCategory.ReportTypesOv;
const CUSTOM = { name: 'config-preset-fimi-report', category: CATEGORY };
const customId = getVocabularyStandardId(CUSTOM);
// An entry the platform creates itself, with no description, no aliases and no order
const DEFAULT = { name: 'threat-report', category: CATEGORY };
const defaultId = getVocabularyStandardId(DEFAULT);
const mode = ConfigImportMode.Overwrite;
const load = (id: string) => storeLoadById<BasicStoreEntityVocabulary>(testContext, ADMIN_USER, id, ENTITY_TYPE_VOCABULARY);
const importCategory = (entries: Record<string, unknown>[], options: { mode?: ConfigImportMode; dryRun?: boolean } = {}) => {
  return importVocabularyCategory(testContext, ADMIN_USER, { category: CATEGORY, entries }, { mode, ...options });
};
const exportableCategories = async () => (await vocabulariesFamily.resolveItems(testContext, ADMIN_USER, null, [])).map(({ id }) => id);
// The file of the category as the export writes it: undefined when the category has no entry
const exportCategory = async () => {
  const [item] = await vocabulariesFamily.resolveItems(testContext, ADMIN_USER, [CATEGORY], []);
  return item ? exportConfigPresetItem(testContext, ADMIN_USER, vocabulariesFamily, item) : undefined;
};
const exportedEntry = async (name: string) => {
  const entries = ((await exportCategory())?.configuration as { entries: { name: string }[] } | undefined)?.entries ?? [];
  return entries.find((entry) => entry.name === name);
};

describe('Vocabulary import and export (configuration preset)', () => {
  afterAll(async () => {
    // No custom entry left
    const custom = await load(customId);
    if (custom) {
      await deleteVocabulary(testContext, ADMIN_USER, custom.id);
    }
  });

  it('exports the entries the platform created, though nobody modified them', async () => {
    const stored = await load(defaultId);
    expect(stored).toMatchObject(DEFAULT);
    expect(await exportedEntry(DEFAULT.name)).toMatchObject({ name: DEFAULT.name, description: '' });
    // The entry exists on the platform: it is skipped, whatever the values of the file
    expect(await importCategory([{ name: DEFAULT.name, description: '', aliases: [], order: 0 }])).toMatchObject({ status: 'skipped', code: 'exists', exists: true });
  });

  it('exports a category whose entries are the ones of the platform, and skips the default entries it holds', async () => {
    // The defaults of these categories have the alias 'low' under the name 'low': the platform stores such an entry without alias
    const low = await load(getVocabularyStandardId({ name: 'low', category: VocabularyCategory.CaseSeverityOv }));
    expect(low).toMatchObject({ name: 'low', order: 1 });
    expect(low?.aliases ?? []).toEqual([]);
    const categories = await exportableCategories();
    expect(categories).toContain(VocabularyCategory.CaseSeverityOv);
    expect(categories).toContain(VocabularyCategory.IncidentSeverityOv);
    expect(categories).toContain(VocabularyCategory.IntegrityLevelOv);
    // The default is skipped, as it is declared or with other values
    expect(await importVocabularyCategory(testContext, ADMIN_USER, { category: VocabularyCategory.CaseSeverityOv, entries: [{ name: 'low', aliases: ['low'], order: 1 }] }, { mode }))
      .toMatchObject({ status: 'skipped', code: 'exists' });
    expect(await importVocabularyCategory(testContext, ADMIN_USER, { category: VocabularyCategory.CaseSeverityOv, entries: [{ name: 'low', description: 'Not written', order: 9 }] }, { mode }))
      .toMatchObject({ status: 'skipped', code: 'exists' });
    expect(await load(getVocabularyStandardId({ name: 'low', category: VocabularyCategory.CaseSeverityOv }))).toMatchObject({ order: 1 });
  });

  it('writes nothing on a dry run, and creates a custom entry otherwise', async () => {
    // Hidden from the start: the visibility is part of the entry, the creation is one event whatever its values
    const entry = { name: CUSTOM.name, description: 'Foreign information manipulation', aliases: ['fimi'], order: 5, is_hidden: true };
    expect(await importCategory([entry], { dryRun: true })).toMatchObject({ status: 'created', exists: false });
    expect(await load(customId)).toBeFalsy();
    expect(await importCategory([entry])).toMatchObject({ status: 'created', exists: false });
    expect(await load(customId)).toMatchObject({ ...CUSTOM, description: 'Foreign information manipulation', aliases: ['fimi'], order: 5, is_hidden: true });
    expect(await exportableCategories()).toContain(CATEGORY);
    expect(await exportedEntry(CUSTOM.name)).toEqual(entry);
  });

  it('never duplicates an entry, whatever the case of its name or the mode', async () => {
    expect(await importCategory([{ name: CUSTOM.name.toUpperCase(), order: 5 }])).toMatchObject({ status: 'skipped', code: 'exists', exists: true });
    expect(await importCategory([{ name: CUSTOM.name, order: 7 }], { mode: ConfigImportMode.Add })).toMatchObject({ status: 'skipped', code: 'exists', exists: true });
    expect(await importCategory([{ name: CUSTOM.name }], { mode: ConfigImportMode.Copy })).toMatchObject({ status: 'skipped', code: 'exists', exists: true });
    expect(await load(customId)).toMatchObject({ order: 5 });
  });

  it('refuses a name or an alias that belongs to another entry of the category, and writes nothing', async () => {
    // The entry has the alias 'fimi': the platform finds it by that name, so it is not a new entry
    const byAlias = { name: 'FIMI', description: 'Not written' };
    for (const dryRun of [true, false]) {
      expect(await importCategory([byAlias], { dryRun })).toMatchObject({ status: 'failed', code: 'alias_conflict', exists: true });
      expect(await importCategory([byAlias], { mode: ConfigImportMode.Add, dryRun })).toMatchObject({ status: 'failed', code: 'alias_conflict', exists: true });
    }
    expect(await load(customId)).toMatchObject({ description: 'Foreign information manipulation' });
    // A new entry that takes the alias or the name of another one
    const newOne = { name: 'config-preset-alias-taker', category: CATEGORY };
    expect(await importCategory([{ name: newOne.name, aliases: ['Fimi'] }])).toMatchObject({ status: 'failed', code: 'alias_conflict', exists: false });
    expect(await importCategory([{ name: newOne.name, aliases: [CUSTOM.name.toUpperCase()] }])).toMatchObject({ status: 'failed', code: 'alias_conflict', exists: false });
    expect(await load(getVocabularyStandardId(newOne))).toBeFalsy();
    // An entry that exists is skipped: its aliases are not written, so they conflict with nothing
    expect(await importCategory([{ name: DEFAULT.name, aliases: ['fimi'] }])).toMatchObject({ status: 'skipped', code: 'exists', exists: true });
    expect(await load(defaultId)).toMatchObject({ name: DEFAULT.name });
    // The same alias in another category is no conflict
    expect(await importVocabularyCategory(testContext, ADMIN_USER, { category: VocabularyCategory.IncidentTypeOv, entries: [{ name: 'config-preset-new-incident', aliases: ['fimi'] }] }, { mode, dryRun: true }))
      .toMatchObject({ status: 'created' });
  });

  it('never changes an entry that exists, whatever the values of the file', async () => {
    expect(await importCategory([{ name: CUSTOM.name, description: 'Changed', aliases: ['other'], order: 7, is_hidden: false }])).toMatchObject({ status: 'skipped', code: 'exists', exists: true });
    expect(await importCategory([{ name: CUSTOM.name, aliases: [], order: 0 }], { dryRun: true })).toMatchObject({ status: 'skipped', code: 'exists' });
    expect(await load(customId)).toMatchObject({ description: 'Foreign information manipulation', aliases: ['fimi'], order: 5, is_hidden: true });
  });

  it('adds the new entries of a category and skips the ones that exist in one import, and changes or deletes none', async () => {
    const other = { name: 'config-preset-other-report', category: CATEGORY };
    const otherId = getVocabularyStandardId(other);
    try {
      expect(await importCategory([{ name: CUSTOM.name, order: 9 }, { name: other.name, description: 'Created with the category' }])).toMatchObject({ status: 'created', exists: true });
      // The entry that exists is not written, the new one is created
      expect(await load(customId)).toMatchObject({ order: 5 });
      expect(await load(otherId)).toMatchObject({ ...other, description: 'Created with the category' });
      // An entry of the category that the file does not have stays as it is, and so does one the file has again
      expect(await importCategory([{ name: other.name, order: 1 }])).toMatchObject({ status: 'skipped', code: 'exists', exists: true });
      expect(await load(otherId)).toMatchObject({ description: 'Created with the category' });
      expect(await load(defaultId)).toMatchObject(DEFAULT);
    } finally {
      const created = await load(otherId);
      if (created) {
        await deleteVocabulary(testContext, ADMIN_USER, created.id);
      }
    }
  });

  it('exports an entry of the platform with its modification, and does not take it back over the entry', async () => {
    const edit = (description: string) => editVocabulary(testContext, ADMIN_USER, defaultId, [{ key: 'description', value: [description] }], {});
    try {
      await edit('Our own definition');
      expect(await exportedEntry(DEFAULT.name)).toMatchObject({ name: DEFAULT.name, description: 'Our own definition' });
      const file = await exportCategory();
      expect(file).toMatchObject({ type: 'taxonomy.vocabularies', id: CATEGORY, configuration: { category: CATEGORY } });
      await edit('');
      expect(await exportedEntry(DEFAULT.name)).toMatchObject({ name: DEFAULT.name, description: '' });
      // The same file on a platform where the entry has its default description: every entry exists, none is written
      expect(await importVocabularyCategory(testContext, ADMIN_USER, file?.configuration, { mode })).toMatchObject({ status: 'skipped', code: 'exists', exists: true });
      expect(await load(defaultId)).toMatchObject({ description: '' });
    } finally {
      await edit('');
    }
  });

  it('refuses a new entry in a closed category, as a result, and writes none of the category', async () => {
    const closed = { name: 'config-preset-own-opinion', category: VocabularyCategory.OpinionOv };
    const result = await importVocabularyCategory(testContext, ADMIN_USER, { category: closed.category, entries: [{ name: 'strongly-disagree', order: 42 }, { name: closed.name }] }, { mode });
    expect(result).toMatchObject({ status: 'failed', code: 'category_closed' });
    expect(result.reason).toContain(closed.name);
    expect(await load(getVocabularyStandardId(closed))).toBeFalsy();
    // The entry of the same file that was valid is not written either
    expect(await load(getVocabularyStandardId({ name: 'strongly-disagree', category: closed.category }))).not.toMatchObject({ order: 42 });
  });

  it('lists, counts, searches and resolves the categories through the family', async () => {
    const categories = await exportableCategories();
    expect(categories).toContain(CATEGORY);
    // A category is an item, its entries are not
    expect(categories.every((id) => !id.startsWith('vocabulary--'))).toBe(true);
    expect(new Set(categories).size).toBe(categories.length);
    const page = await vocabulariesFamily.listItems(testContext, ADMIN_USER, { first: 1 });
    expect(page.pageInfo.globalCount).toBe(categories.length);
    const found = await vocabulariesFamily.listItems(testContext, ADMIN_USER, { search: CATEGORY });
    expect(found.edges.map(({ node }) => [node.id, node.label])).toEqual([[CATEGORY, CATEGORY]]);
    expect((await vocabulariesFamily.listItems(testContext, ADMIN_USER, { ids: [CATEGORY, 'incident_type_ov'] })).edges.map(({ node }) => node.id)).toContain(CATEGORY);
    expect((await vocabulariesFamily.resolveItems(testContext, ADMIN_USER, [CATEGORY], [CATEGORY])).map(({ id }) => id)).toEqual([]);
    expect((await vocabulariesFamily.resolveItems(testContext, ADMIN_USER, [], [])).map(({ id }) => id)).toEqual([]);
  });

  it('imports an export of a category back, whatever the platform it comes from', async () => {
    const file = await exportCategory();
    expect(file?.configuration).toMatchObject({ category: CATEGORY, entries: expect.arrayContaining([expect.objectContaining({ name: CUSTOM.name })]) });
    await deleteVocabulary(testContext, ADMIN_USER, (await load(customId))!.id);
    expect(await load(customId)).toBeFalsy();
    expect(await importVocabularyCategory(testContext, ADMIN_USER, file?.configuration, { mode })).toMatchObject({ status: 'created' });
    expect(await load(customId)).toMatchObject({ ...CUSTOM, description: 'Foreign information manipulation' });
  });
});
