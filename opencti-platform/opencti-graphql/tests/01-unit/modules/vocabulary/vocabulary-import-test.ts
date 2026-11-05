import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../../../src/database/middleware-loader', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/database/middleware-loader')>()),
  storeLoadById: vi.fn(),
}));
vi.mock('../../../../src/modules/vocabulary/vocabulary-domain', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/modules/vocabulary/vocabulary-domain')>()),
  addVocabulary: vi.fn(),
  editVocabulary: vi.fn(),
}));

// Registers the Vocabulary type, which the platform does at boot
import '../../../../src/modules/vocabulary/vocabulary';
import { storeLoadById } from '../../../../src/database/middleware-loader';
import { addVocabulary, editVocabulary } from '../../../../src/modules/vocabulary/vocabulary-domain';
import { ConfigImportMode } from '../../../../src/modules/configImport/configImport-types';
import { getVocabularyStandardId, importVocabulary, importVocabularyCategory } from '../../../../src/modules/vocabulary/vocabulary-import';
import { vocabularyCategoryImportSchema, vocabularyImportSchema } from '../../../../src/modules/vocabulary/vocabulary-import-schema';
import { getVocabularyCategories, getVocabularyCategoryConfigPresetConfiguration } from '../../../../src/modules/vocabulary/vocabulary-export';
import { cleanVocabularyAliases, openVocabularies } from '../../../../src/modules/vocabulary/vocabulary-utils';
import { ENTITY_TYPE_VOCABULARY, type BasicStoreEntityVocabulary } from '../../../../src/modules/vocabulary/vocabulary-types';
import { VocabularyCategory } from '../../../../src/generated/graphql';
import type { AuthContext, AuthUser } from '../../../../src/types/user';

const context = { source: 'test' } as AuthContext;
const user = { id: 'user-id' } as AuthUser;
const entry = { name: 'fimi-report', category: VocabularyCategory.ReportTypesOv };
const stored = { id: 'vocabulary-internal-id', standard_id: getVocabularyStandardId(entry), ...entry, description: 'Foreign information manipulation', aliases: ['fimi'], order: 5 } as BasicStoreEntityVocabulary;

// An entry as the platform creates it from its defaults: no description is '', no aliases [], no order 0, and the name of the entry is not
// kept as one of its aliases (the default 'low' with the alias 'low' is stored without alias)
const seeded = (category: VocabularyCategory, key: string) => {
  const { description, aliases, order } = openVocabularies[category].find((candidate) => candidate.key === key)!;
  const kept = (aliases ?? []).filter((alias) => alias.toLowerCase() !== key.toLowerCase());
  return { name: key, category, description: description ?? '', aliases: kept, order: order ?? 0 } as BasicStoreEntityVocabulary;
};

const withExisting = (vocabulary?: BasicStoreEntityVocabulary) => vi.mocked(storeLoadById).mockResolvedValue(vocabulary as never);

beforeEach(() => {
  vi.resetAllMocks();
  withExisting(undefined);
});

describe('Vocabulary identity', () => {
  it('derives the standard id from the name and the category, whatever the case of the name', () => {
    expect(getVocabularyStandardId(entry)).toMatch(/^vocabulary--[0-9a-f-]{36}$/);
    expect(getVocabularyStandardId({ ...entry, name: ' FIMI-Report ' })).toBe(getVocabularyStandardId(entry));
    expect(getVocabularyStandardId({ ...entry, category: VocabularyCategory.IncidentTypeOv })).not.toBe(getVocabularyStandardId(entry));
  });
});

describe('Vocabulary import schema', () => {
  it('accepts a name and a category, with or without the other values, and trims the name', () => {
    expect(vocabularyImportSchema.parse({ ...entry, name: ' fimi-report ' })).toEqual(entry);
    expect(vocabularyImportSchema.parse({ ...entry, description: '', aliases: [], order: 0 })).toEqual({ ...entry, description: '', aliases: [], order: 0 });
    expect(vocabularyImportSchema.parse({ ...entry, description: null, aliases: null, order: null })).toEqual({ ...entry, description: null, aliases: null, order: null });
  });

  it.each([
    [{}],
    [{ name: 'fimi-report' }],
    [{ category: 'report_types_ov' }],
    [{ ...entry, name: '   ' }],
    [{ ...entry, category: 'not_a_category_ov' }],
    [{ ...entry, aliases: 'fimi' }],
    [{ ...entry, aliases: [1] }],
    [{ ...entry, order: 1.5 }],
    [{ ...entry, builtIn: true }],
    [{ ...entry, standard_id: 'vocabulary--x' }],
  ])('refuses %j', (configuration) => {
    expect(vocabularyImportSchema.safeParse(configuration).success).toBe(false);
  });
});

describe('Vocabulary category import schema', () => {
  const category = VocabularyCategory.ReportTypesOv;

  it('accepts a category with its entries, which have no category of their own, and trims their name', () => {
    expect(vocabularyCategoryImportSchema.parse({ category, entries: [{ name: ' fimi-report ', description: 'Foreign information manipulation', aliases: ['fimi'], order: 5 }, { name: 'other' }] }))
      .toEqual({ category, entries: [{ name: 'fimi-report', description: 'Foreign information manipulation', aliases: ['fimi'], order: 5 }, { name: 'other' }] });
  });

  it.each([
    [{}],
    [{ category }],
    [{ entries: [{ name: 'fimi-report' }] }],
    [{ category, entries: [] }],
    [{ category: 'not_a_category_ov', entries: [{ name: 'fimi-report' }] }],
    [{ category, entries: [{ name: '  ' }] }],
    [{ category, entries: [{ name: 'fimi-report', category }] }],
    [{ category, entries: [{ name: 'fimi-report', order: 1.5 }] }],
    [{ category, entries: [{ name: 'fimi-report' }], builtIn: true }],
    [{ category, entries: [{ name: 'fimi-report' }, { name: ' FIMI-Report ' }] }],
  ])('refuses %j', (configuration) => {
    expect(vocabularyCategoryImportSchema.safeParse(configuration).success).toBe(false);
  });
});

describe('Which categories are exported, and how', () => {
  const all = [
    seeded(VocabularyCategory.ReportTypesOv, 'threat-report'),
    { ...seeded(VocabularyCategory.ReportTypesOv, 'internal-report'), name: 'fimi-report', description: 'Foreign information manipulation', aliases: ['fimi'], order: 5 },
    { ...seeded(VocabularyCategory.IntegrityLevelOv, 'high'), description: 'Our own description' },
    seeded(VocabularyCategory.IntegrityLevelOv, 'low'),
    seeded(VocabularyCategory.IncidentTypeOv, 'phishing'),
  ] as BasicStoreEntityVocabulary[];

  it('exports every category that has an entry, once, the ones of the platform included', () => {
    expect(getVocabularyCategories(all)).toEqual([VocabularyCategory.ReportTypesOv, VocabularyCategory.IntegrityLevelOv, VocabularyCategory.IncidentTypeOv]);
    expect(getVocabularyCategories([])).toEqual([]);
  });

  it('exports all the entries of the category, the ones nobody modified included', () => {
    expect(getVocabularyCategoryConfigPresetConfiguration(VocabularyCategory.ReportTypesOv, all)).toEqual({
      category: 'report_types_ov',
      entries: [
        expect.objectContaining({ name: 'threat-report' }),
        { name: 'fimi-report', description: 'Foreign information manipulation', aliases: ['fimi'], order: 5 },
      ],
    });
    expect(getVocabularyCategoryConfigPresetConfiguration(VocabularyCategory.IntegrityLevelOv, all).entries).toEqual([
      expect.objectContaining({ name: 'high', description: 'Our own description' }),
      expect.objectContaining({ name: 'low' }),
    ]);
    expect(getVocabularyCategoryConfigPresetConfiguration(VocabularyCategory.IncidentTypeOv, all).entries).toEqual([expect.objectContaining({ name: 'phishing' })]);
    expect(getVocabularyCategoryConfigPresetConfiguration(VocabularyCategory.CoverageOv, all)).toEqual({ category: 'coverage_ov', entries: [] });
  });

  it('leaves out of an entry its category, the values it does not have and everything the import does not accept', () => {
    const configuration = getVocabularyCategoryConfigPresetConfiguration(entry.category, [
      { ...stored, creator_id: ['secret'], builtIn: false } as BasicStoreEntityVocabulary,
      { ...stored, name: 'no-values', description: null, aliases: undefined, order: undefined } as unknown as BasicStoreEntityVocabulary,
    ]);
    expect(configuration.entries).toEqual([
      { name: 'fimi-report', description: 'Foreign information manipulation', aliases: ['fimi'], order: 5 },
      { name: 'no-values' },
    ]);
    expect(JSON.stringify(configuration)).not.toMatch(/secret|builtIn|standard_id|vocabulary-internal-id/);
  });

  it('is the format of the import, so an export imports back as is', () => {
    const configuration = getVocabularyCategoryConfigPresetConfiguration(VocabularyCategory.ReportTypesOv, all);
    expect(vocabularyCategoryImportSchema.safeParse(configuration).success).toBe(true);
  });

  it('exports every entry the platform creates, as the platform stores it, in the format of the import', () => {
    const everyDefault = (Object.keys(openVocabularies) as VocabularyCategory[]).flatMap((category) => openVocabularies[category].map(({ key }) => seeded(category, key)));
    expect(everyDefault.length).toBeGreaterThan(100);
    const categories = getVocabularyCategories(everyDefault);
    expect(categories.length).toBeGreaterThan(10);
    categories.forEach((category) => {
      expect(vocabularyCategoryImportSchema.safeParse(getVocabularyCategoryConfigPresetConfiguration(category, everyDefault)).success).toBe(true);
    });
  });
});

describe('The aliases of an entry', () => {
  it('keeps the aliases of an entry as the platform does: not its name, not an empty one, once each', () => {
    expect(cleanVocabularyAliases('low', ['low', 'Low', ' l ', '', 'L', 'weak'])).toEqual(['l', 'weak']);
    expect(cleanVocabularyAliases('low', null)).toEqual([]);
    expect(cleanVocabularyAliases('low')).toEqual([]);
  });
});

describe('importVocabulary', () => {
  it('refuses an invalid configuration with the path of each issue, without reading the platform', async () => {
    const result = await importVocabulary(context, user, { name: '', category: 'nope' }, { mode: ConfigImportMode.Overwrite });
    expect(result).toMatchObject({ status: 'failed', code: 'invalid', exists: false });
    expect(result.reason).toContain('name: Vocabulary name is required');
    expect(result.reason).toContain('category');
    expect(storeLoadById).not.toHaveBeenCalled();
  });

  it('finds the entry by its standard id', async () => {
    await importVocabulary(context, user, entry, { mode: ConfigImportMode.Overwrite, dryRun: true });
    expect(storeLoadById).toHaveBeenCalledWith(context, user, getVocabularyStandardId(entry), ENTITY_TYPE_VOCABULARY);
  });

  describe.each([ConfigImportMode.Overwrite, ConfigImportMode.Add])('an entry that does not exist (%s)', (mode) => {
    it('creates it with the values of the configuration', async () => {
      const configuration = { ...entry, description: 'Foreign information manipulation', aliases: ['fimi'], order: 5 };
      expect(await importVocabulary(context, user, configuration, { mode })).toMatchObject({ status: 'created', exists: false });
      expect(addVocabulary).toHaveBeenCalledWith(context, user, configuration);
    });

    it('gives it the defaults of the platform for what the configuration does not have', async () => {
      await importVocabulary(context, user, entry, { mode });
      expect(addVocabulary).toHaveBeenLastCalledWith(context, user, { ...entry, description: '', aliases: [], order: 0 });
      await importVocabulary(context, user, { ...entry, description: null, aliases: null, order: null }, { mode });
      expect(addVocabulary).toHaveBeenLastCalledWith(context, user, { ...entry, description: '', aliases: [], order: 0 });
    });

    it('decides the same result on a dry run, and writes nothing', async () => {
      expect(await importVocabulary(context, user, entry, { mode, dryRun: true })).toMatchObject({ status: 'created', exists: false });
      expect(addVocabulary).not.toHaveBeenCalled();
    });
  });

  describe('a closed category', () => {
    const closed = { name: 'my-own-opinion', category: VocabularyCategory.OpinionOv };

    it('refuses a new entry, as a result, since the platform would refuse to create it', async () => {
      const result = await importVocabulary(context, user, closed, { mode: ConfigImportMode.Overwrite });
      expect(result).toMatchObject({ status: 'failed', code: 'category_closed', exists: false });
      expect(await importVocabulary(context, user, closed, { mode: ConfigImportMode.Overwrite, dryRun: true })).toMatchObject({ code: 'category_closed' });
      expect(addVocabulary).not.toHaveBeenCalled();
    });

    it('creates one of its own default entries, which an administrator deleted', async () => {
      expect(await importVocabulary(context, user, { name: 'strongly-disagree', category: 'opinion_ov' }, { mode: ConfigImportMode.Overwrite })).toMatchObject({ status: 'created' });
      expect(addVocabulary).toHaveBeenCalledTimes(1);
    });
  });

  describe('an entry that exists, overwrite', () => {
    beforeEach(() => withExisting(stored));
    const overwrite = (configuration: unknown, dryRun = false) => importVocabulary(context, user, configuration, { mode: ConfigImportMode.Overwrite, dryRun });

    it('patches what differs, and only that', async () => {
      expect(await overwrite({ ...entry, description: 'Another description', aliases: ['fimi'], order: 5 })).toMatchObject({ status: 'overwritten', exists: true });
      expect(editVocabulary).toHaveBeenCalledWith(context, user, stored.id, [{ key: 'description', value: ['Another description'] }], {});
      await overwrite({ ...entry, description: 'Foreign information manipulation', aliases: ['fimi', 'fim'], order: 6 });
      expect(editVocabulary).toHaveBeenLastCalledWith(context, user, stored.id, [{ key: 'aliases', value: ['fimi', 'fim'] }, { key: 'order', value: [6] }], {});
      expect(addVocabulary).not.toHaveBeenCalled();
    });

    it('replaces the aliases as a whole, an empty list included, and takes the order 0 and the empty description for values', async () => {
      await overwrite({ ...entry, description: '', aliases: [], order: 0 });
      expect(editVocabulary).toHaveBeenCalledWith(context, user, stored.id, [
        { key: 'description', value: [''] },
        { key: 'aliases', value: [] },
        { key: 'order', value: [0] },
      ], {});
    });

    it('writes nothing on a dry run', async () => {
      expect(await overwrite({ ...entry, order: 6 }, true)).toMatchObject({ status: 'overwritten', exists: true });
      expect(editVocabulary).not.toHaveBeenCalled();
    });

    it.each([
      ['has the same values, the aliases in another order', { ...entry, description: 'Foreign information manipulation', aliases: ['fimi'], order: 5 }],
      ['has no value', entry],
      ['has null values', { ...entry, description: null, aliases: null, order: null }],
    ])('skips it when the configuration %s', async (_name, configuration) => {
      expect(await overwrite(configuration)).toMatchObject({ status: 'skipped', code: 'unchanged', exists: true, reason: 'Already up to date' });
      expect(editVocabulary).not.toHaveBeenCalled();
    });

    it('does not count the order of the aliases as a change', async () => {
      withExisting({ ...stored, aliases: ['a', 'b'] } as BasicStoreEntityVocabulary);
      expect(await overwrite({ ...entry, aliases: ['b', 'a'] })).toMatchObject({ status: 'skipped', code: 'unchanged' });
    });

    it('does not take the name of the entry for an alias, as the platform does not keep it', async () => {
      withExisting({ ...stored, aliases: [] } as BasicStoreEntityVocabulary);
      expect(await overwrite({ ...entry, aliases: ['FIMI-Report'] })).toMatchObject({ status: 'skipped', code: 'unchanged' });
      expect(await overwrite({ ...entry, aliases: ['FIMI-Report', 'fimi'] })).toMatchObject({ status: 'overwritten' });
    });

    it('treats an entry created without description, aliases and order as having the defaults', async () => {
      withExisting({ ...stored, description: undefined, aliases: undefined, order: undefined } as unknown as BasicStoreEntityVocabulary);
      expect(await overwrite({ ...entry, description: '', aliases: [], order: 0 })).toMatchObject({ status: 'skipped', code: 'unchanged' });
    });
  });

  it('refuses an entry that exists when the mode is add', async () => {
    withExisting(stored);
    expect(await importVocabulary(context, user, { ...entry, order: 6 }, { mode: ConfigImportMode.Add })).toMatchObject({ status: 'failed', code: 'exists', exists: true });
    expect(editVocabulary).not.toHaveBeenCalled();
  });

  it('has no copy: an entry is its name and its category', async () => {
    withExisting(stored);
    expect(await importVocabulary(context, user, entry, { mode: ConfigImportMode.Copy })).toMatchObject({ status: 'failed', code: 'copy_unsupported', exists: true });
    withExisting(undefined);
    expect(await importVocabulary(context, user, entry, { mode: ConfigImportMode.Copy })).toMatchObject({ status: 'failed', code: 'copy_unsupported', exists: false });
    expect(addVocabulary).not.toHaveBeenCalled();
    expect(editVocabulary).not.toHaveBeenCalled();
  });
});

describe('importVocabularyCategory', () => {
  const category = VocabularyCategory.ReportTypesOv;
  const other = { name: 'sev-report', category, description: 'Another one', aliases: [], order: 2 };
  const otherStored = { ...other, id: 'other-internal-id', standard_id: getVocabularyStandardId(other) } as unknown as BasicStoreEntityVocabulary;
  const entries = [{ name: 'fimi-report', description: 'Foreign information manipulation', aliases: ['fimi'], order: 5 }, { name: 'sev-report', description: 'Another one', order: 2 }];
  const overwrite = (configuration: unknown, dryRun = false) => importVocabularyCategory(context, user, configuration, { mode: ConfigImportMode.Overwrite, dryRun });
  // The entries of the platform, found by their standard id
  const withPlatform = (...vocabularies: BasicStoreEntityVocabulary[]) => {
    vi.mocked(storeLoadById).mockImplementation(async (_ctx, _user, id) => vocabularies.find(({ standard_id: standardId }) => standardId === id) as never);
  };

  it('refuses an invalid configuration with the path of each issue, without reading the platform', async () => {
    const result = await overwrite({ category: 'nope', entries: [] });
    expect(result).toMatchObject({ status: 'failed', code: 'invalid', exists: false });
    expect(result.reason).toContain('category');
    expect(result.reason).toContain('entries: At least one vocabulary entry is required');
    expect(await overwrite({ category, entries: [{ name: 'a' }, { name: 'A' }] })).toMatchObject({ status: 'failed', code: 'invalid', reason: 'entries: A vocabulary entry is listed twice' });
    expect(storeLoadById).not.toHaveBeenCalled();
  });

  it('creates the entries that do not exist, in the category of the file', async () => {
    expect(await overwrite({ category, entries })).toMatchObject({ status: 'created', exists: false });
    expect(addVocabulary).toHaveBeenCalledTimes(2);
    expect(addVocabulary).toHaveBeenNthCalledWith(1, context, user, { name: 'fimi-report', category, description: 'Foreign information manipulation', aliases: ['fimi'], order: 5 });
    expect(addVocabulary).toHaveBeenNthCalledWith(2, context, user, { name: 'sev-report', category, description: 'Another one', aliases: [], order: 2 });
  });

  it('overwrites the entries that exist, and creates the others: it adds or modifies, never deletes', async () => {
    withPlatform({ ...otherStored, description: 'Before' } as BasicStoreEntityVocabulary);
    expect(await overwrite({ category, entries })).toMatchObject({ status: 'overwritten', exists: true });
    expect(addVocabulary).toHaveBeenCalledTimes(1);
    expect(addVocabulary).toHaveBeenCalledWith(context, user, expect.objectContaining({ name: 'fimi-report', category }));
    expect(editVocabulary).toHaveBeenCalledTimes(1);
    expect(editVocabulary).toHaveBeenCalledWith(context, user, otherStored.id, [{ key: 'description', value: ['Another one'] }], {});
  });

  it('writes nothing on a dry run, and decides the same result', async () => {
    expect(await overwrite({ category, entries }, true)).toMatchObject({ status: 'created', exists: false });
    withPlatform(stored, otherStored);
    expect(await overwrite({ category, entries: [{ name: 'fimi-report', order: 6 }, { name: 'sev-report' }] }, true)).toMatchObject({ status: 'overwritten', exists: true });
    expect(addVocabulary).not.toHaveBeenCalled();
    expect(editVocabulary).not.toHaveBeenCalled();
  });

  it('skips a category whose entries are all the ones of the platform, and writes nothing', async () => {
    withPlatform(stored, otherStored);
    expect(await overwrite({ category, entries: [{ name: 'FIMI-report', description: 'Foreign information manipulation', aliases: ['fimi'], order: 5 }, { name: 'sev-report' }] }))
      .toMatchObject({ status: 'skipped', code: 'unchanged', exists: true, reason: 'Already up to date' });
    expect(addVocabulary).not.toHaveBeenCalled();
    expect(editVocabulary).not.toHaveBeenCalled();
  });

  it('only writes the entries that differ', async () => {
    withPlatform(stored, otherStored);
    expect(await overwrite({ category, entries: [{ name: 'fimi-report', order: 5 }, { name: 'sev-report', order: 3 }] })).toMatchObject({ status: 'overwritten' });
    expect(editVocabulary).toHaveBeenCalledTimes(1);
    expect(editVocabulary).toHaveBeenCalledWith(context, user, otherStored.id, [{ key: 'order', value: [3] }], {});
  });

  it('is created when the entries are only created, whatever the entries that are unchanged', async () => {
    withPlatform(stored);
    expect(await overwrite({ category, entries: [{ name: 'fimi-report', order: 5 }, { name: 'brand-new' }] })).toMatchObject({ status: 'created', exists: true });
    expect(addVocabulary).toHaveBeenCalledTimes(1);
    expect(editVocabulary).not.toHaveBeenCalled();
  });

  it('fails the whole category, and writes nothing, when one of its entries fails, naming the entry', async () => {
    const closed = VocabularyCategory.OpinionOv;
    const result = await overwrite({ category: closed, entries: [{ name: 'strongly-disagree' }, { name: 'my-own-opinion' }, { name: 'another-opinion' }] });
    expect(result).toMatchObject({ status: 'failed', code: 'category_closed', exists: false });
    expect(result.reason).toBe('my-own-opinion: This vocabulary category is closed, new values cannot be added, another-opinion: This vocabulary category is closed, new values cannot be added');
    expect(addVocabulary).not.toHaveBeenCalled();
    expect(editVocabulary).not.toHaveBeenCalled();
  });

  it('has no copy', async () => {
    withPlatform(stored);
    expect(await importVocabularyCategory(context, user, { category, entries }, { mode: ConfigImportMode.Copy })).toMatchObject({ status: 'failed', code: 'copy_unsupported', exists: true });
    expect(addVocabulary).not.toHaveBeenCalled();
  });

  it('refuses an existing entry when the mode is add, and writes nothing', async () => {
    withPlatform(stored);
    expect(await importVocabularyCategory(context, user, { category, entries }, { mode: ConfigImportMode.Add })).toMatchObject({ status: 'failed', code: 'exists', exists: true });
    expect(addVocabulary).not.toHaveBeenCalled();
  });
});
