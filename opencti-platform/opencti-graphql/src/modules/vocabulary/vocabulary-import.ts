import * as R from 'ramda';
import { storeLoadById } from '../../database/middleware-loader';
import { generateStandardId, normalizeName } from '../../schema/identifier';
import type { AuthContext, AuthUser } from '../../types/user';
import type { ConfigImportOptions, ConfigImportResult } from '../configImport/configImport-types';
import { CONFIG_IMPORT_REASON_SEPARATOR, configImportReasonValue, configImportRefusal, configImportValidationReason } from '../configImport/configImport-utils';
import { addVocabulary, isVocabularyNameAllowed } from './vocabulary-domain';
import { type VocabularyCategoryImportConfiguration, vocabularyCategoryImportSchema, type VocabularyImportConfiguration, vocabularyImportSchema } from './vocabulary-import-schema';
import { type BasicStoreEntityVocabulary, ENTITY_TYPE_VOCABULARY } from './vocabulary-types';
import { cleanVocabularyAliases } from './vocabulary-utils';

// An entry costs a few reads: the dry run of a category reads a few entries at a time, whatever the number of entries of the file
const DRY_RUN_BATCH_SIZE = 10;

export type VocabularyImportCode = 'invalid' | 'exists' | 'category_closed' | 'alias_conflict';

export type VocabularyImportResult = ConfigImportResult<VocabularyImportConfiguration, VocabularyImportCode>;

// The standard id of an entry is derived from its name (without its case) and its category: the same on every platform
export const getVocabularyStandardId = ({ name, category }: Pick<VocabularyImportConfiguration, 'name' | 'category'>) => {
  return generateStandardId(ENTITY_TYPE_VOCABULARY, { name, category });
};

// The platform finds an entry by its name and by its aliases: loaded by the standard id of a name, it can return the entry that holds this
// name as an alias
const loadEntry = (context: AuthContext, user: AuthUser, name: string, category: VocabularyImportConfiguration['category']) => {
  return storeLoadById<BasicStoreEntityVocabulary>(context, user, getVocabularyStandardId({ name, category }), ENTITY_TYPE_VOCABULARY);
};

// The first alias of the configuration that is the name or an alias of an entry of the category: the platform would write that entry
// when the new one is created
const findAliasOfAnotherEntry = async (context: AuthContext, user: AuthUser, { name, category, aliases }: VocabularyImportConfiguration) => {
  for (const alias of cleanVocabularyAliases(name, aliases)) {
    if (await loadEntry(context, user, alias, category)) {
      return alias;
    }
  }
  return undefined;
};

const refused = configImportRefusal<VocabularyImportConfiguration, VocabularyImportCode>;

// The one place where a vocabulary entry is imported: validates, finds the entry by its name and category and creates it when it is new.
// A refusal is a result, not an error. A dry run decides the same result and writes nothing.
// An entry that exists is skipped, never written: the entries of a platform (its default ones included, which an export holds) are not changed
// by a bundle, only the ones it does not have are added. The mode does not matter: there is nothing to overwrite and no copy. A name or an alias
// that is already an alias or the name of another entry of the category is a conflict: that entry is never written in place of the new one.
export const importVocabulary = async (
  context: AuthContext,
  user: AuthUser,
  configuration: unknown,
  { dryRun = false }: ConfigImportOptions,
): Promise<VocabularyImportResult> => {
  const parsed = vocabularyImportSchema.safeParse(configuration);
  if (!parsed.success) {
    return refused('failed', 'invalid', configImportValidationReason(parsed.error), false);
  }
  const { name, category, description, aliases, order, is_hidden: isHidden } = parsed.data;
  const found = await loadEntry(context, user, name, category);
  if (found) {
    // Found by its name: the entry exists. Found by an alias of another entry: the name is taken
    if (normalizeName(found.name) === normalizeName(name) && found.category === category) {
      return refused('skipped', 'exists', 'Vocabulary entry already exists', true, parsed.data);
    }
    return refused('failed', 'alias_conflict', `The name is an alias of the vocabulary entry ${found.name}`, true, parsed.data);
  }
  // A closed category only has its default entries: the platform refuses a new one
  if (!isVocabularyNameAllowed(category, name)) {
    return refused('failed', 'category_closed', 'This vocabulary category is closed, new values cannot be added', false, parsed.data);
  }
  const taken = await findAliasOfAnotherEntry(context, user, parsed.data);
  if (taken) {
    return refused('failed', 'alias_conflict', `The alias ${taken} belongs to another vocabulary entry`, false, parsed.data);
  }
  if (!dryRun) {
    await addVocabulary(context, user, {
      name,
      category,
      description: description ?? '',
      aliases: aliases ?? [],
      order: order ?? 0,
      ...(isHidden !== null && isHidden !== undefined ? { is_hidden: isHidden } : {}),
    });
  }
  return { status: 'created', exists: false, configuration: parsed.data };
};

export type VocabularyCategoryImportResult = ConfigImportResult<VocabularyCategoryImportConfiguration, VocabularyImportCode>;

// The one place where the entries of a category are imported: each entry is imported by importVocabulary, so the rules are the ones of an entry
// (found by its name and its category, created when it is new, skipped when it exists, never changed or deleted). Every entry is decided on a
// dry run first, and nothing is written when one of them fails. A category that has no new entry is skipped: an export holds the entries of the
// platform, the ones that are new are the only ones added.
// The writes are not a transaction: an entry that fails on the real pass (it changed since the dry run) is reported, the entries written
// before it stay.
export const importVocabularyCategory = async (
  context: AuthContext,
  user: AuthUser,
  configuration: unknown,
  { mode, dryRun = false }: ConfigImportOptions,
): Promise<VocabularyCategoryImportResult> => {
  const parsed = vocabularyCategoryImportSchema.safeParse(configuration);
  if (!parsed.success) {
    return { status: 'failed', code: 'invalid', reason: configImportValidationReason(parsed.error), exists: false };
  }
  const { category, entries } = parsed.data;
  // A dry run writes nothing: the entries are read a few at a time
  const decided: { entry: VocabularyImportConfiguration; result: VocabularyImportResult }[] = [];
  for (const batch of R.splitEvery(DRY_RUN_BATCH_SIZE, entries)) {
    decided.push(...await Promise.all(batch.map(async (entry) => {
      const entryConfiguration = { ...entry, category };
      return { entry: entryConfiguration, result: await importVocabulary(context, user, entryConfiguration, { mode, dryRun: true }) };
    })));
  }
  const exists = decided.some(({ result }) => result.exists);
  const failed = decided.filter((item) => item.result.status === 'failed');
  if (failed.length > 0) {
    // One reason per entry, on its own line: the front translates each one, and an entry name can hold a comma
    const reason = failed.map(({ entry, result }) => `${configImportReasonValue(entry.name)}: ${result.reason}`).join(CONFIG_IMPORT_REASON_SEPARATOR);
    return { status: 'failed', code: failed[0].result.code, reason, exists, configuration: parsed.data };
  }
  const created = decided.filter((item) => item.result.status === 'created');
  if (created.length === 0) {
    return { status: 'skipped', code: 'exists', reason: 'Vocabulary entries already exist', exists, configuration: parsed.data };
  }
  if (!dryRun) {
    for (const { entry } of created) {
      const written = await importVocabulary(context, user, entry, { mode });
      if (written.status === 'failed') {
        return { status: 'failed', code: written.code, reason: `${configImportReasonValue(entry.name)}: ${written.reason}`, exists, configuration: parsed.data };
      }
    }
  }
  return { status: 'created', exists, configuration: parsed.data };
};
