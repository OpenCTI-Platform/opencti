import { storeLoadById } from '../../database/middleware-loader';
import type { EditInput } from '../../generated/graphql';
import { generateStandardId, normalizeName } from '../../schema/identifier';
import type { AuthContext, AuthUser } from '../../types/user';
import { ConfigImportMode, type ConfigImportOptions, type ConfigImportResult } from '../configImport/configImport-types';
import { configImportRefusal, configImportValidationReason } from '../configImport/configImport-utils';
import { addVocabulary, editVocabulary, isVocabularyNameAllowed } from './vocabulary-domain';
import { type VocabularyCategoryImportConfiguration, vocabularyCategoryImportSchema, type VocabularyImportConfiguration, vocabularyImportSchema } from './vocabulary-import-schema';
import { type BasicStoreEntityVocabulary, ENTITY_TYPE_VOCABULARY } from './vocabulary-types';
import { cleanVocabularyAliases, isSameAliasSet } from './vocabulary-utils';

export type VocabularyImportCode = 'invalid' | 'exists' | 'copy_unsupported' | 'unchanged' | 'category_closed' | 'alias_conflict';

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

// The first alias of the configuration that is the name or an alias of another entry of the category: the platform would write that entry
// when the entry is created, and refuse the alias when it is edited. The aliases the entry already has are its own.
const findAliasOfAnotherEntry = async (
  context: AuthContext,
  user: AuthUser,
  { name, category, aliases }: VocabularyImportConfiguration,
  existing?: BasicStoreEntityVocabulary,
) => {
  const own = cleanVocabularyAliases(name, existing?.aliases).map(normalizeName);
  for (const alias of cleanVocabularyAliases(name, aliases).filter((candidate) => !own.includes(normalizeName(candidate)))) {
    const owner = await loadEntry(context, user, alias, category);
    if (owner && owner.id !== existing?.id) {
      return alias;
    }
  }
  return undefined;
};

const refused = configImportRefusal<VocabularyImportConfiguration, VocabularyImportCode>;

// What differs between an entry and the configuration: a value that is null or absent is left untouched
const toPatch = (existing: BasicStoreEntityVocabulary, { name, description, aliases, order, is_hidden: isHidden }: VocabularyImportConfiguration): EditInput[] => {
  const patch: EditInput[] = [];
  if (description !== null && description !== undefined && description !== (existing.description ?? '')) {
    patch.push({ key: 'description', value: [description] });
  }
  // The aliases are compared as the platform keeps them: the name of the entry is not an alias
  if (aliases !== null && aliases !== undefined && !isSameAliasSet(cleanVocabularyAliases(name, aliases), cleanVocabularyAliases(existing.name, existing.aliases))) {
    patch.push({ key: 'aliases', value: aliases });
  }
  // 0 is an order
  if (order !== null && order !== undefined && order !== (existing.order ?? 0)) {
    patch.push({ key: 'order', value: [order] });
  }
  // An entry that was never hidden has no value: it is visible
  if (isHidden !== null && isHidden !== undefined && isHidden !== (existing.is_hidden ?? false)) {
    patch.push({ key: 'is_hidden', value: [isHidden] });
  }
  return patch;
};

// The one place where a vocabulary entry is imported: validates, finds the entry by its name and category and writes it.
// A refusal is a result, not an error. A dry run decides the same result and writes nothing.
// add: the entry must not exist yet. overwrite: an entry of the same name and category gets the description, the aliases, the order and the
// visibility of the configuration, else it is created; a value that is null or absent leaves the entry untouched, and the aliases are replaced
// as a whole. An entry is its name and its category: it has no copy. A name or an alias that is already an alias or the name of another entry
// of the category is a conflict: that entry is never written in place of the requested one.
export const importVocabulary = async (
  context: AuthContext,
  user: AuthUser,
  configuration: unknown,
  { mode, dryRun = false }: ConfigImportOptions,
): Promise<VocabularyImportResult> => {
  const parsed = vocabularyImportSchema.safeParse(configuration);
  if (!parsed.success) {
    return refused('failed', 'invalid', configImportValidationReason(parsed.error), false);
  }
  const { name, category, description, aliases, order, is_hidden: isHidden } = parsed.data;
  const found = await loadEntry(context, user, name, category);
  // Found by its name, not by an alias of another entry
  const existing = found && normalizeName(found.name) === normalizeName(name) && found.category === category ? found : undefined;
  if (mode === ConfigImportMode.Copy) {
    return refused('failed', 'copy_unsupported', 'A vocabulary entry has no copy', !!existing, parsed.data);
  }
  if (found && !existing) {
    return refused('failed', 'alias_conflict', `The name is an alias of the vocabulary entry ${found.name}`, true, parsed.data);
  }
  if (!existing) {
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
  }
  if (mode === ConfigImportMode.Add) {
    return refused('failed', 'exists', 'Vocabulary entry already exists', true, parsed.data);
  }
  const patch = toPatch(existing, parsed.data);
  if (patch.length === 0) {
    return refused('skipped', 'unchanged', 'Already up to date', true, parsed.data);
  }
  const taken = patch.some(({ key }) => key === 'aliases') ? await findAliasOfAnotherEntry(context, user, parsed.data, existing) : undefined;
  if (taken) {
    return refused('failed', 'alias_conflict', `The alias ${taken} belongs to another vocabulary entry`, true, parsed.data);
  }
  if (!dryRun) {
    await editVocabulary(context, user, existing.id, patch, {});
  }
  return { status: 'overwritten', exists: true, configuration: parsed.data };
};

export type VocabularyCategoryImportResult = ConfigImportResult<VocabularyCategoryImportConfiguration, VocabularyImportCode>;

// The one place where the entries of a category are imported: each entry is imported by importVocabulary, so the rules are the ones of an entry
// (found by its name and its category, created or overwritten, never deleted, no copy). A category is all or nothing: every entry is decided on
// a dry run first, and nothing is written when one of them fails. A category that has no entry to create or overwrite is skipped.
// The result is overwritten when an entry is overwritten, created when the entries are only created.
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
  const decided: { entry: VocabularyImportConfiguration; result: VocabularyImportResult }[] = [];
  for (const entry of entries) {
    const entryConfiguration = { ...entry, category };
    decided.push({ entry: entryConfiguration, result: await importVocabulary(context, user, entryConfiguration, { mode, dryRun: true }) });
  }
  const exists = decided.some(({ result }) => result.exists);
  const failed = decided.filter(({ result }) => result.status === 'failed');
  if (failed.length > 0) {
    const reason = failed.map(({ entry, result }) => `${entry.name}: ${result.reason}`).join(', ');
    return { status: 'failed', code: failed[0].result.code, reason, exists, configuration: parsed.data };
  }
  const changes = decided.filter(({ result }) => result.status !== 'skipped');
  if (changes.length === 0) {
    return { status: 'skipped', code: 'unchanged', reason: 'Already up to date', exists, configuration: parsed.data };
  }
  if (!dryRun) {
    for (const { entry } of changes) {
      await importVocabulary(context, user, entry, { mode });
    }
  }
  return { status: changes.some(({ result }) => result.status === 'overwritten') ? 'overwritten' : 'created', exists, configuration: parsed.data };
};
