import { storeLoadById } from '../../database/middleware-loader';
import type { EditInput } from '../../generated/graphql';
import { generateStandardId } from '../../schema/identifier';
import type { AuthContext, AuthUser } from '../../types/user';
import { ConfigImportMode, type ConfigImportOptions, type ConfigImportResult } from '../configImport/configImport-types';
import { configImportValidationReason } from '../configImport/configImport-utils';
import { addVocabulary, editVocabulary, isVocabularyNameAllowed } from './vocabulary-domain';
import { type VocabularyCategoryImportConfiguration, vocabularyCategoryImportSchema, type VocabularyImportConfiguration, vocabularyImportSchema } from './vocabulary-import-schema';
import { type BasicStoreEntityVocabulary, ENTITY_TYPE_VOCABULARY } from './vocabulary-types';
import { cleanVocabularyAliases, isSameAliasSet } from './vocabulary-utils';

export type VocabularyImportCode = 'invalid' | 'exists' | 'copy_unsupported' | 'unchanged' | 'category_closed';

export type VocabularyImportResult = ConfigImportResult<VocabularyImportConfiguration, VocabularyImportCode>;

// The standard id of an entry is derived from its name (without its case) and its category: the same on every platform
export const getVocabularyStandardId = ({ name, category }: Pick<VocabularyImportConfiguration, 'name' | 'category'>) => {
  return generateStandardId(ENTITY_TYPE_VOCABULARY, { name, category });
};

const refused = (
  status: 'failed' | 'skipped',
  code: VocabularyImportCode,
  reason: string,
  exists: boolean,
  configuration?: VocabularyImportConfiguration,
): VocabularyImportResult => ({ status, code, reason, exists, configuration });

// What differs between an entry and the configuration: a value that is null or absent is left untouched
const toPatch = (existing: BasicStoreEntityVocabulary, { name, description, aliases, order }: VocabularyImportConfiguration): EditInput[] => {
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
  return patch;
};

// The one place where a vocabulary entry is imported: validates, finds the entry by its name and category and writes it.
// A refusal is a result, not an error. A dry run decides the same result and writes nothing.
// add: the entry must not exist yet. overwrite: an entry of the same name and category gets the description, the aliases and the order of
// the configuration, else it is created; a value that is null or absent leaves the entry untouched, and the aliases are replaced as a
// whole. An entry is its name and its category: it has no copy.
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
  const { name, category, description, aliases, order } = parsed.data;
  const existing = await storeLoadById<BasicStoreEntityVocabulary>(context, user, getVocabularyStandardId(parsed.data), ENTITY_TYPE_VOCABULARY);
  if (mode === ConfigImportMode.Copy) {
    return refused('failed', 'copy_unsupported', 'A vocabulary entry has no copy', !!existing, parsed.data);
  }
  if (!existing) {
    // A closed category only has its default entries: the platform refuses a new one
    if (!isVocabularyNameAllowed(category, name)) {
      return refused('failed', 'category_closed', 'This vocabulary category is closed, new values cannot be added', false, parsed.data);
    }
    if (!dryRun) {
      await addVocabulary(context, user, { name, category, description: description ?? '', aliases: aliases ?? [], order: order ?? 0 });
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
