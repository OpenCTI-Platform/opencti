import { z } from 'zod';
import { VocabularyCategory } from '../../generated/graphql';
import { normalizeName } from '../../schema/identifier';
import { cleanVocabularyAliases } from './vocabulary-utils';

// The rules of a vocabulary entry to import, whatever the source: strict, unknown keys are rejected.
// An entry is its name and its category: the platform derives its standard id from them, without the case of the name.
export const vocabularyImportSchema = z.strictObject({
  name: z.string().trim().min(1, 'Vocabulary name is required'),
  // A category this platform does not know (a bundle of a newer platform) is refused
  category: z.enum(VocabularyCategory),
  // Absent or null: a new entry is given its default
  description: z.string().nullable().optional(),
  // Only used to create an entry: an entry that exists is never written
  aliases: z.array(z.string()).nullable().optional(),
  order: z.number().int().nullable().optional(),
  // A hidden entry is not offered as a choice of the fields of its category. Absent or null: a new entry is visible
  is_hidden: z.boolean().nullable().optional(),
});

export type VocabularyImportConfiguration = z.infer<typeof vocabularyImportSchema>;

// An entry of a category: the category is the one of the file
export const vocabularyEntryImportSchema = vocabularyImportSchema.omit({ category: true });

// The entries of one category to import: the entries of a category as a whole
export const vocabularyCategoryImportSchema = z.strictObject({
  category: z.enum(VocabularyCategory),
  entries: z.array(vocabularyEntryImportSchema).min(1, 'At least one vocabulary entry is required'),
}).refine(
  ({ entries }) => new Set(entries.map(({ name }) => normalizeName(name))).size === entries.length,
  { path: ['entries'], message: 'A vocabulary entry is listed twice', abort: true },
).refine(
  // The platform finds an entry by its name and by its aliases: a name or an alias held by two entries would make it write the first one
  // when it creates the second
  ({ entries }) => {
    const keys = entries.flatMap(({ name, aliases }) => [normalizeName(name), ...cleanVocabularyAliases(name, aliases).map(normalizeName)]);
    return new Set(keys).size === keys.length;
  },
  { path: ['entries'], message: 'A vocabulary name or alias is used by several entries' },
);

export type VocabularyCategoryImportConfiguration = z.infer<typeof vocabularyCategoryImportSchema>;
