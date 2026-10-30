import { z } from 'zod';
import { VocabularyCategory } from '../../generated/graphql';
import { normalizeName } from '../../schema/identifier';

// The rules of a vocabulary entry to import, whatever the source (a configuration preset): strict, unknown keys are rejected.
// An entry is its name and its category: the platform derives its standard id from them, without the case of the name.
export const vocabularyImportSchema = z.strictObject({
  name: z.string().trim().min(1, 'Vocabulary name is required'),
  // A category this platform does not know (a bundle of a newer platform) is refused
  category: z.enum(VocabularyCategory),
  // Absent or null: a new entry is given its default, and an existing one is left untouched
  description: z.string().nullable().optional(),
  // Replaced as a whole on an existing entry, an empty list included
  aliases: z.array(z.string()).nullable().optional(),
  order: z.number().int().nullable().optional(),
});

export type VocabularyImportConfiguration = z.infer<typeof vocabularyImportSchema>;

// An entry of a category: the category is the one of the file
export const vocabularyEntryImportSchema = vocabularyImportSchema.omit({ category: true });

// The entries of one category to import: what a configuration preset holds of a category
export const vocabularyCategoryImportSchema = z.strictObject({
  category: z.enum(VocabularyCategory),
  entries: z.array(vocabularyEntryImportSchema).min(1, 'At least one vocabulary entry is required'),
}).refine(
  ({ entries }) => new Set(entries.map(({ name }) => normalizeName(name))).size === entries.length,
  { path: ['entries'], message: 'A vocabulary entry is listed twice' },
);

export type VocabularyCategoryImportConfiguration = z.infer<typeof vocabularyCategoryImportSchema>;
