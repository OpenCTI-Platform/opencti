import { executionContext, SYSTEM_USER } from '../utils/access';
import { logMigration } from '../config/conf';
import { VocabularyCategory } from '../generated/graphql';
import { builtInOv, openVocabularies } from '../modules/vocabulary/vocabulary-utils';
import { addVocabulary } from '../modules/vocabulary/vocabulary-domain';

const message = '[MIGRATION] Add defense matrix vocabularies (detection rule pattern types, defense validation grouping context)';

const NEW_VOCABULARIES: Array<{ category: VocabularyCategory; keys: string[] }> = [
  { category: VocabularyCategory.PatternTypeOv, keys: ['kql', 'esql', 'kuery', 'lucene', 'yara-l', 'crowdstrike-ioa', 'elastic-rule', 'sentinel-rule', 'splunk-rule'] },
  { category: VocabularyCategory.GroupingContextOv, keys: ['defense-validation'] },
];

export const up = async (next: (error?: Error) => void) => {
  const start = Date.now();
  logMigration.info(`${message} > started`);
  const context = executionContext('migration');
  let added = 0;
  for (let index = 0; index < NEW_VOCABULARIES.length; index += 1) {
    const { category, keys } = NEW_VOCABULARIES[index];
    const definitions = openVocabularies[category] ?? [];
    for (let keyIndex = 0; keyIndex < keys.length; keyIndex += 1) {
      const key = keys[keyIndex];
      const definition = definitions.find((d) => d.key === key);
      // addVocabulary upserts on the vocabulary identifier (name + category), so the migration is idempotent
      const vocabulary = {
        name: key,
        description: definition?.description ?? '',
        category,
        builtIn: builtInOv.includes(category),
      };
      await addVocabulary(context, SYSTEM_USER, vocabulary);
      added += 1;
      logMigration.info(`${message} > ${category} ${key} (${added})`);
    }
  }
  logMigration.info(`${message} > done (${added} vocabularies) in ${Date.now() - start} ms`);
  next();
};

export const down = async (next: (error?: Error) => void) => {
  next();
};
