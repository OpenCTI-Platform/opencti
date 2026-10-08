import { logMigration } from '../config/conf';
import { VocabularyCategory } from '../generated/graphql';
import { addVocabulary } from '../modules/vocabulary/vocabulary-domain';
import { builtInOv, openVocabularies } from '../modules/vocabulary/vocabulary-utils';
import { executionContext, SYSTEM_USER } from '../utils/access';

const message = '[MIGRATION] Vocabulary add closing_reason_ov';

export const up = async (next: () => void) => {
  logMigration.info(`${message} > started`);
  const context = executionContext('migration');
  const category = VocabularyCategory.ClosingReasonOv;
  const vocabularies = openVocabularies[category] ?? [];
  for (let i = 0; i < vocabularies.length; i += 1) {
    const { key, description, order } = vocabularies[i];
    const data = {
      name: key,
      description: description ?? '',
      category,
      order,
      builtIn: builtInOv.includes(category),
    };
    await addVocabulary(context, SYSTEM_USER, data);
  }
  logMigration.info(`${message} > done. ${vocabularies.length} vocabularies added.`);
  next();
};

export const down = async (next: () => void) => {
  next();
};
