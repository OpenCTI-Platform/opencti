import { executionContext, SYSTEM_USER } from '../utils/access';
import { logApp } from '../config/conf';
import { VocabularyCategory } from '../generated/graphql';
import { builtInOv, openVocabularies } from '../modules/vocabulary/vocabulary-utils';
import { addVocabulary } from '../modules/vocabulary/vocabulary-domain';

const message = '[MIGRATION] Vocabulary add PersonaTypeOv';
export const up = async (next) => {
  logApp.info(`${message} > started`);
  const context = executionContext('migration');
  const category = VocabularyCategory.PersonaTypeOv;
  const vocabularies = openVocabularies[category] ?? [];
  for (let i = 0; i < vocabularies.length; i += 1) {
    const { key, description } = vocabularies[i];
    const data = {
      name: key,
      description: description ?? '',
      category,
      builtIn: builtInOv.includes(category),
    };
    await addVocabulary(context, SYSTEM_USER, data);
  }
  logApp.info(`${message} > done. ${vocabularies.length} vocabularies added.`);
  next();
};

export const down = async (next) => {
  next();
};
