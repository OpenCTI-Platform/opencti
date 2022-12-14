import { executionContext, SYSTEM_USER } from '../utils/access';
import { addVocabulary } from '../modules/vocabulary/vocabulary-domain';
import { VocabularyCategory } from '../generated/graphql';
import { builtInOv, openVocabularies } from '../modules/vocabulary/vocabulary-utils';

export const up = async (next) => {
  const context = executionContext('migration');
  const category = VocabularyCategory.NoteTypesOv;
  const vocabularies = openVocabularies[category] ?? [];
  for (let i = 0; i < vocabularies.length; i += 1) {
    const { key, description } = vocabularies[i];
    const data = { name: key, description, category, builtIn: builtInOv.includes(category) };
    await addVocabulary(context, SYSTEM_USER, data);
  }
  next();
};

export const down = async (next) => {
  next();
};
