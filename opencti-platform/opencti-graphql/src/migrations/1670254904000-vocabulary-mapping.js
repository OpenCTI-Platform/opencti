import { elAttributeValues } from '../database/engine';
import { executionContext, SYSTEM_USER } from '../utils/access';
import { addVocabulary } from '../modules/vocabulary/vocabulary-domain';
import { VocabularyCategory } from '../generated/graphql';
import { builtInOv, openVocabularies } from '../modules/vocabulary/vocabulary-utils';

export const up = async (next) => {
  const context = executionContext('migration');
  const categories = Object.values(VocabularyCategory);
  for (let index = 0; index < categories.length; index += 1) {
    const category = categories[index];
    const vocabularies = openVocabularies[category] ?? [];
    for (let i = 0; i < vocabularies.length; i += 1) {
      const { key, description } = vocabularies[i];
      const data = { name: key, description, category, builtIn: builtInOv.includes(category) };
      await addVocabulary(context, SYSTEM_USER, data);
    }
    const { edges } = await elAttributeValues(context, SYSTEM_USER, category);
    const keys = edges.map(({ node: { value } }) => value);
    for (let j = 0; index < keys.length; j += 1) {
      const name = keys[j];
      await addVocabulary(context, SYSTEM_USER, { name, category });
    }
  }
  next();
};

export const down = async (next) => {
  next();
};
