import { elAttributeValues } from '../database/engine';
import { executionContext, SYSTEM_USER } from '../utils/access';
import { addVocabulary } from '../modules/vocabulary/vocabulary-domain';
import { VocabularyCategory } from '../generated/graphql';
import { builtInOv, openVocabularies } from '../modules/vocabulary/vocabulary-utils';

export const up = async (next) => {
  const context = executionContext('migration');
  await Promise.all(Object.values(VocabularyCategory).flatMap(async (category) => {
    await Promise.all((openVocabularies[category] ?? []).map(async ({ key, description }) => {
      await addVocabulary(context, SYSTEM_USER, { category, name: key, label: description, builtIn: builtInOv.includes(category) });
    }));
    const { edges } = await elAttributeValues(context, SYSTEM_USER, category);
    const keys = edges.map(({ node: { value } }) => value);
    keys.map(async (name) => {
      await addVocabulary(context, SYSTEM_USER, { name, category });
    });
  }));
  next();
};

export const down = async (next) => {
  next();
};
