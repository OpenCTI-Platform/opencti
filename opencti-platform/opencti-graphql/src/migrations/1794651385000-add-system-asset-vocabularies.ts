import { logMigration } from '../config/conf';
import { VocabularyCategory } from '../generated/graphql';
import { addVocabulary } from '../modules/vocabulary/vocabulary-domain';
import { builtInOv, openVocabularies } from '../modules/vocabulary/vocabulary-utils';
import { executionContext, SYSTEM_USER } from '../utils/access';

const message = '[MIGRATION] Vocabulary add the System asset vocabularies';

// The asset fields of System are optional: existing Systems keep empty values, only the vocabularies are created
const categories = [
  VocabularyCategory.AssetCategoryOv,
  VocabularyCategory.AssetSubcategoryOv,
  VocabularyCategory.AssetInternetFacingOv,
  VocabularyCategory.AssetCriticalityOv,
  VocabularyCategory.AssetEnvironmentOv,
  VocabularyCategory.AssetPlatformOv,
];

export const up = async (next: () => void) => {
  logMigration.info(`${message} > started`);
  const context = executionContext('migration');
  let count = 0;
  for (let c = 0; c < categories.length; c += 1) {
    const category = categories[c];
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
      count += 1;
    }
  }
  logMigration.info(`${message} > done. ${count} vocabularies added.`);
  next();
};

export const down = async (next: () => void) => {
  next();
};
