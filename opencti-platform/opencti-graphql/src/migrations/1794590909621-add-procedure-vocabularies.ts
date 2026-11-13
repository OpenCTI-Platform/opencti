import { logMigration } from '../config/conf';
import { VocabularyCategory } from '../generated/graphql';
import { addVocabulary } from '../modules/vocabulary/vocabulary-domain';
import { builtInOv, openVocabularies } from '../modules/vocabulary/vocabulary-utils';
import { executionContext, SYSTEM_USER } from '../utils/access';

const message = '[MIGRATION] Vocabulary add procedure platforms';

// New platforms_ov keys introduced with the Procedure entity (procedure_type_ov starts empty)
const PROCEDURE_PLATFORM_KEYS = ['network', 'cloud', 'ics', 'containers', 'saas', 'office suite', 'identity provider', 'google workspace', 'azure ad', 'mobile'];

export const up = async (next: () => void) => {
  const startTime = Date.now();
  logMigration.info(`${message} > started`);
  const context = executionContext('migration');
  const category = VocabularyCategory.PlatformsOv;
  const vocabularies = (openVocabularies[category] ?? []).filter(({ key }) => PROCEDURE_PLATFORM_KEYS.includes(key));
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
  logMigration.info(`${message} > done in ${Date.now() - startTime} ms. ${vocabularies.length} vocabularies added.`);
  next();
};

export const down = async (next: () => void) => {
  next();
};
