import { executionContext, SYSTEM_USER } from '../utils/access';
import { logMigration } from '../config/conf';
import { VocabularyCategory } from '../generated/graphql';
import { builtInOv } from '../modules/vocabulary/vocabulary-utils';
import { addVocabulary } from '../modules/vocabulary/vocabulary-domain';

const message = '[MIGRATION] Add nova pattern type vocabulary';
export const up = async (next) => {
  logMigration.info(`${message} > started`);
  const context = executionContext('migration');
  const category = VocabularyCategory.PatternTypeOv;
  const data = {
    name: 'nova',
    description: '',
    category,
    builtIn: builtInOv.includes(category),
  };
  await addVocabulary(context, SYSTEM_USER, data);
  logMigration.info(`${message} > done`);
  next();
};

export const down = async (next) => {
  next();
};
