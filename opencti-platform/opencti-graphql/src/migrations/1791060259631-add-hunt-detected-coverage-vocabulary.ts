import { logMigration } from '../config/conf';
import { VocabularyCategory } from '../generated/graphql';
import { addVocabulary } from '../modules/vocabulary/vocabulary-domain';
import { openVocabularies } from '../modules/vocabulary/vocabulary-utils';
import { HUNT_DETECTED_COVERAGE } from '../modules/hunt/hunt-coverage-utils';
import { executionContext, SYSTEM_USER } from '../utils/access';

const message = '[MIGRATION] Add hunt_detected to the coverage open vocabulary';

export const up = async (next: (error?: Error) => void) => {
  const startTime = Date.now();
  logMigration.info(`${message} > started`);
  const context = executionContext('migration');
  const definition = (openVocabularies.coverage_ov ?? []).find((vocabulary) => vocabulary.key === HUNT_DETECTED_COVERAGE);
  // The vocabulary standard id derives from its name and category: creating it again is an upsert
  await addVocabulary(context, SYSTEM_USER, {
    name: HUNT_DETECTED_COVERAGE,
    description: definition?.description ?? 'Hunt detection',
    category: VocabularyCategory.CoverageOv,
    order: definition?.order ?? 4,
  });
  logMigration.info(`${message} > done in ${Date.now() - startTime} ms`);
  next();
};

export const down = async (next: (error?: Error) => void) => {
  next();
};
