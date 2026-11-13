import { logMigration } from '../config/conf';
import { VocabularyCategory } from '../generated/graphql';
import { addVocabulary } from '../modules/vocabulary/vocabulary-domain';
import { openVocabularies } from '../modules/vocabulary/vocabulary-utils';
import { executionContext, SYSTEM_USER } from '../utils/access';

const message = '[MIGRATION] Add hunting to the incident type open vocabulary';
// The incident type of the incidents hunts open (hunt-incident HUNT_INCIDENT_TYPE)
const HUNT_INCIDENT_TYPE = 'hunting';

export const up = async (next: (error?: Error) => void) => {
  const startTime = Date.now();
  logMigration.info(`${message} > started`);
  const context = executionContext('migration');
  const definition = (openVocabularies.incident_type_ov ?? []).find((vocabulary) => vocabulary.key === HUNT_INCIDENT_TYPE);
  // The vocabulary standard id derives from its name and category: creating it again is an upsert
  await addVocabulary(context, SYSTEM_USER, {
    name: HUNT_INCIDENT_TYPE,
    description: definition?.description ?? 'Found by a threat hunt.',
    category: VocabularyCategory.IncidentTypeOv,
  });
  logMigration.info(`${message} > done in ${Date.now() - startTime} ms`);
  next();
};

export const down = async (next: (error?: Error) => void) => {
  next();
};
