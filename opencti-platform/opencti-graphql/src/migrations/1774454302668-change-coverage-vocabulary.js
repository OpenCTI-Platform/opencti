import { executionContext, SYSTEM_USER } from '../utils/access';
import { logMigration } from '../config/conf';
import { editVocabulary, findById } from '../modules/vocabulary/vocabulary-domain';

const message = '[MIGRATION] Rename coverage_ov vulnerabilities to vulnerability in vocabulary';
export const up = async (next) => {
  logMigration.info(`${message} > started`);
  const context = executionContext('migration');
  const elementToChange = await findById(context, SYSTEM_USER, 'vocabulary--836e90eb-4d7e-5747-88ef-1405dba8d471'); // 'vulnerabitilies' vocabulary id
  if (elementToChange) {
    const input = [
      {
        key: 'name',
        value: ['vulnerability'],
      },
      {
        key: 'description',
        value: ['Vulnerability'],
      },
    ];
    await editVocabulary(context, SYSTEM_USER, elementToChange.id, input);
    logMigration.info(`${message} > changing 'vulnerabilities' to 'vulnerability'.`);
  }
  logMigration.info(`${message} > done.`);
  next();
};

export const down = async (next) => {
  next();
};
