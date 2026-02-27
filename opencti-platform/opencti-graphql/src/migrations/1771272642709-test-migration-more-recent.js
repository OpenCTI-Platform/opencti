import { logApp } from '../config/conf';
import { cleanInconsistentRelations } from '../utils/clean-relations';
import { executionContext } from '../utils/access';

export const up = async (next) => {
  const context = executionContext('migration');
  // Fix missing deleted data
  // In case of relation to relation, some deletion was not executed.
  // For each relations of the platform we need to check if the from and the to are available.
  logApp.info('[MIGRATION] Starting migration to fix missing deletion');
  await cleanInconsistentRelations(context);
  logApp.info('[MIGRATION] Fix missing deletion migration done');
  next();
};

export const down = async (next) => {
  // Nothing to do.
  next();
};
