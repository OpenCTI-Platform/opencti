import type { AuthUser } from '../../types/user';
import { retrieveMigration } from '../../database/migration';
import { logApp, logMigration } from '../../config/conf';
import { MigrationSet } from 'migrate';
import { isBypassUser } from '../../utils/access';
import { ForbiddenAccess, FunctionalError } from '../../config/errors';

export const runMigration = async (user: AuthUser, migrationFileName: string) => {
  if (!isBypassUser(user)) {
    throw ForbiddenAccess();
  }
  const migration = await retrieveMigration(migrationFileName);
  const migrationSet = new MigrationSet(migration);
  migrationSet.up((migrationError) => {
    if (migrationError) {
      logApp.error(`[MIGRATION] Migration ${migrationFileName} up error`, { cause: migrationError });
      throw FunctionalError('Error running migration', { cause: migrationError });
    }
    logMigration.info(`[MIGRATION] Migration ${migrationFileName} successfully run`);
  });
  return true;
};
