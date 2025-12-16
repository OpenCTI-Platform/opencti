import type { AuthContext, AuthUser } from '../../types/user';
import { retrieveMigration } from '../../database/migration';
import { logApp, logMigration } from '../../config/conf';
import { MigrationSet } from 'migrate';

export const runMigration = async (context: AuthContext, user: AuthUser, migrationFileName: string) => {
  const migration = await retrieveMigration(migrationFileName);
  const migrationSet = new MigrationSet(migration);
  migrationSet.up((migrationError) => {
    if (migrationError) {
      logApp.error(`[MIGRATION] Migration ${migrationFileName} up error`, { cause: migrationError });
      return 'ERROR';
    }
    logMigration.info(`[MIGRATION] Migration ${migrationFileName} successfully run`);
    return 'DONE';
  });
};
