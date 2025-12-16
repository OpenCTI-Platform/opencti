import type { AuthContext, AuthUser } from '../../types/user';
import { retrieveMigration } from '../../database/migration';

export const runMigration = async (context: AuthContext, user: AuthUser, migrationName: string) => {
  const migration = await retrieveMigration(migrationName);
  console.log('migration', migration);
  return 'DONE';
};
