import type { AuthContext, AuthUser } from '../../types/user';
import { retrieveMigration } from '../../database/migration';

export const runMigration = (context: AuthContext, user: AuthUser, migrationName: string) => {
  retrieveMigration(migrationName);
  return 'DONE';
};
