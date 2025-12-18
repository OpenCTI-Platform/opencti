import type { AuthContext, AuthUser } from '../../types/user';
import { retrieveMigration } from '../../database/migration';
import { logApp } from '../../config/conf';
import { isBypassUser, SYSTEM_USER } from '../../utils/access';
import { ForbiddenAccess, FunctionalError } from '../../config/errors';
import { createEntity, createRelation, loadEntity } from '../../database/middleware';
import { ENTITY_TYPE_MIGRATION_REFERENCE, ENTITY_TYPE_MIGRATION_STATUS } from '../../schema/internalObject';
import { RELATION_MIGRATES } from '../../schema/internalRelationship';

export const runMigration = async (context: AuthContext, user: AuthUser, migrationFileName: string) => {
  if (!isBypassUser(user)) {
    throw ForbiddenAccess();
  }
  // 01. Run the migration
  const migration = await retrieveMigration(migrationFileName);
  try {
    migration.up(() => {});
  } catch (migrationError) {
    logApp.error(`[MIGRATION] Migration ${migrationFileName} up error`, { cause: migrationError });
    throw FunctionalError('Error running migration', { cause: migrationError });
  }
  logApp.info(`[MIGRATION] Migration ${migrationFileName} successfully run`);

  // 02. Indicate the migration is run
  const migrationStatus = await loadEntity(context, SYSTEM_USER, [ENTITY_TYPE_MIGRATION_STATUS]);
  // Crete the migration reference
  const migrationRefInput = { title: migration.title, timestamp: migration.timestamp };
  const migrationRef = await createEntity(context, SYSTEM_USER, migrationRefInput, ENTITY_TYPE_MIGRATION_REFERENCE);
  // Attach the reference to the migration status
  const migrationRel = { fromId: migrationStatus?.id, toId: migrationRef.id, relationship_type: RELATION_MIGRATES };
  await createRelation(context, SYSTEM_USER, migrationRel);
  logApp.info(`[MIGRATION] Migration ${migrationFileName} saved`);

  return true;
};
