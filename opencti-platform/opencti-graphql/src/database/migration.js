import * as R from 'ramda';
import { MigrationSet } from 'migrate';
import Migration from 'migrate/lib/migration';
import { logApp, PLATFORM_VERSION } from '../config/conf';
import { DatabaseError } from '../config/errors';
import { RELATION_MIGRATES } from '../schema/internalRelationship';
import { ENTITY_TYPE_MIGRATION_REFERENCE, ENTITY_TYPE_MIGRATION_STATUS } from '../schema/internalObject';
import { createEntity, createRelation, listThroughGetTo, loadEntity, patchAttribute } from './middleware';
import { SYSTEM_USER } from '../utils/access';
// eslint-disable-next-line import/extensions,import/no-unresolved
import migrations, { filenames as migrationsFilenames } from '../migrations/*.js';

const normalizeMigrationName = (rawName) => {
  if (rawName.startsWith('./')) {
    return rawName.substring(2);
  }
  return rawName;
};

const retrieveMigrations = () => {
  const knexMigrations = migrations.map((migration, i) => ({
    name: migrationsFilenames[i].substring('../migrations/'.length),
    migration,
  }));
  return knexMigrations.map(({ name, migration }) => {
    const title = normalizeMigrationName(name);
    const [time] = title.split('-');
    const timestamp = parseInt(time, 10);
    return { title, up: migration.up, down: migration.down, timestamp };
  });
};

export const lastAvailableMigrationTime = () => {
  const allMigrations = retrieveMigrations();
  const lastMigration = R.last(allMigrations);
  return lastMigration && lastMigration.timestamp;
};

const migrationStorage = {
  async load(fn) {
    // Get current status of migrations
    const migration = await loadEntity(SYSTEM_USER, [ENTITY_TYPE_MIGRATION_STATUS]);
    const migrationId = migration.internal_id;
    const dbMigrations = await listThroughGetTo(
      SYSTEM_USER,
      migrationId,
      RELATION_MIGRATES,
      ENTITY_TYPE_MIGRATION_REFERENCE
    );
    logApp.info(`[MIGRATION] Read ${dbMigrations.length} migrations from the database`);
    const migrationStatus = {
      lastRun: migration.lastRun,
      internal_id: migration.internal_id,
      platformVersion: migration.platformVersion,
      migrations: R.map(
        (record) => ({
          title: record.title,
          timestamp: record.timestamp,
        }),
        dbMigrations
      ),
    };
    return fn(null, migrationStatus);
  },
  async save(set, fn) {
    try {
      // Get current done migration
      const mig = R.head(R.filter((m) => m.title === set.lastRun, set.migrations));
      // Update the reference status to the last run
      const migrationStatus = await loadEntity(SYSTEM_USER, [ENTITY_TYPE_MIGRATION_STATUS]);
      const statusPatch = { lastRun: set.lastRun };
      await patchAttribute(SYSTEM_USER, migrationStatus.internal_id, ENTITY_TYPE_MIGRATION_STATUS, statusPatch);
      // Insert the migration reference
      const migrationRefInput = { title: mig.title, timestamp: mig.timestamp };
      const migrationRef = await createEntity(SYSTEM_USER, migrationRefInput, ENTITY_TYPE_MIGRATION_REFERENCE);
      // Attach the reference to the migration status.
      const migrationRel = { fromId: migrationStatus.id, toId: migrationRef.id, relationship_type: RELATION_MIGRATES };
      await createRelation(SYSTEM_USER, migrationRel);
      logApp.info(`[MIGRATION] Saving current configuration, ${mig.title}`);
      return fn();
    } catch (err) {
      logApp.error('[MIGRATION] Error saving the migration state', { error: err });
      return fn();
    }
  },
};

export const applyMigration = () => {
  const set = new MigrationSet(migrationStorage);
  return new Promise((resolve, reject) => {
    migrationStorage.load((err, state) => {
      if (err) throw DatabaseError('[MIGRATION] Error applying migration', err);
      // Set last run date on the set
      set.lastRun = state.lastRun;
      // Read migrations from webpack
      const filesMigrationSet = retrieveMigrations();
      // Filter migration to apply. Should be > lastRun
      const [lastMigrationTime] = state.lastRun.split('-');
      const lastMigrationDate = new Date(parseInt(lastMigrationTime, 10));
      const migrationToApply = R.filter((file) => new Date(file.timestamp) > lastMigrationDate, filesMigrationSet);
      const alreadyAppliedMigrations = new Map(state.migrations ? state.migrations.map((i) => [i.title, i]) : null);
      /** Match the files migrations to the database migrations.
       Plays migrations that does not have matching name / timestamp */
      if (migrationToApply.length > 0) {
        logApp.info(`[MIGRATION] ${migrationToApply.length} migrations will be executed`);
      } else {
        logApp.info('[MIGRATION] Platform already up to date, nothing to migrate');
      }
      for (let index = 0; index < migrationToApply.length; index += 1) {
        const migSet = migrationToApply[index];
        const migration = new Migration(migSet.title, migSet.up, migSet.down);
        const stateMigration = alreadyAppliedMigrations.get(migration.title);
        if (stateMigration) {
          logApp.info(`[MIGRATION] Replaying migration ${migration.title}`);
        }
        set.addMigration(migration);
      }
      // Start the set migration
      set.up((migrationError) => {
        if (migrationError) {
          logApp.error('[MIGRATION] Error during migration', { error: migrationError });
          reject(migrationError);
          return;
        }
        logApp.info('[MIGRATION] Migration process completed');
        resolve(state);
      });
    });
  }).then(async (state) => {
    // After migration, path the current version runtime
    const statusPatch = { platformVersion: PLATFORM_VERSION };
    await patchAttribute(SYSTEM_USER, state.internal_id, ENTITY_TYPE_MIGRATION_STATUS, statusPatch);
    logApp.info(`[MIGRATION] Platform version updated to ${PLATFORM_VERSION}`);
  });
};
