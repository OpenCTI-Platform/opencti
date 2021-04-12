import * as R from 'ramda';
import { MigrationSet } from 'migrate';
import Migration from 'migrate/lib/migration';
import { logApp } from '../config/conf';
import { DatabaseError } from '../config/errors';
import { RELATION_MIGRATES } from '../schema/internalRelationship';
import { ENTITY_TYPE_MIGRATION_REFERENCE, ENTITY_TYPE_MIGRATION_STATUS } from '../schema/internalObject';
import { createEntity, createRelation, listThroughGetTo, loadEntity, patchAttribute } from './middleware';
import { SYSTEM_USER } from '../domain/user';

const normalizeMigrationName = (rawName) => {
  if (rawName.startsWith('./')) {
    return rawName.substring(2);
  }
  return rawName;
};

const retrieveMigrations = () => {
  const webpackMigrationsContext = require.context('../migrations', false, /.js$/);
  return webpackMigrationsContext
    .keys()
    .sort()
    .map((name) => {
      const title = normalizeMigrationName(name);
      const migration = webpackMigrationsContext(name);
      const [time] = title.split('-');
      const timestamp = parseInt(time, 10);
      return { title, up: migration.up, down: migration.down, timestamp };
    });
};

export const lastAvailableMigrationTime = () => {
  const migrations = retrieveMigrations();
  const lastMigration = R.last(migrations);
  return lastMigration && lastMigration.timestamp;
};

const migrationStorage = {
  async load(fn) {
    // Get current status of migrations
    const migration = await loadEntity(SYSTEM_USER, [ENTITY_TYPE_MIGRATION_STATUS]);
    const migrationId = migration.internal_id;
    const migrations = await listThroughGetTo(
      SYSTEM_USER,
      migrationId,
      RELATION_MIGRATES,
      ENTITY_TYPE_MIGRATION_REFERENCE
    );
    logApp.info(`[MIGRATION] Read ${migrations.length} migrations from the database`);
    const migrationStatus = {
      lastRun: migration.lastRun,
      migrations: R.map(
        (record) => ({
          title: record.title,
          timestamp: record.timestamp,
        }),
        migrations
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
      logApp.error('[MIGRATION] Error saving the migration state');
      return fn();
    }
  },
};

const applyMigration = () => {
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
        logApp.info(`[MIGRATION] Platform already up to date, nothing to migrate`);
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
          logApp.error('[MIGRATION] Error during migration');
          reject(migrationError);
          return;
        }
        logApp.info('[MIGRATION] Migration process completed');
        resolve();
      });
    });
  });
};

export default applyMigration;
