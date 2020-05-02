import { v4 as uuid } from 'uuid';
import { filter, head, last, map } from 'ramda';
import { MigrationSet } from 'migrate';
import Migration from 'migrate/lib/migration';
import { executeWrite, find, load, internalDirectWrite } from './grakn';
import { logger } from '../config/conf';

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
      return { title, up: migration.up, down: migration.down };
    });
};

const graknStateStorage = {
  async load(fn) {
    // Get current status of migrations in Grakn
    const migration = await load(`match $status isa MigrationStatus; get;`, ['status'], { noCache: true });
    if (!migration) {
      // If no migration found, initialize
      logger.info('[MIGRATION] > Fresh platform detected, creating migration structure');
      const lastExistingMigration = last(retrieveMigrations());
      const [time] = lastExistingMigration.title.split('-');
      const lastRunInit = `${parseInt(time, 10) + 1}-init`;
      await internalDirectWrite(
        `insert $x isa MigrationStatus, has lastRun "${lastRunInit}", has internal_id_key "${uuid()}";`
      );
      return fn(null, { lastRun: lastRunInit, migrations: [] });
    }
    // If migrations found, convert to current status
    const migrations = await find(
      `match $from isa MigrationStatus; $rel(status:$from, state:$to) isa migrate; get;`,
      ['from', 'to'],
      { noCache: true }
    );
    logger.info(`[MIGRATION] > Read ${migrations.length} migrations from the database`);
    const migrationStatus = {
      lastRun: migration.status.lastRun,
      migrations: map(
        (record) => ({
          title: record.to.title,
          timestamp: record.to.timestamp,
        }),
        migrations
      ),
    };
    return fn(null, migrationStatus);
  },
  async save(set, fn) {
    try {
      await executeWrite(async (wTx) => {
        // Get current done migration
        const mig = head(filter((m) => m.title === set.lastRun, set.migrations));
        // We have only one instance of migration status.
        const q1 = `match $x isa MigrationStatus, has lastRun $run; delete $run;`;
        logger.debug(`[MIGRATION] step 1`, { query: q1 });
        await wTx.tx.query(q1);
        const q2 = `match $x isa MigrationStatus; insert $x has lastRun "${set.lastRun}";`;
        logger.debug(`[MIGRATION] step 2`, { query: q2 });
        await wTx.tx.query(q2);
        // Insert the migration reference
        const q3 = `insert $x isa MigrationReference,
          has internal_id_key "${uuid()}",
          has title "${mig.title}",
          has timestamp ${mig.timestamp};`;
        logger.debug(`[MIGRATION] step 3`, { query: q3 });
        // Attach the reference to the migration status.
        await wTx.tx.query(q3);
        // Attach the reference to the migration status.
        const q4 = `match $status isa MigrationStatus; 
          $ref isa MigrationReference, has title "${mig.title}"; 
          insert (status: $status, state: $ref) isa migrate, has internal_id_key "${uuid()}";`;
        logger.debug(`[MIGRATION] step 4`, { query: q4 });
        await wTx.tx.query(q4);
        logger.info(`[MIGRATION] > Saving current configuration, ${mig.title}`);
      });
      return fn();
    } catch (err) {
      logger.error('[MIGRATION] > Error saving the migration state');
      return fn();
    }
  },
};

const applyMigration = () => {
  const set = new MigrationSet(graknStateStorage);
  return new Promise((resolve, reject) => {
    graknStateStorage.load((err, state) => {
      if (err) throw new Error(err);
      // Set last run date on the set
      set.lastRun = state.lastRun;
      // Read migrations from webpack
      const filesMigrationSet = retrieveMigrations();
      // Filter migration to apply. Should be > lastRun
      const [platformTime] = state.lastRun.split('-');
      const platformDate = new Date(parseInt(platformTime, 10));
      const migrationToApply = filter((file) => {
        const [time] = file.title.split('-');
        const fileDate = new Date(parseInt(time, 10));
        return fileDate > platformDate;
      }, filesMigrationSet);
      const alreadyAppliedMigrations = new Map(state.migrations ? state.migrations.map((i) => [i.title, i]) : null);
      /** Match the files migrations to the database migrations.
       Plays migrations that doesnt have matching name / timestamp */
      if (migrationToApply.length > 0) {
        logger.info(`[MIGRATION] > ${migrationToApply.length} migrations will be executed`);
      }
      for (let index = 0; index < migrationToApply.length; index += 1) {
        const migSet = migrationToApply[index];
        const migration = new Migration(migSet.title, migSet.up, migSet.down);
        const stateMigration = alreadyAppliedMigrations.get(migration.title);
        if (stateMigration) {
          logger.info(`[MIGRATION] > Replaying migration ${migration.title}`);
        }
        set.addMigration(migration);
      }
      // Start the set migration
      set.up((migrationError) => {
        if (migrationError) {
          logger.error('[GRAKN] Error during migration');
          reject(migrationError);
        }
        logger.info('[MIGRATION] > Migration process completed, platform is up to date');
        resolve();
      });
    });
  });
};

export default applyMigration;
