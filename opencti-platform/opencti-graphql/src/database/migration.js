import uuid from 'uuid/v4';
import { filter, head, isEmpty, map } from 'ramda';
import { MigrationSet } from 'migrate';
import Migration from 'migrate/lib/migration';
import { executeWrite, find, write } from './grakn';
import { logger } from '../config/conf';

const normalizeMigrationName = rawName => {
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
    .map(name => {
      const title = normalizeMigrationName(name);
      const migration = webpackMigrationsContext(name);
      return { title, up: migration.up, down: migration.down };
    });
};

const graknStateStorage = {
  async load(fn) {
    // Get current status of migrations in Grakn
    const result = await find(
      `match $from isa MigrationStatus; $rel(status:$from, state:$to) isa migrate; get;`,
      ['rel', 'from', 'to'],
      { noCache: true }
    );
    logger.info(`[MIGRATION] > Read ${result.length} from the database`);
    if (isEmpty(result)) {
      logger.info(
        '[MIGRATION] > Cannot read migrations from database. If this is the first time you run migrations,' +
          ' then this is normal.'
      );
      await write(`insert $x isa MigrationStatus, has internal_id_key "${uuid()}";`);
      return fn(null, {});
    }
    const migrationStatus = {
      lastRun: head(result).from.lastRun,
      migrations: map(
        record => ({
          title: record.to.title,
          timestamp: record.to.timestamp
        }),
        result
      )
    };
    return fn(null, migrationStatus);
  },
  async save(set, fn) {
    try {
      await executeWrite(async wTx => {
        // Get current done migration
        const mig = head(filter(m => m.title === set.lastRun, set.migrations));
        // We have only one instance of migration status.
        const q1 = `match $x isa MigrationStatus, has lastRun $run; delete $run;`;
        logger.debug(`[MIGRATION] > ${q1}`);
        await wTx.tx.query(q1);
        const q2 = `match $x isa MigrationStatus; insert $x has lastRun "${set.lastRun}";`;
        logger.debug(`[MIGRATION] > ${q2}`);
        await wTx.tx.query(q2);
        // Insert the migration reference
        const q3 = `insert $x isa MigrationReference,
          has internal_id_key "${uuid()}",
          has title "${mig.title}",
          has timestamp ${mig.timestamp};`;
        logger.debug(`[MIGRATION] > ${q3}`);
        // Attach the reference to the migration status.
        await wTx.tx.query(q3);
        // Attach the reference to the migration status.
        const q4 = `match $status isa MigrationStatus; 
          $ref isa MigrationReference, has title "${mig.title}"; 
          insert (status: $status, state: $ref) isa migrate, has internal_id_key "${uuid()}";`;
        logger.debug(`[MIGRATION] > ${q4}`);
        await wTx.tx.query(q4);
        logger.info(`[MIGRATION] > Saving current configuration, ${mig.title}`);
      });
      return fn();
    } catch (err) {
      logger.error('[MIGRATION] > Error saving the migration state');
      return fn();
    }
  }
};

const applyMigration = () => {
  logger.info('[MIGRATION] > Starting migration process');
  const set = new MigrationSet(graknStateStorage);
  return new Promise((resolve, reject) => {
    graknStateStorage.load((err, state) => {
      if (err) throw new Error(err);
      // Set last run date on the set
      set.lastRun = state.lastRun || null;
      // Read migrations from webpack
      const migrationSet = retrieveMigrations();
      const stateMigrations = new Map(state.migrations ? state.migrations.map(i => [i.title, i]) : null);
      for (let index = 0; index < migrationSet.length; index += 1) {
        const migSet = migrationSet[index];
        const migration = new Migration(migSet.title, migSet.up, migSet.down);
        // Add timestamp if already done in remote state
        const stateMigration = stateMigrations.get(migration.title);
        if (stateMigration) {
          migration.timestamp = stateMigration.timestamp;
        } else {
          logger.info(`[MIGRATION] > ${migSet.title} will be executed`);
        }
        set.addMigration(migration);
      }
      // Start the set migration
      set.up(migrationError => {
        if (migrationError) {
          logger.error('[GRAKN] Error during migration');
          reject(migrationError);
        }
        logger.info('[MIGRATION] > Migrations completed');
        resolve();
      });
    });
  });
};

export default applyMigration;
