import uuid from 'uuid/v4';
import { isEmpty, head, map, filter } from 'ramda';
import migrate from 'migrate';
import path from 'path';
import { find, write } from './grakn';
import { logger } from '../config/conf';

// noinspection JSUnusedGlobalSymbols
const graknStateStorage = {
  async load(fn) {
    // Get current status of migrations in Grakn
    const result = await find(
      `match $from isa MigrationStatus; $rel(status:$from, state:$to); get;`,
      ['rel', 'from', 'to']
    );
    logger.info(`[MIGRATION] > Read ${result.length} from the database`);
    if (isEmpty(result)) {
      logger.info(
        '[MIGRATION] > Cannot read migrations from database. If this is the first time you run migrations,' +
          ' then this is normal.'
      );
      await write(
        `insert $x isa MigrationStatus, has internal_id "${uuid()}";`
      );
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
    // Get current done migration
    const mig = head(filter(m => m.title === set.lastRun, set.migrations));
    // We have only one instance of migration status.
    await write(`match $x isa MigrationStatus, has lastRun $run; delete $run;`);
    await write(
      `match $x isa MigrationStatus; insert $x has lastRun "${set.lastRun}";`
    );

    // Insert the migration reference
    await write(
      `insert $x isa MigrationReference,
      has internal_id "${uuid()}",
      has title "${mig.title}",
      has timestamp ${mig.timestamp};`
    );
    // Attach the reference to the migration status.
    await write(
      `match $status isa MigrationStatus; 
      $ref isa MigrationReference, has title "${mig.title}"; 
      insert (status: $status, state: $ref) isa migrate, has internal_id "${uuid()}";`
    );
    logger.info(`[MIGRATION] > Saving current configuration, ${mig.title}`);
    return fn();
  }
};

const applyMigration = () => {
  logger.info('[MIGRATION] > Starting migration process');
  return new Promise((resolve, reject) => {
    const migrationsDirectory = path.join(__dirname, '../migrations');
    migrate.load(
      { stateStore: graknStateStorage, migrationsDirectory },
      async (err, set) => {
        if (err) reject(err);
        logger.info(
          '[MIGRATION] > Migration state successfully updated, starting migrations'
        );
        set.up(err2 => {
          if (err2) reject(err2);
          logger.info('[MIGRATION] > Migrations successfully ran');
          resolve(true);
        });
      }
    );
  });
};

export default applyMigration;
