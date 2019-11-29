import uuid from 'uuid/v4';
import { filter, head, isEmpty, map } from 'ramda';
import migrate from 'migrate';
import path from 'path';
import { executeWrite, find, write } from './grakn';
import { logger } from '../config/conf';

// noinspection JSUnusedGlobalSymbols
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
  return new Promise((resolve, reject) => {
    const migrationsDirectory = path.join(__dirname, '../migrations');
    return migrate.load({ stateStore: graknStateStorage, migrationsDirectory }, async (err, set) => {
      if (err) reject(err);
      logger.info('[MIGRATION] > Migration state successfully updated, starting migrations');
      return set.up(err2 => {
        if (err2) reject(err2);
        logger.info('[MIGRATION] > Migrations successfully ran');
        return resolve(true);
      });
    });
  });
};

export default applyMigration;
