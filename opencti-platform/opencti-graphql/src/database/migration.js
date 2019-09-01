import uuid from 'uuid/v4';
import { isNil, isEmpty, head, map, filter } from 'ramda';
import migrate from 'migrate';
import { queryOne, queryMultiple, write } from './grakn';
import { logger } from '../config/conf';
import { elasticIsAlive } from './elasticSearch';

// noinspection JSUnusedGlobalSymbols
const graknStateStorage = {
  async load(fn) {
    // Check if ES is alive
    await elasticIsAlive();
    // Get current status of migrations in Grakn
    const result = await queryMultiple(
      `match $x isa MigrationStatus; 
      (status:$x, state:$y); 
      get;`,
      ['x', 'y']
    );
    if (isEmpty(result)) {
      logger.info(
        'Cannot read migrations from database. If this is the first time you run migrations, then this is normal.'
      );
      return fn(null, {});
    }
    const migrationStatus = {
      lastRun: head(result).x.lastRun,
      migrations: map(
        record => ({
          title: record.y.title,
          timestamp: record.y.timestamp
        }),
        result
      )
    };
    return fn(null, migrationStatus);
  },
  async save(set, fn) {
    logger.info('OpenCTI Migration: Saving current configuration');
    // Get current done migration
    const mig = head(filter(m => m.title === set.lastRun, set.migrations));

    // Get the MigrationStatus. If exist, update last run, if not create it
    const migrationStatus = await queryOne(
      `match $x isa MigrationStatus; get;`,
      ['x']
    );
    if (!isNil(migrationStatus)) {
      await write(
        `match $x isa MigrationStatus, 
        has lastRun $run; 
        delete $run;`
      );
      await write(
        `match $x isa MigrationStatus; 
        insert $x has lastRun "${set.lastRun}";`
      );
    } else {
      await write(
        `insert $x isa MigrationStatus,
        has internal_id "${uuid()}",
        has lastRun "${set.lastRun}";`
      );
    }
    await write(
      `insert $x isa MigrationReference,
      has internal_id "${uuid()}",
      has title "${mig.title}",
      has timestamp ${mig.timestamp};`
    );
    await write(
      `match $status isa MigrationStatus; 
      $ref isa MigrationReference, has title "${mig.title}"; 
      insert (status: $status, state: $ref) isa migrate, has internal_id "${uuid()}";`
    );
    fn();
  }
};

migrate.load({ stateStore: graknStateStorage }, (err, set) => {
  if (err) {
    throw err;
  }
  logger.info('Migration state successfully updated, starting migrations');
  set.up(err2 => {
    if (err2) {
      throw err2;
    }
    logger.info('Migrations successfully ran');
    process.exit(0);
  });
});
