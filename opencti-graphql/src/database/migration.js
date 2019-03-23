import { head, isEmpty, map, filter } from 'ramda';
import migrate from 'migrate';
import { qk, write, getSimpleObject } from './grakn';
import { logger } from '../config/conf';

// noinspection JSUnusedGlobalSymbols
const graknStateStorage = {
  async load(fn) {
    const promise = qk(
      `match $x isa MigrationStatus has lastRun $lastRun; 
          (status:$x, state:$y); 
          $y has title $title; 
          $y has timestamp $timestamp; 
          get;`
    );
    promise.then(result => {
      const { data } = result;
      if (isEmpty(data)) {
        logger.info(
          'Cannot read migrations from database. If this is the first time you run migrations, then this is normal.'
        );
        return fn(null, {});
      }

      // Extract the config (end) node
      const migrationStatus = {
        lastRun: head(data).lastRun.value,
        migrations: map(
          record => ({
            title: record.title.value,
            timestamp: record.timestamp.value
          }),
          data
        )
      };
      return fn(null, migrationStatus);
    });
  },
  async save(set, fn) {
    logger.info('OpenCTI Migration: Saving current configuration');
    // Get current done migration
    const mig = head(filter(m => m.title === set.lastRun, set.migrations));

    // Get the MigrationStatus. If exist, update last run, if not create it
    const migrationStatus = await getSimpleObject(
      `match $x isa MigrationStatus; get;`
    );
    if (migrationStatus !== undefined) {
      await write(
        `match $x isa MigrationStatus has lastRun $run; delete $run;`
      );
      await write(
        `match $x isa MigrationStatus; insert $x has lastRun "${set.lastRun}";`
      );
    } else {
      await write(
        `insert $x isa MigrationStatus has lastRun "${set.lastRun}";`
      );
    }

    await write(
      `insert $x isa MigrationReference 
              has title "${mig.title}"; 
              $x has timestamp ${mig.timestamp};`
    );
    await write(
      `match $status isa MigrationStatus; 
              $ref isa MigrationReference has title "${mig.title}"; 
              insert (status: $status, state: $ref) isa migrate;`
    );
    fn();
  }
};

migrate.load(
  {
    stateStore: graknStateStorage
  },
  (err, set) => {
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
  }
);
