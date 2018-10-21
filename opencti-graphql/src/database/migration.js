import { head, isEmpty, dissoc, map, flatten, compose } from 'ramda';
import migrate from 'migrate';
import driver from './index';
import { logger } from '../config/conf';

// noinspection JSUnusedGlobalSymbols
const neo4jStateStorage = {
  async load(fn) {
    const session = driver.session();
    const promise = session.run(
      'MATCH config=(:Migration)-[r:PART_OF]->(:Configuration) RETURN config'
    );
    promise.then(data => {
      if (isEmpty(data.records)) {
        logger.info(
          'Cannot read migrations from database. If this is the first time you run migrations, then this is normal.'
        );
        return fn(null, {});
      }
      // Extract the config (end) node
      const migrationStatus = {
        lastRun: head(data.records).get('config').end.properties.lastRun,
        migrations: map(
          record => record.get('config').start.properties,
          data.records
        )
      };
      session.close();
      return fn(null, migrationStatus);
    });
  },
  async save(set, fn) {
    logger.info('OpenCTI Migration: Saving current configuration');
    const migrations = map(
      migration =>
        compose(
          dissoc('up'),
          dissoc('down'),
          dissoc('description')
        )(migration),
      set.migrations
    );
    const session = driver.session();
    await session.run(
      'MERGE (c:Configuration { name: "migration" }) ON MATCH SET c.lastRun = {lastRun}',
      { lastRun: set.lastRun }
    );

    const migrationExecutions = compose(
      map(migration => {
        const migrationCreation = session.run(
          'MERGE (migration:Migration { title: {title} }) ON MATCH SET migration.timestamp = {timestamp}',
          { title: migration.title, timestamp: migration.timestamp }
        );
        const migrationRelation = session.run(
          'MATCH (c:Configuration {name:"migration"}), (m:Migration {title: {title}}) MERGE (m)-[r:PART_OF]-(c)',
          { title: migration.title, timestamp: migration.timestamp }
        );
        return [migrationCreation, migrationRelation];
      }),
      flatten
    )(migrations);
    Promise.all(migrationExecutions).then(() => {
      session.close();
      return fn();
    });
  }
};

migrate.load(
  {
    stateStore: neo4jStateStorage
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
      driver.close();
      logger.info('Migrations successfully ran');
    });
  }
);
