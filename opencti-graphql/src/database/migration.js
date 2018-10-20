import {driver} from '../database/index';
import {head, isEmpty, dissoc, map, compose} from 'ramda';
import migrate from 'migrate';

// noinspection JSUnusedGlobalSymbols
const neo4jStateStorage = {
    load: async function (fn) {
        let session = driver.session();
        let promise = session.run('MATCH config=(:Migration)-[r:PART_OF]->(:Configuration) RETURN config');
        promise.then((data) => {
            if (isEmpty(data.records)) {
                console.log('Cannot read migrations from database. If this is the first time you run migrations, then this is normal.');
                return fn(null, {})
            }
            //Extract the config (end) node
            const migrationStatus = {
                lastRun: head(data.records).get('config').end.properties.lastRun,
                migrations: map((record) => record.get('config').start.properties, data.records)
            };
            session.close();
            fn(null, migrationStatus);
        });
    },
    save: async function (set, fn) {
        console.log('OpenCTI Migration: Saving current configuration');
        const migrations = map(
            migration => compose(dissoc('up'), dissoc('down'), dissoc('description'))(migration),
            set.migrations
        );
        let session = driver.session();
        await session.run('MERGE (c:Configuration { name: "migration" }) ON MATCH SET c.lastRun = {lastRun}', {lastRun: set.lastRun});
        for(const migration of migrations) {
            await session.run('MERGE (migration:Migration { title: {title} }) ON MATCH SET migration.timestamp = {timestamp}',
                {title: migration.title, timestamp: migration.timestamp});
            await session.run('MATCH (c:Configuration {name:"migration"}), (m:Migration {title: {title}}) MERGE (m)-[r:PART_OF]-(c)',
                {title: migration.title, timestamp: migration.timestamp});
        }
        session.close();
        return fn();
    }
};

migrate.load({
    stateStore: neo4jStateStorage
}, function (err, set) {
    if (err) {
        throw err
    }
    console.log('Migration state successfully updated, starting migrations');
    set.up((err2) => {
        if (err2) {
            throw err2
        }
        driver.close();
        console.log('Migrations successfully ran');
    })
});