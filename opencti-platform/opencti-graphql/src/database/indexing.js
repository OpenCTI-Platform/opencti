import { flatten, map, pipe, uniqBy } from 'ramda';
import { Promise } from 'bluebird';
import moment from 'moment';
import { find, getSingleValueNumber, indexElements } from './grakn';
import { elCreateIndexes, elDeleteIndexes } from './elasticSearch';

const GROUP_NUMBER = 200; // Pagination size for query
const GROUP_CONCURRENCY = 10; // Number of query in //
const GROUP_INDEX_MAX_RETRY = 5; // Number of index update retry (Useful for relations impacts update)

// eslint-disable-next-line no-extend-native
const pad = (val, size) => {
  let s = String(val);
  while (s.length < (size || 2)) {
    s = `0${s}`;
  }
  return s;
};

const indexElement = async (type, isRelation = false) => {
  const start = moment();
  // Indexing all entities
  const matchingQuery = isRelation ? '$rel($from, $to)' : '$elem';
  const nbOfEntities = await getSingleValueNumber(`match ${matchingQuery} isa ${type}; get; count;`);
  if (nbOfEntities === 0) return;
  // Compute the number of groups to create
  let counter = 0;
  const nbGroup = Math.ceil(nbOfEntities / GROUP_NUMBER);
  const count = isRelation ? nbOfEntities / 2 : nbOfEntities;
  process.stdout.write(`Indexing ${count} ${type} in 000/${pad(nbGroup, 3)} batchs\r`);
  // Build queries to execute
  const queries = [];
  for (let index = 0; index < nbGroup; index += 1) {
    const offset = index * GROUP_NUMBER;
    const query = `match ${matchingQuery} isa ${type}; get; offset ${offset}; limit ${GROUP_NUMBER};`;
    queries.push(query);
  }
  // Fetch grakn with concurrency limit.
  await Promise.map(
    queries,
    query => {
      return find(query, [isRelation ? 'rel' : 'elem'])
        .then(fetchedGroupElements => {
          const fetchedElements = pipe(
            flatten,
            map(e => e[isRelation ? 'rel' : 'elem']),
            uniqBy(u => u.grakn_id)
          )(fetchedGroupElements);
          return indexElements(fetchedElements, GROUP_INDEX_MAX_RETRY);
        })
        .then(() => {
          counter += 1;
          process.stdout.write(`Indexing ${count} ${type} in ${pad(counter, 3)}/${pad(nbGroup, 3)} batchs\r`);
        });
    },
    { concurrency: GROUP_CONCURRENCY }
  );
  const execDuration = moment.duration(moment().diff(start));
  const avg = (execDuration.asSeconds() / count).toFixed(2);
  console.log(
    `Indexing of ${type} done in ${execDuration.asSeconds()} secs (${execDuration.humanize()}) - Element Avg: ${avg} secs`
  );
  console.log(`> ---------------------------------------------------------------------`);
};

export const index = async () => {
  // 01. Delete current indexes
  await elDeleteIndexes();
  console.log(`Indexing > Old indices deleted`);
  // 02. Create new ones
  await elCreateIndexes();
  console.log(`Indexing > New indices created`);
  // 03. Handle every entity subbing entity
  // MigrationsStatus  - Not needed, migration related.
  // MigrationReference  - Not needed, migration related.
  // Token - Not needed, authentication
  await indexElement('Settings');
  await indexElement('Tag');
  await indexElement('Connector');
  await indexElement('Group');
  await indexElement('Workspace');
  await indexElement('Stix-Domain');
  await indexElement('Stix-Observable');
  await indexElement('Stix-Observable-Data');

  // 04. Handle every entity subbing relation
  // migrate - Not needed, migration related.
  // authorize - Not needed, authentication
  await indexElement('membership', true);
  await indexElement('permission', true);
  await indexElement('user_permission', true);
  await indexElement('stix_relation', true);
  await indexElement('relation_embedded', true);
  await indexElement('stix_relation_embedded', true);
  await indexElement('stix_relation_observable_embedded', true);
  await indexElement('stix_relation_observable_grouping', true);
  await indexElement('stix_sighting', true);
};