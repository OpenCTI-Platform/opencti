import { flatten, map, pipe, uniqBy } from 'ramda';
import moment from 'moment';
import { find, getSingleValueNumber, reindexElements } from './database/grakn';
import { elCreateIndexes, elDeleteIndexes } from './database/elasticSearch';

const GROUP_NUMBER = 200;

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
  const nbGroup = Math.ceil(nbOfEntities / GROUP_NUMBER);
  const count = isRelation ? nbOfEntities / 2 : nbOfEntities;
  let counter = 0;
  process.stdout.write(`Fetching ${count} ${type} in 000/${pad(nbGroup, 3)} batchs\r`);
  const fetchedPromises = [];
  for (let index = 0; index < nbGroup; index += 1) {
    const offset = index * GROUP_NUMBER;
    // `match ${matchingQuery} isa ${type}, has internal_id_key $key; get; sort $key asc; offset ${offset}; limit ${GROUP_NUMBER};`;
    const query = `match ${matchingQuery} isa ${type}; get; offset ${offset}; limit ${GROUP_NUMBER};`;
    // eslint-disable-next-line no-loop-func
    const batch = find(query, [isRelation ? 'rel' : 'elem']).then(data => {
      counter += 1;
      process.stdout.write(`Fetching ${count} ${type} in ${pad(counter, 3)}/${pad(nbGroup, 3)} batchs\r`);
      return data;
    });
    fetchedPromises.push(batch);
  }
  const fetchedGroupElements = await Promise.all(fetchedPromises);
  const fetchedElements = pipe(
    flatten,
    map(e => e[isRelation ? 'rel' : 'elem']),
    uniqBy(u => u.grakn_id)
  )(fetchedGroupElements);
  console.log(`\nReindexing ${type} ... ${fetchedElements.length}`);
  await reindexElements(fetchedElements);
  const execDuration = moment.duration(moment().diff(start));
  const avg = (execDuration.asSeconds() / count).toFixed(2);
  console.log(
    `Indexing of ${type} done in ${execDuration.asSeconds()} secs (${execDuration.humanize()}) - Element Avg: ${avg} secs`
  );
  console.log(`> ---------------------------------------------------------------------`);
};
const indexer = async () => {
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
  await indexElement('authored_by', true);
  await indexElement('owned_by', true);
  await indexElement('tagged', true);
  await indexElement('stix_relation_observable_embedded', true);
  await indexElement('stix_relation_observable_grouping', true);
  await indexElement('stix_sighting', true);
};
const start = moment();
console.log(`> ---------------------------------------------------------------------`);
indexer().then(() => {
  const execDuration = moment.duration(moment().diff(start));
  console.log(`Indexing done in ${execDuration.asSeconds()} seconds (${execDuration.humanize()})`);
});
