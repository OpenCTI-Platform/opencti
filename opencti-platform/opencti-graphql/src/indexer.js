import { flatten, map, pipe, uniqBy } from 'ramda';
import moment from 'moment';
import { find, getSingleValueNumber, reindexElements } from './database/grakn';
import { elCreateIndexes, elDeleteIndexes } from './database/elasticSearch';

const GROUP_NUMBER = 15;
const indexElement = async (type, isRelation = false) => {
  const start = moment();
  // Indexing all entities
  const matchingQuery = isRelation ? '$rel($from, $to)' : '$elem';
  const nbOfEntities = await getSingleValueNumber(`match ${matchingQuery} isa ${type}; get; count;`);
  // Compute the number of groups to create
  const nbGroup = Math.ceil(nbOfEntities / GROUP_NUMBER);
  console.log(`Fetching ${type} ... ${isRelation ? nbOfEntities / 2 : nbOfEntities} in 0/${nbGroup} batchs`);
  const fetchedPromises = [];
  for (let index = 0; index < nbGroup; index += 1) {
    const offset = index * GROUP_NUMBER;
    // `match ${matchingQuery} isa ${type}, has internal_id_key $key; get; sort $key asc; offset ${offset}; limit ${GROUP_NUMBER};`;
    const query = `match ${matchingQuery} isa ${type}, has internal_id_key $key; get; sort $key asc; offset ${offset}; limit ${GROUP_NUMBER};`;
    const batch = find(query, [isRelation ? 'rel' : 'elem']);
    fetchedPromises.push(batch);
  }
  const fetchedGroupElements = await Promise.all(fetchedPromises);
  const fetchedElements = pipe(
    flatten,
    map(e => e[isRelation ? 'rel' : 'elem']),
    uniqBy(u => u.grakn_id)
  )(fetchedGroupElements);
  console.log(`Reindexing ${type} ... ${fetchedElements.length}`);
  await reindexElements(fetchedElements);
  // Wait for all batch to execute.
  // await Promise.all(indexedElements);
  const execDuration = moment.duration(moment().diff(start));
  console.log(`Indexing of ${type} done in ${execDuration.asSeconds()} seconds (${execDuration.humanize()})`);
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
  // MigrationsStatus
  // MigrationReference
  await indexElement('Settings');
  await indexElement('Tag');
  await indexElement('Connector');
  await indexElement('Group');
  await indexElement('Workspace');
  // await indexElement('Token'); // TODO JRI ???
  await indexElement('Stix-Domain');
  await indexElement('Stix-Observable');
  await indexElement('Stix-Observable-Data');

  // 04. Handle every entity subbing relation
  // authorize
  // migrate
  // membership
  // permission
  // user_permission
  await indexElement('stix_relation', true);
  await indexElement('relation_embedded', true);
  await indexElement('stix_relation_embedded', true);
  // authored_by
  // owned_by
  await indexElement('tagged', true);
  // stix_relation_observable_embedded
  // stix_relation_observable_grouping
  // stix_sighting
};
const start = moment();
console.log(`> ---------------------------------------------------------------------`);
indexer().then(() => {
  const execDuration = moment.duration(moment().diff(start));
  console.log(`Indexing done in ${execDuration.asSeconds()} seconds (${execDuration.humanize()})`);
});
