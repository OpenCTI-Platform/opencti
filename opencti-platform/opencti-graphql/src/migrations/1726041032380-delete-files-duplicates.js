import { groupBy, uniq } from 'ramda';
import { logApp } from '../config/conf';
import { listAllEntities } from '../database/middleware-loader';
import { ENTITY_TYPE_INTERNAL_FILE } from '../schema/internalObject';
import { elDeleteInstances } from '../database/engine';
import { executionContext, SYSTEM_USER } from '../utils/access';
import { READ_INDEX_INTERNAL_OBJECTS } from '../database/utils';

const message = '[MIGRATION] Delete potential files duplicates after index rollover';

export const up = async (next) => {
  logApp.info(`${message} > started`);
  // TODO condition de départ pour déterminer s'il y a plusieurs index internal_objects
  const context = executionContext('migration');
  const allFiles = await listAllEntities(context, SYSTEM_USER, [ENTITY_TYPE_INTERNAL_FILE], { indices: [READ_INDEX_INTERNAL_OBJECTS] });
  // TODO only fetch id, internal_id, lastModified, _index
  const filesGroupedById = Object.entries(groupBy((f) => f.internal_id, allFiles));
  const filesToDelete = [];
  filesGroupedById.forEach(([_, filesList]) => {
    if (filesList.length > 1) { // if a duplicate exists
      const maximumLastModified = filesList.map((h) => h.lastModified).sort((a, b) => b.localeCompare(a))[0];
      const olderFiles = filesList.filter((f) => f.lastModified !== maximumLastModified);
      filesToDelete.push(olderFiles);
    }
  });
  // keep uniq couples (id, index) of files to delete
  const finalFilesToDelete = uniq(filesToDelete.map((h) => [h._index, h.internal_id]));
  logApp.info(`Deleting ${finalFilesToDelete.length} files that have duplicates.`);
  // delete the files
  await elDeleteInstances(finalFilesToDelete);
  logApp.info(`${message} > done`);
  next();
};

export const down = async (next) => {
  next();
};
