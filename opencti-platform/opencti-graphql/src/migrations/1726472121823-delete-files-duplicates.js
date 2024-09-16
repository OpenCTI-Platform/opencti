import { groupBy } from 'ramda';
import { logApp } from '../config/conf';
import { listAllEntities } from '../database/middleware-loader';
import { ENTITY_TYPE_INTERNAL_FILE } from '../schema/internalObject';
import { elDeleteInstances, elIndexGetAlias } from '../database/engine';
import { executionContext, SYSTEM_USER } from '../utils/access';
import { READ_INDEX_INTERNAL_OBJECTS } from '../database/utils';

const message = '[MIGRATION] Delete potential files duplicates after index rollover';

export const up = async (next) => {
  logApp.info(`${message} > started`);
  const context = executionContext('migration');
  // test if there are multiple indices for internal objects
  const internalObjectsIndexAlias = await elIndexGetAlias(READ_INDEX_INTERNAL_OBJECTS);
  if (internalObjectsIndexAlias && Object.keys(internalObjectsIndexAlias).length > 1) {
    logApp.info(`${message} > multiple indices found for internal objects, running migration`);
    const allFiles = await listAllEntities(
      context,
      SYSTEM_USER,
      [ENTITY_TYPE_INTERNAL_FILE],
      { indices: [READ_INDEX_INTERNAL_OBJECTS], baseData: true, baseFields: ['internal_id', '_index', 'lastModified'] }
    );
    const filesGroupedById = Object.entries(groupBy((f) => f.internal_id, allFiles));
    const filesToDelete = [];
    filesGroupedById.forEach(([_, filesList]) => {
      if (filesList.length > 1) { // if a duplicate exists
        const sortedFileList = filesList.sort((a, b) => new Date(b.lastModified) - new Date(a.lastModified));
        filesToDelete.push(...sortedFileList.slice(1));
      }
    });
    const finalFilesToDelete = filesToDelete.map((h) => ({ _index: h._index, internal_id: h.internal_id }));
    logApp.info(`Deleting ${finalFilesToDelete.length} files that have duplicates.`);
    // delete the files
    await elDeleteInstances(finalFilesToDelete);
  } else {
    logApp.info(`${message} > no multiple indices found for internal objects, no need to run migration`);
  }
  logApp.info(`${message} > done`);
  next();
};

export const down = async (next) => {
  next();
};
