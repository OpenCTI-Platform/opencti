import { executionContext, SYSTEM_USER } from '../utils/access';
import { loadedFilesListing } from '../database/file-storage';
import { logApp } from '../config/conf';
import { buildFileDataForIndexing } from '../modules/internal/document/document-domain';
import { elIndexElements } from '../database/engine';
import { INDEX_INTERNAL_OBJECTS } from '../database/utils';

export const up = async (next) => {
  const context = executionContext('migration');
  logApp.info('[MIGRATION] Starting 1701354091161-files-registration.js');
  let iteration = 1;
  let filesCount = 0;
  const callback = async (files) => {
    filesCount += files.length;
    logApp.info(`[MIGRATION] (${iteration}) ${files.length} files to register (total: ${filesCount})`);
    const elements = files.map((file) => ({ _index: INDEX_INTERNAL_OBJECTS, ...buildFileDataForIndexing(file) }));
    await elIndexElements(context, SYSTEM_USER, 'Migration files registration', elements);
    iteration += 1;
  };
  await loadedFilesListing(SYSTEM_USER, '', { recursive: true, callback });
  logApp.info('[MIGRATION] Done 1701354091161-files-registration.js');
  next();
};

export const down = async (next) => {
  next();
};
