import { executionContext, SYSTEM_USER } from '../utils/access';
import { rawFilesListing } from '../database/file-storage';
import { logApp } from '../config/conf';
import { buildFileDataForIndexing } from '../modules/internal/document/document-domain';
import { elIndexElements } from '../database/engine';
import { INDEX_INTERNAL_OBJECTS } from '../database/utils';

export const up = async (next) => {
  const context = executionContext('migration');
  logApp.info('[MIGRATION] Starting 1701354091161-files-registration.js');
  const files = await rawFilesListing(context, SYSTEM_USER, '/', { recursive: true });
  logApp.info(`[MIGRATION] ${files.length} files to register in index`);
  const elements = files.map((file) => {
    return { _index: INDEX_INTERNAL_OBJECTS, ...buildFileDataForIndexing(file) };
  });
  await elIndexElements(context, SYSTEM_USER, 'Migration files registration', elements);
  logApp.info('[MIGRATION] Done 1701354091161-files-registration.js');
  next();
};

export const down = async (next) => {
  next();
};
