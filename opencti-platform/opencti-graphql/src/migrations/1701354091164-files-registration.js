import { executionContext, SYSTEM_USER } from '../utils/access';
import { rawFilesListing } from '../database/file-storage';
import { logApp } from '../config/conf';
import { indexFileToDocument } from '../modules/document/document-domain';

export const up = async (next) => {
  const context = executionContext('migration');
  logApp.info('[MIGRATION] Starting 1701354091161-files-registration.js');
  const files = await rawFilesListing(context, SYSTEM_USER, '/', { recursive: true });
  logApp.info(`[MIGRATION] ${files.length} files to register in index`);
  let count = 0;
  for (let index = 0; index < files.length; index += 1) {
    const file = files[index];
    const pathSegments = file.id.split('/');
    pathSegments.pop();
    const path = pathSegments.join('/');
    await indexFileToDocument(path, file);
    count += 1;
    if (count % 100 === 0) {
      logApp.info(`[MIGRATION] ${count}/${files.length}`);
    }
  }
  logApp.info('[MIGRATION] Done 1701354091161-files-registration.js');
  next();
};

export const down = async (next) => {
  next();
};
