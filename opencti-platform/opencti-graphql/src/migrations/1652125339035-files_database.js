import * as R from 'ramda';
import { Promise } from 'bluebird';
import { deleteFiles, rawFilesListing, storeFileConverter } from '../database/file-storage';
import { SYSTEM_USER } from '../utils/access';
import { elUpdate, ES_MAX_CONCURRENCY } from '../database/engine';
import { internalLoadById } from '../database/middleware';
import { logApp } from '../config/conf';

export const up = async (next) => {
  logApp.info('[MIGRATION] Starting 1652125339035-files_database.js');
  const files = await rawFilesListing(SYSTEM_USER, '/', true);
  const imports = files.filter((f) => f.id.startsWith('import/'));
  logApp.info(`[MIGRATION] Migrating ${imports.length} files references`);
  const importGroups = R.groupBy((i) => i.metaData.entity_id, imports);
  const importEntries = Object.entries(importGroups);
  const concurrentChange = (entry) => {
    const [id, groupFiles] = entry;
    return internalLoadById(SYSTEM_USER, id).then((element) => {
      if (element) {
        const eventFiles = groupFiles.map((f) => storeFileConverter(SYSTEM_USER, f));
        const source = 'ctx._source.x_opencti_files = params.files;';
        return elUpdate(element._index, element.internal_id, {
          script: { source, lang: 'painless', params: { files: eventFiles } },
        });
      }
      return deleteFiles(SYSTEM_USER, groupFiles.map((g) => g.id));
    });
  };
  await Promise.map(importEntries, concurrentChange, { concurrency: ES_MAX_CONCURRENCY });
  logApp.info('[MIGRATION] 1652125339035-files_database.js finished');
  next();
};

export const down = async (next) => {
  next();
};
