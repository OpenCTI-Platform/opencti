import * as R from 'ramda';
import { Promise } from 'bluebird';
import { deleteFiles, loadedFilesListing, storeFileConverter } from '../database/file-storage';
import { executionContext, SYSTEM_USER } from '../utils/access';
import { elUpdate, ES_MAX_CONCURRENCY } from '../database/engine';
import { logApp } from '../config/conf';
import { internalLoadById } from '../database/middleware-loader';

export const up = async (next) => {
  const context = executionContext('migration');
  logApp.info('[MIGRATION] Starting files artifacts migration');
  const imports = await loadedFilesListing(context, SYSTEM_USER, 'import/Artifact/', { recursive: true });
  const importGroups = R.groupBy((i) => i.metaData.entity_id, imports);
  const groupSize = Object.keys(importGroups).length;
  logApp.info(`[MIGRATION] Migrating ${groupSize} artifacts references`);
  const importEntries = Object.entries(importGroups);
  let migratedCount = 0;
  const concurrentChange = (entry) => {
    const [id, groupFiles] = entry;
    return internalLoadById(context, SYSTEM_USER, id).then((element) => {
      if (element) {
        const eventFiles = groupFiles.map((f) => storeFileConverter(SYSTEM_USER, f));
        const source = 'ctx._source.x_opencti_files = params.files;';
        return elUpdate(element._index, element.internal_id, {
          script: { source, lang: 'painless', params: { files: eventFiles } },
        });
      }
      return deleteFiles(context, SYSTEM_USER, groupFiles.map((g) => g.id));
    }).then(() => {
      migratedCount += 1;
      if (migratedCount % 100 === 0) {
        logApp.info(`[MIGRATION] Migrating artifacts: ${migratedCount}/${groupSize}`);
      }
    });
  };
  await Promise.map(importEntries, concurrentChange, { concurrency: ES_MAX_CONCURRENCY });
  logApp.info('[MIGRATION] files artifacts migration finished');
  next();
};

export const down = async (next) => {
  next();
};
