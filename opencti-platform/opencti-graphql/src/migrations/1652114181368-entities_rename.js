// TODO JRI Create needed migrations
/*
// 02. Migrate files to insert information in elastic
const filesList = await rawFilesListing(user, `import/${instance.entity_type}/${instance.id}/`);
instance.x_opencti_files = filesList.map((f) => f.id);
*/

import { logApp } from '../config/conf';
import { searchClient } from '../database/engine';
import { READ_DATA_INDICES } from '../database/utils';
import { DatabaseError } from '../config/errors';

export const up = async (next) => {
  const entities = [
    { source: 'X-OpenCTI-Cryptographic-Key', destination: 'Cryptographic-Key' },
    { source: 'X-OpenCTI-Cryptocurrency-Wallet', destination: 'Cryptocurrency-Wallet' },
    { source: 'X-OpenCTI-Hostname', destination: 'Hostname' },
    { source: 'X-OpenCTI-Text', destination: 'Text' },
    { source: 'X-OpenCTI-User-Agent', destination: 'User-Agent' },
  ];

  logApp.info('[MIGRATION] Changing entity custom names');
  for (let index = 0; index < entities.length; index += 1) {
    const { source, destination } = entities[index];
    logApp.info(`[MIGRATION] Renaming entity ${source}`);
    await searchClient()
      .updateByQuery({ index: READ_DATA_INDICES,
        refresh: true,
        body: {
          script: {
            params: { name: destination },
            source: 'ctx._source.entity_type = params.name;',
          },
          query: {
            bool: {
              must: [
                { term: { 'entity_type.keyword': { value: source } } },
              ],
            },
          },
        } })
      .catch((err) => {
        throw DatabaseError('Error updating elastic', { error: err });
      });
  }
  logApp.info('[MIGRATION] Migration finished');
  next();
};

export const down = async (next) => {
  next();
};
