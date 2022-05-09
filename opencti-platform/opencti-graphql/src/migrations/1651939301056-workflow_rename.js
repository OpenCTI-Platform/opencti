import { searchClient } from '../database/engine';
import { READ_DATA_INDICES } from '../database/utils';
import { DatabaseError } from '../config/errors';
import { logApp } from '../config/conf';

export const up = async (next) => {
  logApp.info('[MIGRATION] Changing status attribute to new format');
  await searchClient()
    .updateByQuery({
      index: READ_DATA_INDICES,
      refresh: true,
      conflicts: 'proceed',
      body: {
        script: {
          params: { from: 'status_id', to: 'x_opencti_workflow_id' },
          source: 'ctx._source[params.to] = ctx._source.remove(params.from);',
        },
        query: {
          bool: {
            must: [{ exists: { field: 'status_id' } }],
          },
        },
      },
    })
    .catch((err) => {
      throw DatabaseError('Error updating elastic', { error: err });
    });
  logApp.info('[MIGRATION] Migration finished');
  next();
};

export const down = async (next) => {
  next();
};

// TODO JRI Create needed migrations
/*
// 01. Migrate Entity Type to remove X-OpenCTI!
export const ENTITY_CRYPTOGRAPHIC_KEY = 'X-OpenCTI-Cryptographic-Key';
export const ENTITY_CRYPTOGRAPHIC_WALLET = 'X-OpenCTI-Cryptocurrency-Wallet';
export const ENTITY_HOSTNAME = 'X-OpenCTI-Hostname';
export const ENTITY_TEXT = 'X-OpenCTI-Text';
export const ENTITY_USER_AGENT = 'X-OpenCTI-User-Agent';

// 02. Migrate files to insert information in elastic
const filesList = await rawFilesListing(user, `import/${instance.entity_type}/${instance.id}/`);
instance.x_opencti_files = filesList.map((f) => f.id);
*/
