import { searchClient } from '../database/engine';
import { READ_DATA_INDICES } from '../database/utils';
import { DatabaseError } from '../config/errors';

export const up = async (next) => {
  await searchClient()
    .updateByQuery({
      index: READ_DATA_INDICES,
      refresh: true,
      body: {
        script: {
          params: { from: 'status_id', to: 'x_opencti_workflow_id' },
          source: 'ctx._source[params.to] = ctx._source[params.from]; ctx._source.remove(params.from);',
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
  next();
};

export const down = async (next) => {
  next();
};
