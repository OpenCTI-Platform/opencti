import { logApp } from '../config/conf';
import { elUpdateByQueryForMigration } from '../database/engine';
import { READ_RELATIONSHIPS_INDICES } from '../database/utils';

const message = '[MIGRATION] Fix old rename for relations';

export const up = async (next) => {
  logApp.info(`${message} > started`);
  const types = [
    { source: 'X-OpenCTI-Cryptographic-Key', destination: 'Cryptographic-Key' },
    { source: 'X-OpenCTI-Cryptocurrency-Wallet', destination: 'Cryptocurrency-Wallet' },
    { source: 'X-OpenCTI-Hostname', destination: 'Hostname' },
    { source: 'X-OpenCTI-Text', destination: 'Text' },
    { source: 'X-OpenCTI-User-Agent', destination: 'User-Agent' },
  ];
  const scriptSource = `
    if (ctx._source.fromType == params.type) {
      ctx._source.fromType = params.target;
    }
    if (ctx._source.toType == params.type) {
      ctx._source.toType = params.target;
    }
    for (connection in ctx._source.connections) {
      def typeIndex = connection.types.indexOf(params.type);
      if (typeIndex >= 0) {
        connection.types.remove(typeIndex);
        connection.types.add(params.target)
      }
    }
  `;
  for (let index = 0; index < types.length; index += 1) {
    const { source, destination } = types[index];
    const updateQuery = {
      script: {
        params: { type: source, target: destination },
        source: scriptSource,
      },
      query: {
        nested: {
          path: 'connections',
          query: {
            term: {
              'connections.types.keyword': source,
            },
          },
        },
      },
    };
    await elUpdateByQueryForMigration(
      `Rename entity type ${source} to ${destination}`,
      READ_RELATIONSHIPS_INDICES,
      updateQuery
    );
  }
  logApp.info(`${message} > done`);
  next();
};

export const down = async (next) => {
  next();
};
