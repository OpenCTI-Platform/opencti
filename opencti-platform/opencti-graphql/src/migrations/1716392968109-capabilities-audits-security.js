import { executionContext, SYSTEM_USER } from '../utils/access';
import { addCapability } from '../domain/grant';
import { elUpdateByQueryForMigration } from '../database/engine';
import { READ_INDEX_INTERNAL_OBJECTS } from '../database/utils';

export const up = async (next) => {
  const context = executionContext('migration');
  const message = '[MIGRATION] Add SECURITY_ACTIVITY capability to platform and to users with SETTINGS capability';
  await addCapability(
    context,
    SYSTEM_USER,
    {
      name: 'SETTINGS_SECURITYACTIVITY',
      description: 'Security Activity',
      attribute_order: 3500
    }
  );
  const updateQuery = {
    script: {
      source: `
        if (ctx._source.capabilities == null) {
          ctx._source.capabilities = [];
        }
        if (ctx._source.capabilities.contains('SETTINGS') && !ctx._source.capabilities.contains('SECURITY_ACTIVITY')) {
          ctx._source.capabilities.add('SECURITY_ACTIVITY');
        }
      `,
    },
    query: {
      bool: {
        must: [
          { term: { 'entity_type.keyword': { value: 'User' } } },
          { term: { 'capabilities.keyword': { value: 'SETTINGS' } } }
        ],
        must_not: [
          { term: { 'capabilities.keyword': { value: 'SECURITY_ACTIVITY' } } }
        ]
      },
    },
  };
  await elUpdateByQueryForMigration(
    message,
    [READ_INDEX_INTERNAL_OBJECTS],
    updateQuery
  );
  next();
};

export const down = async (next) => {
  next();
};
