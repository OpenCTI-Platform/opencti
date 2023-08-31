import { logApp } from '../config/conf';
import { ES_IGNORE_THROTTLED, elRawSearch } from '../database/engine';
import { READ_INDEX_INTERNAL_OBJECTS } from '../database/utils';
import { addCapability } from '../domain/grant';
import { SYSTEM_USER, executionContext } from '../utils/access';

const message = '[MIGRATION] Add new capabilities for Case RBAC';

export const up = async (next) => {
  logApp.info(`${message} > started`);

  const context = executionContext('migration');
  const capabilities = [
    {
      name: 'KNOWLEDGE_KNCASES',
      description: 'Case management',
      attribute_order: 305,
    },
    {
      name: 'KNOWLEDGE_KNCASES_KNCREATE',
      description: 'Create cases',
      attribute_order: 306,
    },
    {
      name: 'KNOWLEDGE_KNCASES_KNUPDATE',
      description: 'Update cases',
      attribute_order: 307,
    },
    {
      name: 'KNOWLEDGE_KNCASES_KNDELETE',
      description: 'Delete cases',
      attribute_order: 308,
    },
  ];
  const findQuery = (capability) => ({
    index: READ_INDEX_INTERNAL_OBJECTS,
    ignore_throttled: ES_IGNORE_THROTTLED,
    body: {
      query: {
        bool: {
          must: [
            {
              match: {
                'entity_type.keyword': 'Capability'
              }
            },
            {
              match: {
                'name.keyword': capability
              }
            }
          ]
        }
      }
    }
  });

  // Determine if Case RBAC Capabilities are already in Elastic
  // Use Promise.all to run in parallel
  await Promise.all(capabilities.map(async (capability) => {
    const searchQuery = findQuery(capability.name);
    const data = await elRawSearch(
      context,
      SYSTEM_USER,
      'Capabilities',
      searchQuery
    );
    if (data?.hits?.hits?.length < 1) {
      logApp.info(`${message} > Adding capability ${capability.name}`);
      await addCapability(context, SYSTEM_USER, capability);
    }
  }));

  logApp.info(`${message} > done`);
  next();
};

export const down = async (next) => {
  next();
};
