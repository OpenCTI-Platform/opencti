import { elUpdateByQueryForMigration } from '../database/engine';
import { fullEntitiesList } from '../database/middleware-loader';
import { READ_INDEX_INTERNAL_OBJECTS } from '../database/utils';
import { ENTITY_TYPE_PLAYBOOK } from '../modules/playbook/playbook-types';
import { executionContext, SYSTEM_USER } from '../utils/access';
import { logMigration } from '../config/conf';

// Addition of new attribute "canEnrollManually" in PLAYBOOK_INTERNAL_DATA_STREAM component configuration.
// Before: no "canEnrollManually" attribute in the component config.
// Now: "canEnrollManually" boolean attribute, defaulting to true.

const message = '[MIGRATION] Upgrade playbook configs with new attribute: canEnrollManually';

const PLAYBOOK_INTERNAL_DATA_STREAM_ID = 'PLAYBOOK_INTERNAL_DATA_STREAM';

const elasticUpdate = (convertor) => {
  const playbooksUpdateQuery = {
    script: {
      params: { convertor },
      source: 'if (params.convertor.containsKey(ctx._source.internal_id)) { ctx._source.playbook_definition = params.convertor[ctx._source.internal_id]; }',
    },
    query: {
      term: {
        'entity_type.keyword': {
          value: ENTITY_TYPE_PLAYBOOK,
        },
      },
    },
  };
  return elUpdateByQueryForMigration(
    message,
    READ_INDEX_INTERNAL_OBJECTS,
    playbooksUpdateQuery,
  );
};

export const up = async (next) => {
  logMigration.info(`${message} > started`);
  const context = executionContext('migration', SYSTEM_USER);

  // -- step 1: fetch all playbooks --
  const playbooks = await fullEntitiesList(context, SYSTEM_USER, [ENTITY_TYPE_PLAYBOOK]);

  // -- step 2: update the config of PLAYBOOK_INTERNAL_DATA_STREAM nodes --
  let playbooksDefinitionConvertor = {};

  playbooks.forEach((playbook) => {
    const playbookDefinition = JSON.parse(playbook.playbook_definition);
    let hasChanges = false;

    const newDefinitionNodes = playbookDefinition.nodes.map((node) => {
      if (node.component_id !== PLAYBOOK_INTERNAL_DATA_STREAM_ID) {
        return node;
      }
      const nodeConfiguration = JSON.parse(node.configuration);

      // Only migrate nodes that don't already have the new attribute
      if (nodeConfiguration.canEnrollManually !== undefined) {
        return node;
      }

      hasChanges = true;
      return {
        ...node,
        configuration: JSON.stringify({
          ...nodeConfiguration,
          canEnrollManually: true,
        }),
      };
    });

    // Only include playbooks that actually needed changes
    if (hasChanges) {
      playbooksDefinitionConvertor = {
        ...playbooksDefinitionConvertor,
        [playbook.internal_id]: JSON.stringify({
          ...playbookDefinition,
          nodes: newDefinitionNodes,
        }),
      };
    }
  });

  // -- step 3: update the playbooks in elastic --
  if (Object.keys(playbooksDefinitionConvertor).length > 0) {
    await elasticUpdate(playbooksDefinitionConvertor);
  }

  logMigration.info(`${message} > done`);
  next();
};

export const down = async (next) => {
  next();
};
