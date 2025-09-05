import { logMigration } from '../config/conf';
import { fullEntitiesList } from '../database/middleware-loader';
import { executionContext, SYSTEM_USER } from '../utils/access';
import { ENTITY_TYPE_PLAYBOOK } from '../modules/playbook/playbook-types';
import { elUpdateByQueryForMigration } from '../database/engine';
import { isEmptyField, READ_DATA_INDICES } from '../database/utils';
import { PLAYBOOK_INTERNAL_DATA_CRON } from '../modules/playbook/playbook-components';
import { isFilterGroupNotEmpty } from '../utils/filtering/filtering-utils';
import { REL_INDEX_PREFIX } from '../schema/general';
import { schemaRelationsRefDefinition } from '../schema/schema-relationsRef';

// In playbooks components of type PLAYBOOK_INTERNAL_DATA_CRON
// revert the conversion of rel filter keys that were made by an unwanted call to checkAndConvertFilters at playbook creation

const message = '[MIGRATION] Fix playbook cron filter rel keys conversion';

export const up = async (next) => {
  logMigration.info(`${message} > started`);
  const context = executionContext('migration', SYSTEM_USER);

  // -- step 0: define the utils functions --
  // detect filter keys providing from a rel conversion
  const isKeyFromRelConversion = (key) => {
    return key.startsWith(REL_INDEX_PREFIX) && key.endsWith('.*');
  };

  // map [input_name, database_name] for rel relationship to convert the keys
  const inputNameToDatabaseNameMap = new Map(
    schemaRelationsRefDefinition.getAllInputNames()
      .map((name) => [schemaRelationsRefDefinition.getDatabaseName(name), name]),
  );

  // revert a filter key conversion done by checkAndConvertFilters
  const revertRelFilterKeyConversion = (key) => {
    if (isKeyFromRelConversion(key)) {
      const relDatabaseName = key.replace(REL_INDEX_PREFIX, '').replace('.*', '');
      const relInputName = inputNameToDatabaseNameMap.get(relDatabaseName);
      if (relInputName) {
        return relInputName;
      }
      return key;
    }
    return key; // no conversion for key that are not rel
  };

  // revert the conversion of a filters object
  const convertFilters = (inputFilters) => {
    // no filters
    if (!inputFilters || isEmptyField(inputFilters)) {
      return undefined;
    }
    // empty filters
    if (!isFilterGroupNotEmpty(inputFilters)) {
      return inputFilters;
    }
    const { filters, filterGroups } = inputFilters;
    const newFiltersContent = [];
    const newFilterGroupsContent = [];

    if (filterGroups.length > 0) {
      for (let i = 0; i < filterGroups.length; i += 1) {
        const group = filterGroups[i];
        const convertedGroup = convertFilters(group);
        newFilterGroupsContent.push(convertedGroup);
      }
    }
    filters.forEach((f) => {
      const filterKeys = Array.isArray(f.key) ? f.key : [f.key];
      const convertedFilterKeys = filterKeys
        .map((key) => revertRelFilterKeyConversion(key));
      newFiltersContent.push({ ...f, key: convertedFilterKeys });
    });
    return {
      mode: inputFilters.mode,
      filters: newFiltersContent,
      filterGroups: newFilterGroupsContent,
    };
  };

  // -- step 1: fetch the playbooks --
  const playbooks = await fullEntitiesList(
    context,
    SYSTEM_USER,
    [ENTITY_TYPE_PLAYBOOK],
  );

  // -- step 2: fill playbooksDefinitionConvertor with the playbooks with correct filters --
  let playbooksDefinitionConvertor = {};
  playbooks
    .forEach((playbook) => {
      const playbookDefinition = JSON.parse(playbook.playbook_definition);
      const definitionNodes = playbookDefinition.nodes;
      const newDefinitionNodes = [];
      for (let i = 0; i < definitionNodes.length; i += 1) {
        const node = definitionNodes[i];
        if (node.component_id === PLAYBOOK_INTERNAL_DATA_CRON.id) {
          const nodeConfiguration = JSON.parse(node.configuration);
          const { filters } = nodeConfiguration;
          if (filters) {
            const newFilters = JSON.stringify(convertFilters(JSON.parse(filters)));
            const newNode = {
              ...node,
              configuration: JSON.stringify({
                ...nodeConfiguration,
                filters: newFilters,
              }),
            };
            newDefinitionNodes.push(newNode);
          } else { // no conversion to do
            newDefinitionNodes.push(node);
          }
        } else { // no conversion to do for components that are not CRON
          newDefinitionNodes.push(node);
        }
      }
      const newPlaybookDefinition = {
        ...playbookDefinition,
        nodes: newDefinitionNodes,
      };
      playbooksDefinitionConvertor = {
        ...playbooksDefinitionConvertor,
        [playbook.internal_id]: JSON.stringify(newPlaybookDefinition),
      };
    });

  // -- step 3: update the playbooks filters in elastic --
  const playbooksUpdateQuery = {
    script: {
      params: { convertor: playbooksDefinitionConvertor },
      source: 'if (params.convertor.containsKey(ctx._source.internal_id)) { ctx._source.playbook_definition = params.convertor[ctx._source.internal_id]; }',
    },
    query: {
      bool: {
        should: [
          {
            bool: {
              must: [{ term: { 'entity_type.keyword': { value: 'Playbook' } } }],
            }
          },
        ],
        minimum_should_match: 1,
      },
    }
  };
  await elUpdateByQueryForMigration(
    '[MIGRATION] Playbooks CRON filters keys conversion fix',
    READ_DATA_INDICES,
    playbooksUpdateQuery
  );
  logMigration.info(`${message} > done`);
  next();
};

export const down = async (next) => {
  next();
};
