import { logApp } from '../config/conf';
import { listAllEntities } from '../database/middleware-loader';
import { executionContext, SYSTEM_USER } from '../utils/access';
import { ENTITY_TYPE_PLAYBOOK } from '../modules/playbook/playbook-types';
import { elUpdateByQueryForMigration } from '../database/engine';
import { isEmptyField, READ_DATA_INDICES } from '../database/utils';
import { PLAYBOOK_INTERNAL_DATA_CRON } from '../modules/playbook/playbook-components';
import { isFilterGroupNotEmpty } from '../utils/filtering/filtering-utils';
import { ABSTRACT_STIX_CORE_OBJECT, REL_INDEX_PREFIX } from '../schema/general';
import { schemaRelationsRefDefinition } from '../schema/schema-relationsRef';

// In playbooks components of type PLAYBOOK_INTERNAL_DATA_CRON
// revert the conversion of rel filter keys that were made by an unwanted call to checkAndConvertFilters at playbook creation

const message = '[MIGRATION] Fix playbook cron filter rel keys conversion';

export const up = async (next) => {
  logApp.info(`${message} > started`);
  const context = executionContext('migration', SYSTEM_USER);

  // detect filter keys providing from a rel conversion
  const isKeyFromRelConversion = (key) => {
    return key.startsWith(REL_INDEX_PREFIX) && key.endsWith('.*');
  };

  const revertRelFilterKeyConversion = (key) => {
    console.log('key', key);
    if (isKeyFromRelConversion(key)) {
      const relDatabaseName = key.replace(REL_INDEX_PREFIX, '').replace('.*', '');
      console.log('---database name---', relDatabaseName);
      const relInputName = schemaRelationsRefDefinition.convertDatabaseNameToInputName(ABSTRACT_STIX_CORE_OBJECT, relDatabaseName);
      if (relInputName) {
        console.log('RETURN REL :', relInputName);
        return relInputName;
      }
      console.log('NO CONVERSION');
      return key;
    }
    console.log('NO CONVERSION');
    return key; // no conversion for key that are not rel
  };

  // fonction to revert the conversion of rel filter keys
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

  // fetch the playbooks
  const playbooks = await listAllEntities(
    context,
    SYSTEM_USER,
    [ENTITY_TYPE_PLAYBOOK],
  );

  // fill playbooksDefinitionConvertor with the playbook with the converted filters
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

  // update the playbooks filters in elastic
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
  throw Error('test');
  logApp.info(`${message} > done`);
  next();
};

export const down = async (next) => {
  next();
};
