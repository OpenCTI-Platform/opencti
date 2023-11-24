import { head, last, toPairs } from 'ramda';
import { executionContext, SYSTEM_USER } from '../utils/access';
import { listAllEntities } from '../database/middleware-loader';
import {
  ENTITY_TYPE_BACKGROUND_TASK,
  ENTITY_TYPE_FEED, ENTITY_TYPE_RETENTION_RULE,
  ENTITY_TYPE_STREAM_COLLECTION,
  ENTITY_TYPE_TAXII_COLLECTION
} from '../schema/internalObject';
import { ENTITY_TYPE_TRIGGER } from '../modules/notification/notification-types';
import { logApp } from '../config/conf';
import { isEmptyField, READ_DATA_INDICES } from '../database/utils';
import { elUpdateByQueryForMigration } from '../database/engine';
import { DatabaseError } from '../config/errors';
import { ENTITY_TYPE_WORKSPACE } from '../modules/workspace/workspace-types';
import { ENTITY_TYPE_PLAYBOOK } from '../modules/playbook/playbook-types';

const message = '[MIGRATION] Stored filters refacto';

export const up = async (next) => {
  logApp.info(`${message} > started`);
  const context = executionContext('migration', SYSTEM_USER);

  // 00. utils
  const filterKeysConvertor = new Map([
    ['labelledBy', 'objectLabel'],
    ['markedBy', 'objectMarking'],
    ['objectContains', 'objects'],
    ['killChainPhase', 'killChainPhases'],
    ['assigneeTo', 'objectAssignee'],
    ['participant', 'objectParticipant'],
    ['creator', 'creator_id'],
    ['hasExternalReference', 'externalReferences'],
    ['hashes_MD5', 'hashes.MD5'],
    ['hashes_SHA1', 'hashes.SHA-1'],
    ['hashes_SHA256', 'hashes.SHA-256'],
    ['hashes_SHA512', 'hashes.SHA-512'],
  ]);
  const convertFilters = (filters, alreadyParsed = false, instance_trigger = false) => {
    if (isEmptyField(filters)) {
      return undefined;
    }
    const parsedFilters = alreadyParsed ? filters : JSON.parse(filters);
    // filters already in new format are not converted again (code protection in case of migration re-run)
    if (parsedFilters.mode) {
      return filters;
    }
    const newFiltersContent = [];
    const newFilterGroupsContent = [];
    toPairs(parsedFilters).forEach((pair) => {
      let key = head(pair);
      const values = last(pair);
      const valIds = values.map((v) => v.id);
      let operator = 'eq';
      let mode = 'or';
      // handle operators contained in the key
      if (key.endsWith('start_date') || key.endsWith('_gt')) {
        key = key.replace('_start_date', '').replace('_gt', '');
        operator = 'gt';
      } else if (key.endsWith('end_date') || key.endsWith('_lt')) {
        key = key.replace('_end_date', '').replace('_lt', '');
        operator = 'lt';
      } else if (key.endsWith('_lte')) {
        key = key.replace('_lte', '');
        operator = 'lte';
      } else if (key.endsWith('_not_eq')) {
        key = key.replace('_not_eq', '');
        operator = 'not_eq';
        mode = 'and';
      }
      // change renamed keys
      if (filterKeysConvertor.has(key)) {
        key = filterKeysConvertor.get(key);
      }
      // rename element_id key for instance triggers
      if (instance_trigger && key === 'elementId') {
        key = 'connectedToId';
      }
      if (valIds.includes(null)) { // values cannot contains 'null' anymore, new nil operator
        const nilOperator = (operator === 'not_eq') ? 'not_nil' : 'nil'; // replace the operator
        if (valIds.length === 1) { // if there is only 'null' in values
          newFiltersContent.push({ key: [key], values: [], operator: nilOperator, mode }); // replace by a filter with nil and values = []
        } else { // if there is other values
          newFilterGroupsContent.push(
            {
              mode,
              filters: [
                { key: [key], values: valIds.filter((id) => id !== null), operator, mode }, // remove null id
                { key: [key], values: [], operator: nilOperator, mode }, // create a filter for the former null id
              ],
              filterGroups: [],
            }
          );
        }
      } else {
        newFiltersContent.push({ key: [key], values: valIds, operator, mode });
      }
    });
    const newFilters = {
      mode: 'and',
      filters: newFiltersContent,
      filterGroups: newFilterGroupsContent,
    };
    return alreadyParsed ? newFilters : JSON.stringify(newFilters);
  };

  // 01. feeds, taxiiCollections, triggers, streams, retention rules
  const entitiesToRefacto = await listAllEntities(
    context,
    SYSTEM_USER,
    [ENTITY_TYPE_FEED, ENTITY_TYPE_TAXII_COLLECTION, ENTITY_TYPE_TRIGGER, ENTITY_TYPE_STREAM_COLLECTION, ENTITY_TYPE_RETENTION_RULE],
  );

  let entitiesFiltersConvertor = {};
  entitiesToRefacto
    .forEach((n) => {
      const instance_trigger = n.entity_type === ENTITY_TYPE_TRIGGER && n.instance_trigger === true;
      entitiesFiltersConvertor = {
        ...entitiesFiltersConvertor,
        [n.internal_id]: convertFilters(n.filters, false, instance_trigger),
      };
    });

  const entitiesUpdateQuery = {
    script: {
      params: { convertor: entitiesFiltersConvertor },
      source: 'if (params.convertor.containsKey(ctx._source.internal_id)) { ctx._source.filters = params.convertor[ctx._source.internal_id]; }',
    },
    query: {
      bool: {
        should: [
          {
            bool: {
              must: [{ term: { 'entity_type.keyword': { value: 'Trigger' } } }],
            }
          },
          {
            bool: {
              must: [{ term: { 'entity_type.keyword': { value: 'TaxiiCollection' } } }],
            }
          },
          {
            bool: {
              must: [{ term: { 'entity_type.keyword': { value: 'Feed' } } }],
            }
          },
          {
            bool: {
              must: [{ term: { 'entity_type.keyword': { value: 'StreamCollection' } } }],
            }
          },
          {
            bool: {
              must: [{ term: { 'entity_type.keyword': { value: 'RetentionRule' } } }],
            }
          },
        ],
        minimum_should_match: 1,
      },
    }
  };
  await elUpdateByQueryForMigration(
    '[MIGRATION] Triggers, Taxii and Feeds filters refacto',
    READ_DATA_INDICES,
    entitiesUpdateQuery
  ).catch((err) => {
    throw DatabaseError('Error updating elastic', { error: err });
  });

  // 02. not finished query background tasks
  const tasks = await listAllEntities(
    context,
    SYSTEM_USER,
    [ENTITY_TYPE_BACKGROUND_TASK],
    {
      filters: {
        mode: 'and',
        filters: [
          {
            key: 'type',
            values: ['QUERY'],
          },
          {
            key: 'completed',
            values: ['false'],
          }
        ],
        filterGroups: [],
      }
    },
    true,
  );

  let tasksFiltersConvertor = {};
  tasks
    .filter((task) => task.task_filters)
    .forEach((task) => {
      tasksFiltersConvertor = {
        ...tasksFiltersConvertor,
        [task.internal_id]: convertFilters(task.task_filters),
      };
    });

  const tasksUpdateQuery = {
    script: {
      params: { convertor: tasksFiltersConvertor },
      source: 'if (params.convertor.containsKey(ctx._source.internal_id)) { ctx._source.task_filters = params.convertor[ctx._source.internal_id]; }',
    },
    query: {
      bool: {
        must: [
          { term: { 'entity_type.keyword': { value: 'BackgroundTask' } } },
          { term: { 'type.keyword': { value: 'QUERY' } } },
          { term: { 'completed.keyword': { value: 'false' } } },
        ],
      },
    }
  };
  await elUpdateByQueryForMigration(
    '[MIGRATION] Query tasks filters refacto',
    READ_DATA_INDICES,
    tasksUpdateQuery
  ).catch((err) => {
    throw DatabaseError('Error updating elastic', { error: err });
  });

  // 03. Workspaces
  const workspaces = await listAllEntities(
    context,
    SYSTEM_USER,
    [ENTITY_TYPE_WORKSPACE],
  );

  let workspacesManifestConvertor = {};
  workspaces
    .forEach((workspace) => {
      if (workspace.manifest) {
        const decodedManifest = JSON.parse(atob(workspace.manifest)); // atob is used to decode B64 strings
        const { widgets } = decodedManifest;
        const widgetEntries = Object.entries(widgets);
        const newWidgets = {};
        for (let i = 0; i < widgetEntries.length; i += 1) {
          const [key, value] = widgetEntries[i];
          const { dataSelection } = value;
          const newDataSelection = dataSelection.map((selection) => {
            const { filters = null, dynamicFrom = null, dynamicTo = null } = selection;
            const newFilters = convertFilters(filters, true);
            const newDynamicFrom = convertFilters(dynamicFrom, true);
            const newDynamicTo = convertFilters(dynamicTo, true);
            return {
              ...selection,
              filters: newFilters,
              dynamicFrom: newDynamicFrom,
              dynamicTo: newDynamicTo,
            };
          });
          newWidgets[key] = {
            ...value,
            dataSelection: newDataSelection,
          };
        }
        const newManifest = {
          ...decodedManifest,
          widgets: newWidgets,
        };
        const newEncodedManifest = btoa(JSON.stringify(newManifest));
        workspacesManifestConvertor = {
          ...workspacesManifestConvertor,
          [workspace.internal_id]: newEncodedManifest,
        };
      }
    });

  const workspacesUpdateQuery = {
    script: {
      params: { convertor: workspacesManifestConvertor },
      source: 'if (params.convertor.containsKey(ctx._source.internal_id)) { ctx._source.manifest = params.convertor[ctx._source.internal_id]; }',
    },
    query: {
      bool: {
        should: [
          {
            bool: {
              must: [{ term: { 'entity_type.keyword': { value: 'Workspace' } } }],
            }
          },
        ],
        minimum_should_match: 1,
      },
    }
  };
  await elUpdateByQueryForMigration(
    '[MIGRATION] Workspaces filters refacto',
    READ_DATA_INDICES,
    workspacesUpdateQuery
  ).catch((err) => {
    throw DatabaseError('Error updating elastic', { error: err });
  });

  // 04. Playbooks
  const playbooks = await listAllEntities(
    context,
    SYSTEM_USER,
    [ENTITY_TYPE_PLAYBOOK],
  );

  let playbooksDefinitionConvertor = {};
  playbooks
    .forEach((playbook) => {
      const playbookDefinition = JSON.parse(playbook.playbook_definition);
      const definitionNodes = playbookDefinition.nodes;
      const newDefinitionNodes = [];
      for (let i = 0; i < definitionNodes.length; i += 1) {
        const node = definitionNodes[i];
        const nodeConfiguration = JSON.parse(node.configuration);
        const { filters } = nodeConfiguration;
        if (filters) {
          const newFilters = convertFilters(filters);
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
    '[MIGRATION] Playbooks filters refacto',
    READ_DATA_INDICES,
    playbooksUpdateQuery
  ).catch((err) => {
    throw DatabaseError('Error updating elastic', { error: err });
  });

  logApp.info(`${message} > done`);
  next();
};

export const down = async (next) => {
  next();
};
