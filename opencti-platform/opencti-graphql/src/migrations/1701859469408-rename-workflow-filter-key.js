import { uniq } from 'ramda';
import { executionContext, SYSTEM_USER } from '../utils/access';
import { listAllEntities } from '../database/middleware-loader';
import { ENTITY_TYPE_BACKGROUND_TASK, ENTITY_TYPE_FEED, ENTITY_TYPE_RETENTION_RULE, ENTITY_TYPE_STREAM_COLLECTION, ENTITY_TYPE_TAXII_COLLECTION } from '../schema/internalObject';
import { ENTITY_TYPE_TRIGGER } from '../modules/notification/notification-types';
import { logApp } from '../config/conf';
import { fromBase64, isNotEmptyField, READ_DATA_INDICES, toBase64 } from '../database/utils';
import { elUpdateByQueryForMigration } from '../database/engine';
import { DatabaseError } from '../config/errors';
import { ENTITY_TYPE_WORKSPACE } from '../modules/workspace/workspace-types';
import { ENTITY_TYPE_PLAYBOOK } from '../modules/playbook/playbook-types';
import { isFilterGroupNotEmpty } from '../utils/filtering/filtering-utils';

const message = '[MIGRATION] Rename workflow filter key';

export const up = async (next) => {
  logApp.info(`${message} > started`);
  const context = executionContext('migration', SYSTEM_USER);

  const convertWorkflowFilterKeys = (inputFilters, alreadyParsed = false) => {
    let newFilters = { // empty filter group
      mode: 'and',
      filters: [],
      filterGroups: [],
    };
    if (inputFilters) {
      const parsedFilters = alreadyParsed ? inputFilters : JSON.parse(inputFilters);
      if (isFilterGroupNotEmpty(parsedFilters)) {
        const { filters, filterGroups } = parsedFilters;
        const newFiltersContent = [];
        const newFilterGroups = [];
        filters.forEach((filter) => {
          const { key } = filter;
          const arrayKeys = Array.isArray(key) ? key : [key];
          if (arrayKeys.includes('x_opencti_workflow_id')) {
            const newKeys = arrayKeys.filter((k) => k !== 'x_opencti_workflow_id');
            newKeys.push('workflow_id');
            newFiltersContent.push({ ...filter, key: uniq(newKeys) });
          } else {
            newFiltersContent.push(filter);
          }
        });
        filterGroups.forEach((group) => {
          const newGroup = convertWorkflowFilterKeys(group, true);
          newFilterGroups.push(newGroup);
        });
        newFilters = {
          mode: parsedFilters.mode,
          filters: newFiltersContent,
          filterGroups: newFilterGroups,
        };
      }
    }
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
      entitiesFiltersConvertor = {
        ...entitiesFiltersConvertor,
        [n.internal_id]: convertWorkflowFilterKeys(n.filters, false),
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
    '[MIGRATION] Rename workflow filter key for triggers, taxii, feeds, streams and retention rules',
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
      },
      noFiltersChecking: true
    }
  );

  let tasksFiltersConvertor = {};
  tasks
    .filter((task) => task.task_filters)
    .forEach((task) => {
      tasksFiltersConvertor = {
        ...tasksFiltersConvertor,
        [task.internal_id]: convertWorkflowFilterKeys(task.task_filters),
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
    '[MIGRATION] Rename workflow filter key for query tasks',
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
      if (isNotEmptyField(workspace.manifest)) {
        const decodedManifest = JSON.parse(fromBase64(workspace.manifest));
        const { widgets } = decodedManifest;
        const widgetEntries = Object.entries(widgets);
        const newWidgets = {};
        for (let i = 0; i < widgetEntries.length; i += 1) {
          const [key, value] = widgetEntries[i];
          const { dataSelection } = value;
          const newDataSelection = dataSelection.map((selection) => {
            const { filters = null, dynamicFrom = null, dynamicTo = null } = selection;
            const newFilters = convertWorkflowFilterKeys(filters, true);
            const newDynamicFrom = convertWorkflowFilterKeys(dynamicFrom, true);
            const newDynamicTo = convertWorkflowFilterKeys(dynamicTo, true);
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
        const newEncodedManifest = toBase64(JSON.stringify(newManifest));
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
    '[MIGRATION] Rename workflow filter key for workspaces',
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
      definitionNodes.forEach((node) => {
        const nodeConfiguration = JSON.parse(node.configuration);
        const { filters } = nodeConfiguration;
        if (filters) {
          const newFilters = convertWorkflowFilterKeys(filters);
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
      });
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
    '[MIGRATION] Rename workflow filter key for playbooks',
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
