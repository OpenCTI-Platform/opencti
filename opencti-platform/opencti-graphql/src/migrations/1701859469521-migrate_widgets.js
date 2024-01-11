import { listAllEntities } from '../database/middleware-loader';
import { executionContext, SYSTEM_USER } from '../utils/access';
import { ENTITY_TYPE_WORKSPACE } from '../modules/workspace/workspace-types';
import { fromBase64, isNotEmptyField, READ_DATA_INDICES, toBase64 } from '../database/utils';
import { elUpdateByQueryForMigration } from '../database/engine';

const keyFilterFinder = (filters, keyToFind) => {
  return filters.filters.find((f) => {
    const keys = Array.isArray(f.key) ? f.key : [f.key];
    return keys.includes(keyToFind);
  });
};

const keyFilterRemover = (filters, keysToRemove) => {
  return filters.filters.filter((f) => {
    const keys = Array.isArray(f.key) ? f.key : [f.key];
    return !keys.some((k) => keysToRemove.includes(k));
  });
};

const convertFilters = (filters, perspective) => {
  if (filters && perspective === 'entities') {
    const elementIdFilter = keyFilterFinder(filters, 'elementId');
    const relationshipTypeIdFilter = keyFilterFinder(filters, 'relationship_type');
    if (elementIdFilter || relationshipTypeIdFilter) {
      const newFilters = keyFilterRemover(filters, ['elementId', 'relationship_type']);
      const regardingOfValues = [];
      if (elementIdFilter && isNotEmptyField(elementIdFilter.values)) {
        regardingOfValues.push({ key: 'id', values: elementIdFilter.values });
      }
      if (relationshipTypeIdFilter && isNotEmptyField(relationshipTypeIdFilter.values)) {
        regardingOfValues.push({ key: 'type', values: relationshipTypeIdFilter.values });
      }
      if (regardingOfValues.length > 0) {
        newFilters.push({
          key: 'regardingOf',
          mode: 'and',
          values: regardingOfValues,
        });
      }
      return {
        mode: filters.mode,
        filters: newFilters,
        filterGroups: filters.filterGroups
      };
    }
  }
  return filters;
};

export const up = async (next) => {
  const context = executionContext('migration', SYSTEM_USER);
  const workspaces = await listAllEntities(context, SYSTEM_USER, [ENTITY_TYPE_WORKSPACE]);
  let workspacesManifestConvertor = {};
  workspaces.forEach((workspace) => {
    if (isNotEmptyField(workspace.manifest)) {
      const decodedManifest = JSON.parse(fromBase64(workspace.manifest));
      const { widgets } = decodedManifest;
      const widgetEntries = Object.entries(widgets);
      const newWidgets = {};
      for (let i = 0; i < widgetEntries.length; i += 1) {
        const [key, value] = widgetEntries[i];
        const { dataSelection } = value;
        if (dataSelection) {
          const newDataSelection = dataSelection.map((selection) => {
            const { perspective, filters = null, dynamicFrom = null, dynamicTo = null } = selection;
            const newFilters = convertFilters(filters, perspective);
            const newDynamicFrom = convertFilters(dynamicFrom, 'entities');
            const newDynamicTo = convertFilters(dynamicTo, 'entities');
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
        } else {
          newWidgets[key] = {
            ...value,
          };
        }
      }
      const newManifest = { ...decodedManifest, widgets: newWidgets };
      const newEncodedManifest = toBase64(JSON.stringify(newManifest));
      workspacesManifestConvertor = { ...workspacesManifestConvertor, [workspace.internal_id]: newEncodedManifest };
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
    '[MIGRATION] Migrate widgets',
    READ_DATA_INDICES,
    workspacesUpdateQuery
  );
  next();
};

export const down = async (next) => {
  next();
};
