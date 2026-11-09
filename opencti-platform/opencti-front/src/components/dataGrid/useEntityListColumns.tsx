import { useMemo } from 'react';
import useAuth, { FilterDefinition } from '../../utils/hooks/useAuth';
import { getCustomFieldRawValueByFieldName, isCustomFieldAttribute } from '../../utils/customFields';
import { defaultColumnsMap, defaultRender } from './dataTableUtils';
import type { DataTableColumn, DataTableProps } from './dataTableTypes';

// Attributes of the data model whose column in the lists has another id.
const ATTRIBUTE_TO_COLUMN: Record<string, string> = {
  creator_id: 'creator',
  workflow_id: 'x_opencti_workflow_id',
};

// Kind of value of an attribute, displayed next to its name when managing columns.
const SPECIFIC_TYPE_LABELS: Record<string, string> = {
  name: 'Text',
  objectLabel: 'Labels',
  objectMarking: 'Markings',
  workflow_id: 'Status',
};

const getTypeLabel = (attribute: string, definition?: FilterDefinition) => {
  if (SPECIFIC_TYPE_LABELS[attribute]) return SPECIFIC_TYPE_LABELS[attribute];
  switch (definition?.type) {
    case 'date':
      return 'Date';
    case 'integer':
    case 'float':
      return 'Number';
    case 'boolean':
      return 'Boolean';
    case 'id':
      return definition.multiple ? 'References' : 'Reference';
    case 'enum':
    case 'vocabulary':
      return 'Enum';
    case 'string':
    case 'text':
      return 'Text';
    default:
      return undefined;
  }
};

// A custom field is rendered from the custom field values of the entity, in the formats of the platform.
const buildCustomFieldColumn = (attribute: string, definition: FilterDefinition): Partial<DataTableColumn> => ({
  id: attribute,
  label: definition.label,
  percentWidth: 12,
  isSortable: false,
  typeLabel: getTypeLabel(attribute, definition),
  render: (data, helpers) => {
    const value = getCustomFieldRawValueByFieldName(data.customFieldValues, attribute);
    if (typeof value === 'boolean') return defaultRender(helpers.t_i18n(value ? 'True' : 'False'));
    if (definition.type === 'date' && typeof value === 'string') return defaultRender(helpers.ftd(value));
    return defaultRender(value);
  },
});

/**
 * Columns of the list of an entity type, from its data model: the default ones of the list,
 * and every attribute of the type that can be added (including custom fields).
 * An attribute is offered when the list knows how to render it; it is sortable only if the list can sort on it.
 */
const useEntityListColumns = (
  entityType: string,
  dataColumns: DataTableProps['dataColumns'],
  sortableColumnIds: readonly string[],
) => {
  const { schema: { filterKeysSchema } } = useAuth();
  const attributes = filterKeysSchema.get(entityType);

  return useMemo(() => {
    const definitionsByColumn = new Map<string, { attribute: string; definition: FilterDefinition }>();
    attributes?.forEach((definition, attribute) => {
      definitionsByColumn.set(ATTRIBUTE_TO_COLUMN[attribute] ?? attribute, { attribute, definition });
    });

    const typedDataColumns = Object.fromEntries(Object.entries(dataColumns).map(([id, column]) => {
      const { attribute, definition } = definitionsByColumn.get(id) ?? { attribute: id };
      return [id, { ...column, typeLabel: getTypeLabel(attribute, definition) }];
    }));

    const availableColumns: DataTableProps['dataColumns'] = {};
    definitionsByColumn.forEach(({ attribute, definition }, id) => {
      if (dataColumns[id]) return;
      if (isCustomFieldAttribute(attribute)) {
        availableColumns[id] = buildCustomFieldColumn(attribute, definition);
        return;
      }
      const registeredColumn = defaultColumnsMap.get(id);
      if (!registeredColumn?.render) return;
      availableColumns[id] = {
        label: registeredColumn.label,
        typeLabel: getTypeLabel(attribute, definition),
        isSortable: !!registeredColumn.isSortable && sortableColumnIds.includes(id),
      };
    });
    return { dataColumns: typedDataColumns, availableColumns };
  }, [attributes, dataColumns]);
};

export default useEntityListColumns;
