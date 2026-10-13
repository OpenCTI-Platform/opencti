import type { FilterDefinition } from '../../utils/hooks/useAuth';
import { entityTypesFilters } from '../../utils/filters/filtersUtils';
import type { DashboardVariable, DashboardVariableType } from './dashboard-types';

// Values read from the back schema (schema/internalObject.ts, schema/stixMetaObject.ts): do not invent other literals.
const ID_VARIABLE_ENTITY_TYPE: Partial<Record<DashboardVariableType, string>> = {
  user: 'User',
  label: 'Label',
  marking: 'Marking-Definition',
  status: 'StatusTemplate',
  group: 'Group',
  killChainPhase: 'Kill-Chain-Phase',
};

/**
 * Whether a dashboard variable can be bound to a filter (a filter value can be replaced by the variable token).
 * Mirrors the compatibility table of the spec: the variable type must match the filter definition type and,
 * for id/vocabulary filters, the entity types / vocabulary category exposed by `elementsForFilterValuesSearch`.
 */
export const isVariableCompatibleWithFilter = (
  variable: DashboardVariable,
  filterDefinition: FilterDefinition | undefined,
  helpers: { isSubTypeOf: (type: string, parent: string) => boolean },
): boolean => {
  if (!filterDefinition) return false;
  const domain = filterDefinition.elementsForFilterValuesSearch ?? [];
  switch (variable.type) {
    case 'boolean': return filterDefinition.type === 'boolean';
    case 'date': return filterDefinition.type === 'date';
    case 'numeric': return filterDefinition.type === 'integer' || filterDefinition.type === 'float';
    case 'text': return filterDefinition.type === 'string' || filterDefinition.type === 'text';
    case 'entityType': return filterDefinition.type === 'string' && entityTypesFilters.includes(filterDefinition.filterKey);
    case 'vocabulary':
      // For a vocabulary filter, the back exposes the category as the only element of elementsForFilterValuesSearch.
      return filterDefinition.type === 'vocabulary' && domain.includes(variable.vocabularyCategory);
    case 'entity':
      return filterDefinition.type === 'id'
        && variable.entityTypes.some((type) => domain.some((d) => helpers.isSubTypeOf(type, d)));
    default: {
      const entityType = ID_VARIABLE_ENTITY_TYPE[variable.type];
      return filterDefinition.type === 'id' && !!entityType && domain.includes(entityType);
    }
  }
};
