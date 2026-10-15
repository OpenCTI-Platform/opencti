import type { FilterDefinition } from '../../utils/hooks/useAuth';
import { entityTypesFilters } from '../../utils/filters/filtersUtils';
import type { FilterOptionValue } from '@components/common/lists/FilterAutocomplete';
import type { DashboardVariable, DashboardVariableType } from './dashboard-types';
import { toVariableToken } from './dashboardVariablesResolution';

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
      // Subtype rule: one of the variable entity types must be the type of the filter domain or one of its subtypes.
      // Every value the variable can hold is then a valid value of the filter. A variable of an abstract parent type
      // (e.g. Stix-Domain-Object) is NOT offered on a narrower filter (e.g. createdBy, on Identity): it could hold a
      // Malware, which that filter cannot take. Pinned by compatibility-cases.json.
      return filterDefinition.type === 'id'
        // An id filter whose domain is empty accepts any entity (e.g. `objects`, "Contains"): no type to intersect with.
        && (domain.length === 0 || variable.entityTypes.some((type) => domain.some((d) => helpers.isSubTypeOf(type, d))));
    default: {
      const entityType = ID_VARIABLE_ENTITY_TYPE[variable.type];
      return filterDefinition.type === 'id' && !!entityType && domain.includes(entityType);
    }
  }
};

// Group of the variable options in a filter value list; translated where the list is rendered (key in lang/front).
export const VARIABLES_OPTION_GROUP = 'Variables';

/**
 * Options offering the variables compatible with a filter: picking one adds the variable token as filter value.
 */
export const getVariableOptions = (
  variables: DashboardVariable[],
  filterDefinition: FilterDefinition | undefined,
  helpers: { isSubTypeOf: (type: string, parent: string) => boolean },
): FilterOptionValue[] => variables
  .filter((variable) => isVariableCompatibleWithFilter(variable, filterDefinition, helpers))
  .map((variable) => ({
    value: toVariableToken(variable.id),
    label: variable.name,
    type: 'Variable',
    group: VARIABLES_OPTION_GROUP,
    parentTypes: [],
  }));
