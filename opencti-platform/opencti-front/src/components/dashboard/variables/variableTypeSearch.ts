import type { DashboardVariableType } from '../dashboard-types';
import type { FilterSearchContext } from '../../../utils/filters/filtersUtils';

// Variable types whose values are entity ids: their labels are resolved through the filters representatives.
export const ID_VARIABLE_TYPES: readonly DashboardVariableType[] = ['entity', 'label', 'marking', 'user', 'group', 'status', 'killChainPhase'];

export const isIdVariableType = (type: DashboardVariableType) => ID_VARIABLE_TYPES.includes(type);

// The schema keys below (objectLabel, objectMarking, workflow_id, killChainPhases) are Stix-Core-Object keys.
export const VARIABLE_SEARCH_CONTEXT: FilterSearchContext = { entityTypes: ['Stix-Core-Object'] };

/**
 * Filter key handed to `useSearchEntities` to list the candidate values of a variable type.
 * Each key is checked in variableTypeSearch.test.tsx against the back filter keys schema and the query it runs.
 * `members_user`, `members_group`, `id` and `entity_type` have a search of their own in `useSearchEntities`:
 * every platform user / group, every entity of the search scope, every type of the schema.
 */
export const VARIABLE_TYPE_SEARCH: Partial<Record<DashboardVariableType, string>> = {
  entity: 'id',
  label: 'objectLabel',
  marking: 'objectMarking',
  user: 'members_user',
  group: 'members_group',
  status: 'workflow_id',
  killChainPhase: 'killChainPhases',
  entityType: 'entity_type',
};
