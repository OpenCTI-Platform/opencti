import type { FilterDefinition } from '../hooks/useAuth';
import { getFilterDefinitionFromFilterKeysMap } from './filtersUtils';

const WORKFLOW_FILTER_KEYS = ['workflow_user', 'workflow_group', 'workflow_organization'];

export interface GroupedFilterKeyOption {
  value: string;
  label: string;
  groupLabel?: string;
  groupOrder?: number;
}

/**
 * Whether the "add filter" key picker should bucket its options into groups (Workflow / Draft /
 * Most used / All other) instead of a flat alphabetical list — true for a generic abstract entity
 * type or several entity types at once, where the schema mixes keys of very different relevance.
 * Shared so the root filter bar (`ListFilters`) and the nested filter-group row (`FilterRow`)
 * group the exact same way instead of drifting apart.
 */
export const isGroupedFilterKeySelection = (entityTypes: string[]): boolean => (
  (entityTypes.length === 1 && ['Stix-Core-Object', 'Stix-Domain-Object', 'Stix-Cyber-Observable', 'Container'].includes(entityTypes[0]))
  || entityTypes.length > 1
);

/**
 * Builds the `availableFilterKeys` options for a key picker, grouped and ordered like the root
 * filter bar when `isGroupedFilterKeySelection(entityTypes)` holds, flat and alphabetical
 * otherwise. `t_i18n` is injected (not called here as a hook) so this stays a plain function
 * usable from any component.
 */
export const buildGroupedFilterKeyOptions = (
  availableFilterKeys: string[],
  entityTypes: string[],
  filterKeysMap: Map<string, FilterDefinition>,
  t_i18n: (s: string) => string,
): GroupedFilterKeyOption[] => {
  const isFilterKeyForAllTypes = (subEntityTypes: string[]): boolean => (
    (entityTypes.length === 1 && subEntityTypes.some((subType) => entityTypes.includes(subType)))
    || (entityTypes.length > 1 && entityTypes.every((subType) => subEntityTypes.includes(subType)))
  );

  const getGroupLabel = (key: string, filterDefinition: ReturnType<typeof getFilterDefinitionFromFilterKeysMap>): string => {
    const subEntityTypes = filterDefinition?.subEntityTypes ?? [];
    const isDraftSpecificKey = subEntityTypes.length > 0 && subEntityTypes.every((t) => t === 'DraftWorkspace');
    if (isDraftSpecificKey) return t_i18n('Draft filters');
    if (WORKFLOW_FILTER_KEYS.includes(key)) return t_i18n('Workflow filters');
    if (isFilterKeyForAllTypes(subEntityTypes)) return t_i18n('Most used filters');
    return t_i18n('All other filters');
  };

  const getGroupOrder = (key: string, filterDefinition: ReturnType<typeof getFilterDefinitionFromFilterKeysMap>): number => {
    const subEntityTypes = filterDefinition?.subEntityTypes ?? [];
    const isDraftSpecificKey = subEntityTypes.length > 0 && subEntityTypes.every((t) => t === 'DraftWorkspace');
    if (WORKFLOW_FILTER_KEYS.includes(key)) return 1;
    if (isDraftSpecificKey) return 2;
    if (isFilterKeyForAllTypes(subEntityTypes)) return 3;
    return 0;
  };

  if (!isGroupedFilterKeySelection(entityTypes)) {
    return availableFilterKeys
      .map((key) => ({
        value: key,
        label: t_i18n(getFilterDefinitionFromFilterKeysMap(key, filterKeysMap)?.label ?? key),
      }))
      .sort((a, b) => a.label.localeCompare(b.label));
  }

  return availableFilterKeys
    .map((key) => {
      const filterDefinition = getFilterDefinitionFromFilterKeysMap(key, filterKeysMap);
      return {
        value: key,
        label: t_i18n(filterDefinition?.label ?? key),
        groupLabel: getGroupLabel(key, filterDefinition),
        groupOrder: getGroupOrder(key, filterDefinition),
      };
    })
    .sort((a, b) => a.label.localeCompare(b.label))
    .sort((a, b) => (b.groupOrder ?? 0) - (a.groupOrder ?? 0)); // 'Most used filters' before 'All other filters'
};
