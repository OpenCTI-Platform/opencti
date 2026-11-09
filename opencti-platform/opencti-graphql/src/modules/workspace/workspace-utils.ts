import * as R from 'ramda';
import type { AuthContext, AuthUser } from '../../types/user';
import type { Filter, FilterGroup } from '../../generated/graphql';
import type { BasicStoreObject } from '../../types/store';
import { internalFindByIds } from '../../database/middleware-loader';
import { INSTANCE_DYNAMIC_REGARDING_OF, INSTANCE_REGARDING_OF } from '../../utils/filtering/filtering-constants';
import { isInternalId, isStixId } from '../../schema/schemaUtils';
import { idsValuesRemap } from '../../database/stix-2-1-converter';
import { isFilterGroupNotEmpty } from '../../utils/filtering/filtering-utils';
import { pushAll } from '../../utils/arrayUtil';
import { DASHBOARD_VARIABLE_ID_TYPES, type StoreDashboardVariable } from './workspace-variables-types';

// workspace ids converter_2_1
// Export => Dashboard filter ids must be converted to standard id
// Import => Dashboards filter ids must be converted back to internal id

const toKeys = (k: string | string[]) => (Array.isArray(k) ? k : [k]);

const isRegardingOfKey = (key: string | string[]) => {
  const keys = toKeys(key);
  return keys.includes(INSTANCE_REGARDING_OF) || keys.includes(INSTANCE_DYNAMIC_REGARDING_OF);
};

const filterValuesRemap = (filter: Filter, resolvedMap: { [k: string]: BasicStoreObject }, from: 'internal' | 'stix') => {
  return idsValuesRemap(filter.values, resolvedMap, from);
};

const extractFiltersIds = (filter: FilterGroup, from: 'internal' | 'stix') => {
  const internalIds: string[] = [];
  filter.filters.forEach((f) => {
    let innerValues = f.values;
    if (isRegardingOfKey(f.key)) {
      innerValues = innerValues.find((v) => toKeys(v.key).includes('id'))?.values ?? [];
      // dynamicRegardingOf may contain a 'dynamic' subfilter with nested FilterGroups holding IDs
      const dynamicSubfilter = f.values.find((v) => toKeys(v.key).includes('dynamic'));
      if (dynamicSubfilter) {
        dynamicSubfilter.values.forEach((dynamicFilterGroup: any) => {
          if (isFilterGroupNotEmpty(dynamicFilterGroup)) {
            const nestedIds = extractFiltersIds(dynamicFilterGroup as FilterGroup, from);
            pushAll(internalIds, nestedIds);
          }
        });
      }
    }
    const ids = innerValues.filter((value) => {
      if (from === 'internal') return isInternalId(value);
      return isStixId(value);
    });
    pushAll(internalIds, ids);
  });
  filter.filterGroups.forEach((group) => {
    const groupIds = extractFiltersIds(group, from);
    pushAll(internalIds, groupIds);
  });
  return R.uniq(internalIds);
};

const replaceFiltersIds = (filter: FilterGroup, resolvedMap: { [k: string]: BasicStoreObject }, from: 'internal' | 'stix') => {
  filter.filters.forEach((f) => {
    // Explicit reassign working by references
    if (isRegardingOfKey(f.key)) {
      const regardingOfValues = [];
      const idInnerFilter = f.values.find((v) => toKeys(v.key).includes('id'));
      if (idInnerFilter) { // Id is not mandatory
        idInnerFilter.values = filterValuesRemap(idInnerFilter, resolvedMap, from);
        regardingOfValues.push(idInnerFilter);
      }
      const typeInnerFilter = f.values.find((v) => toKeys(v.key).includes('relationship_type'));
      if (typeInnerFilter) { // Type is not mandatory
        regardingOfValues.push(typeInnerFilter);
      }
      // dynamicRegardingOf may contain a 'dynamic' subfilter with nested FilterGroups holding IDs
      const dynamicSubfilter = f.values.find((v) => toKeys(v.key).includes('dynamic'));
      if (dynamicSubfilter) {
        dynamicSubfilter.values.forEach((dynamicFilterGroup: any) => {
          if (isFilterGroupNotEmpty(dynamicFilterGroup)) {
            replaceFiltersIds(dynamicFilterGroup as FilterGroup, resolvedMap, from);
          }
        });
        regardingOfValues.push(dynamicSubfilter);
      }
      f.values = regardingOfValues;
    } else {
      f.values = filterValuesRemap(f, resolvedMap, from);
    }
  });
  filter.filterGroups.forEach((group) => {
    replaceFiltersIds(group, resolvedMap, from);
  });
};

type IdsMap = { [k: string]: BasicStoreObject };

const SELECTION_FILTER_KEYS = ['filters', 'dynamicFrom', 'dynamicTo'] as const;

const resolveIdsMap = async (context: AuthContext, user: AuthUser, ids: string[]): Promise<IdsMap> => {
  if (ids.length === 0) return {};
  const resolveOpts = { baseData: true, toMap: true, mapWithAllIds: true };
  const resolvedMap = await internalFindByIds(context, user, R.uniq(ids), resolveOpts);
  return resolvedMap as unknown as IdsMap;
};

const extractWidgetsIds = (widgetDefinitions: any[], from: 'internal' | 'stix') => {
  const resolvingIds: string[] = [];
  widgetDefinitions.forEach((widgetDefinition: any) => {
    widgetDefinition.dataSelection.forEach((selection: any) => {
      SELECTION_FILTER_KEYS.forEach((key) => {
        if (isFilterGroupNotEmpty(selection[key])) {
          pushAll(resolvingIds, extractFiltersIds(selection[key] as FilterGroup, from));
        }
      });
    });
  });
  return resolvingIds;
};

const replaceWidgetsIds = (widgetDefinitions: any[], idsMap: IdsMap, from: 'internal' | 'stix') => {
  widgetDefinitions.forEach((widgetDefinition: any) => {
    widgetDefinition.dataSelection.forEach((selection: any) => {
      SELECTION_FILTER_KEYS.forEach((key) => {
        if (isFilterGroupNotEmpty(selection[key])) {
          replaceFiltersIds(selection[key] as FilterGroup, idsMap, from);
        }
      });
    });
  });
};

// Only the variables whose type references entities hold ids: a text value shaped like an id stays as is.
const idVariablesOf = (variables: StoreDashboardVariable[]) => variables.filter((variable) => DASHBOARD_VARIABLE_ID_TYPES.has(variable.type));

const extractDashboardVariablesIds = (variables: StoreDashboardVariable[], from: 'internal' | 'stix') => {
  const resolvingIds: string[] = [];
  const isConvertible = (value: string) => (from === 'internal' ? isInternalId(value) : isStixId(value));
  idVariablesOf(variables).forEach((variable) => {
    const { defaultValue, restriction } = variable;
    if (defaultValue && isConvertible(defaultValue)) resolvingIds.push(defaultValue);
    if (restriction.mode === 'selection') pushAll(resolvingIds, restriction.values.filter(isConvertible));
    if (restriction.mode === 'filters' && isFilterGroupNotEmpty(restriction.filters)) {
      pushAll(resolvingIds, extractFiltersIds(restriction.filters, from));
    }
  });
  return resolvingIds;
};

const replaceDashboardVariablesIds = (variables: StoreDashboardVariable[], idsMap: IdsMap, from: 'internal' | 'stix') => {
  idVariablesOf(variables).forEach((variable) => {
    const { restriction } = variable;
    if (variable.defaultValue) {
      [variable.defaultValue] = idsValuesRemap([variable.defaultValue], idsMap, from);
    }
    if (restriction.mode === 'selection') {
      // Two ids may resolve to one entity (merged entity, STIX id alias): a selection never holds a value twice.
      restriction.values = R.uniq(idsValuesRemap(restriction.values, idsMap, from));
    }
    if (restriction.mode === 'filters' && isFilterGroupNotEmpty(restriction.filters)) {
      replaceFiltersIds(restriction.filters, idsMap, from);
    }
  });
};

/**
 * Converts entity IDs within widget filter definitions between internal and STIX formats.
 * On export (from='internal'): internal IDs are replaced with standard STIX IDs.
 * On import (from='stix'): STIX IDs are replaced back with internal IDs.
 */
export const convertWidgetsIds = async (
  context: AuthContext,
  user: AuthUser,
  widgetDefinitions: any[],
  from: 'internal' | 'stix',
) => {
  // First iteration: resolve all the ids to translate
  const idsMap = await resolveIdsMap(context, user, extractWidgetsIds(widgetDefinitions, from));
  // Second iteration: replace the ids
  replaceWidgetsIds(widgetDefinitions, idsMap, from);
};

/**
 * Converts the entity ids of the widgets and of the dashboard variables of a dashboard between internal and STIX
 * formats, like convertWidgetsIds, with a single lookup for both: a variable default is usually one of the widget
 * filter values. The default and the selection of a variable go through the same map, so a default still belongs to
 * its selection afterwards.
 */
export const convertDashboardIds = async (
  context: AuthContext,
  user: AuthUser,
  widgetDefinitions: any[],
  variables: StoreDashboardVariable[],
  from: 'internal' | 'stix',
) => {
  const resolvingIds = [...extractWidgetsIds(widgetDefinitions, from), ...extractDashboardVariablesIds(variables, from)];
  const idsMap = await resolveIdsMap(context, user, resolvingIds);
  replaceWidgetsIds(widgetDefinitions, idsMap, from);
  replaceDashboardVariablesIds(variables, idsMap, from);
};
