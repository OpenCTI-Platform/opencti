import * as R from 'ramda';
import type { AuthContext, AuthUser } from '../../types/user';
import { isNotEmptyField } from '../../database/utils';
import type { Filter, FilterGroup } from '../../generated/graphql';
import type { BasicStoreObject } from '../../types/store';
import { internalFindByIds } from '../../database/middleware-loader';
import { INSTANCE_REGARDING_OF } from '../../utils/filtering/filtering-constants';
import { isInternalId, isStixId } from '../../schema/schemaUtils';

// workspace ids converter
// Export => Dashboard filter ids must be converted to standard id
// Import => Dashboards filter ids must be converted back to internal id

const toKeys = (k: string | string[]) => (Array.isArray(k) ? k : [k]);

const filterValuesRemap = (filter: Filter, resolvedMap: { [k: string]: BasicStoreObject }, from: 'internal' | 'stix') => {
  return filter.values.map((value) => {
    if (from === 'internal' && isInternalId(value)) {
      return resolvedMap[value]?.standard_id ?? value;
    }
    if (from === 'stix' && isStixId(value)) {
      return resolvedMap[value]?.internal_id ?? value;
    }
    return value;
  });
};

const extractFiltersIds = (filter: FilterGroup, from: 'internal' | 'stix') => {
  const internalIds: string[] = [];
  filter.filters.forEach((f) => {
    let innerValues = f.values;
    if (toKeys(f.key).includes(INSTANCE_REGARDING_OF)) {
      innerValues = innerValues.find((v) => toKeys(v.key).includes('id'))?.values ?? [];
    }
    const ids = innerValues.filter((value) => {
      if (from === 'internal') return isInternalId(value);
      return isStixId(value);
    });
    internalIds.push(...ids);
  });
  filter.filterGroups.forEach((group) => {
    const groupIds = extractFiltersIds(group, from);
    internalIds.push(...groupIds);
  });
  return R.uniq(internalIds);
};

const replaceFiltersIds = (filter: FilterGroup, resolvedMap: { [k: string]: BasicStoreObject }, from: 'internal' | 'stix') => {
  filter.filters.forEach((f) => {
    // Explicit reassign working by references
    if (toKeys(f.key).includes(INSTANCE_REGARDING_OF)) {
      const regardingOfValues = [];
      const idInnerFilter = f.values.find((v) => toKeys(v.key).includes('id'));
      if (idInnerFilter) { // Id is not mandatory
        idInnerFilter.values = filterValuesRemap(idInnerFilter, resolvedMap, from);
        regardingOfValues.push(idInnerFilter);
      }
      const typeInnerFilter = f.values.find((v) => toKeys(v.key).includes('type'));
      if (typeInnerFilter) { // Type is not mandatory
        regardingOfValues.push(typeInnerFilter);
      }
      // eslint-disable-next-line no-param-reassign
      f.values = regardingOfValues;
    } else {
      // eslint-disable-next-line no-param-reassign
      f.values = filterValuesRemap(f, resolvedMap, from);
    }
  });
  filter.filterGroups.forEach((group) => {
    replaceFiltersIds(group, resolvedMap, from);
  });
};

export const convertWidgetsIds = async (context: AuthContext, user: AuthUser, widgetDefinitions: any[], from: 'internal' | 'stix') => {
  // First iteration to resolve all ids to translate
  const resolvingIds: string[] = [];
  widgetDefinitions.forEach((widgetDefinition: any) => {
    widgetDefinition.dataSelection.forEach((selection: any) => {
      if (isNotEmptyField(selection.filters)) {
        const filterIds = extractFiltersIds(selection.filters as FilterGroup, from);
        resolvingIds.push(...filterIds);
      }
      if (isNotEmptyField(selection.dynamicFrom)) {
        const dynamicFromIds = extractFiltersIds(selection.dynamicFrom as FilterGroup, from);
        resolvingIds.push(...dynamicFromIds);
      }
      if (isNotEmptyField(selection.dynamicTo)) {
        const dynamicToIds = extractFiltersIds(selection.dynamicTo as FilterGroup, from);
        resolvingIds.push(...dynamicToIds);
      }
    });
  });
  // Resolve then second iteration to replace the ids
  const resolveOpts = { baseData: true, toMap: true, mapWithAllIds: true };
  const resolvedMap = await internalFindByIds(context, user, resolvingIds, resolveOpts);
  const idsMap = resolvedMap as unknown as { [k: string]: BasicStoreObject };
  widgetDefinitions.forEach((widgetDefinition: any) => {
    widgetDefinition.dataSelection.forEach((selection: any) => {
      if (isNotEmptyField(selection.filters)) {
        replaceFiltersIds(selection.filters as FilterGroup, idsMap, from);
      }
      if (isNotEmptyField(selection.dynamicFrom)) {
        replaceFiltersIds(selection.dynamicFrom as FilterGroup, idsMap, from);
      }
      if (isNotEmptyField(selection.dynamicTo)) {
        replaceFiltersIds(selection.dynamicTo as FilterGroup, idsMap, from);
      }
    });
  });
};
