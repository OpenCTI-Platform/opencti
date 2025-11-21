import * as R from 'ramda';
import type { AuthContext, AuthUser } from '../../types/user';
import type { Filter, FilterGroup } from '../../generated/graphql';
import type { BasicStoreObject } from '../../types/store';
import { internalFindByIds } from '../../database/middleware-loader';
import { INSTANCE_REGARDING_OF } from '../../utils/filtering/filtering-constants';
import { isInternalId, isStixId } from '../../schema/schemaUtils';
import { idsValuesRemap } from '../../database/stix-2-1-converter';
import { isFilterGroupNotEmpty } from '../../utils/filtering/filtering-utils';

// workspace ids converter_2_1
// Export => Dashboard filter ids must be converted to standard id
// Import => Dashboards filter ids must be converted back to internal id

const toKeys = (k: string | string[]) => (Array.isArray(k) ? k : [k]);

const filterValuesRemap = (filter: Filter, resolvedMap: { [k: string]: BasicStoreObject }, from: 'internal' | 'stix') => {
  return idsValuesRemap(filter.values, resolvedMap, from);
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
      const typeInnerFilter = f.values.find((v) => toKeys(v.key).includes('relationship_type'));
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
  // First iteration: resolve all the ids to translate
  const resolvingIds: string[] = [];
  widgetDefinitions.forEach((widgetDefinition: any) => {
    widgetDefinition.dataSelection.forEach((selection: any) => {
      if (isFilterGroupNotEmpty(selection.filters)) {
        const filterIds = extractFiltersIds(selection.filters as FilterGroup, from);
        resolvingIds.push(...filterIds);
      }
      if (isFilterGroupNotEmpty(selection.dynamicFrom)) {
        const dynamicFromIds = extractFiltersIds(selection.dynamicFrom as FilterGroup, from);
        resolvingIds.push(...dynamicFromIds);
      }
      if (isFilterGroupNotEmpty(selection.dynamicTo)) {
        const dynamicToIds = extractFiltersIds(selection.dynamicTo as FilterGroup, from);
        resolvingIds.push(...dynamicToIds);
      }
    });
  });
  // Second iteration: replace the ids
  const resolveOpts = { baseData: true, toMap: true, mapWithAllIds: true };
  const resolvedMap = await internalFindByIds(context, user, resolvingIds, resolveOpts);
  const idsMap = resolvedMap as unknown as { [k: string]: BasicStoreObject };
  widgetDefinitions.forEach((widgetDefinition: any) => {
    widgetDefinition.dataSelection.forEach((selection: any) => {
      if (isFilterGroupNotEmpty(selection.filters)) {
        replaceFiltersIds(selection.filters as FilterGroup, idsMap, from);
      }
      if (isFilterGroupNotEmpty(selection.dynamicFrom)) {
        replaceFiltersIds(selection.dynamicFrom as FilterGroup, idsMap, from);
      }
      if (isFilterGroupNotEmpty(selection.dynamicTo)) {
        replaceFiltersIds(selection.dynamicTo as FilterGroup, idsMap, from);
      }
    });
  });
};
