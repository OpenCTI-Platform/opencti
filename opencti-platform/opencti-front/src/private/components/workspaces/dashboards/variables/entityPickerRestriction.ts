import { FilterGroup } from '../../../../../utils/filters/filtersHelpers-types';
import { isFilterGroupFormatCorrect, isFilterGroupNotEmpty, removeFrontendIdAndEmptyFiltersFromFilterGroupObject } from '../../../../../utils/filters/filtersUtils';

export type EntityPickerRestrictionMode = 'no_restriction' | 'filter' | 'selection';

interface EntityPickerRestrictionPayload {
  mode: Exclude<EntityPickerRestrictionMode, 'no_restriction'>;
  defaultEntityId: string;
  filterGroup?: FilterGroup;
  selectedEntityIds?: string[];
}

export interface ParsedEntityPickerRestriction {
  mode: EntityPickerRestrictionMode;
  defaultEntityId: string;
  filterGroup?: FilterGroup;
  selectedEntityIds: string[];
}

const isMode = (value: unknown): value is Exclude<EntityPickerRestrictionMode, 'no_restriction'> => {
  return value === 'filter' || value === 'selection';
};

const toValidFilterGroup = (value: unknown): FilterGroup | undefined => {
  if (!isFilterGroupFormatCorrect(value)) {
    return undefined;
  }
  return value as FilterGroup;
};

export const parseEntityPickerRestriction = (value: string | null | undefined): ParsedEntityPickerRestriction | null => {
  if (!value) {
    return null;
  }

  try {
    const parsed = JSON.parse(value) as EntityPickerRestrictionPayload;
    if (!parsed || typeof parsed !== 'object') {
      return { mode: 'no_restriction', defaultEntityId: value, selectedEntityIds: [value] };
    }

    if (!isMode(parsed.mode) || typeof parsed.defaultEntityId !== 'string' || parsed.defaultEntityId.length === 0) {
      return { mode: 'no_restriction', defaultEntityId: value, selectedEntityIds: [value] };
    }

    const selectedEntityIds = Array.isArray(parsed.selectedEntityIds)
      ? parsed.selectedEntityIds.filter((entityId): entityId is string => typeof entityId === 'string' && entityId.length > 0)
      : [];

    return {
      mode: parsed.mode,
      defaultEntityId: parsed.defaultEntityId,
      filterGroup: toValidFilterGroup(parsed.filterGroup),
      selectedEntityIds: selectedEntityIds.length > 0 ? selectedEntityIds : [parsed.defaultEntityId],
    };
  } catch {
    return { mode: 'no_restriction', defaultEntityId: value, selectedEntityIds: [value] };
  }
};

export const serializeEntityPickerRestriction = (
  mode: EntityPickerRestrictionMode,
  noRestrictionDefaultEntityId: string | null | undefined,
  filterModeDefaultEntityId: string | null | undefined,
  filterModeFilterGroup: FilterGroup,
  selectModeEntityIds: string[],
): string | null => {
  if (mode === 'no_restriction') {
    return noRestrictionDefaultEntityId || null;
  }

  if (mode === 'filter') {
    if (!filterModeDefaultEntityId) {
      return null;
    }
    const payload: EntityPickerRestrictionPayload = {
      mode: 'filter',
      defaultEntityId: filterModeDefaultEntityId,
      ...(isFilterGroupNotEmpty(filterModeFilterGroup)
        ? { filterGroup: removeFrontendIdAndEmptyFiltersFromFilterGroupObject(filterModeFilterGroup) }
        : {}),
    };
    return JSON.stringify(payload);
  }

  const cleanedEntityIds = selectModeEntityIds.filter((entityId) => !!entityId);
  if (cleanedEntityIds.length === 0) {
    return null;
  }

  const payload: EntityPickerRestrictionPayload = {
    mode: 'selection',
    defaultEntityId: cleanedEntityIds[0],
    selectedEntityIds: cleanedEntityIds,
  };
  return JSON.stringify(payload);
};