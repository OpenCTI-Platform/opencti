import type { DimensionalGaugeItem } from '../../telemetry/TelemetryMeterManager';
import type { FilterGroup } from '../../generated/graphql';
import { extractFilterKeys } from '../../utils/filtering/filtering-utils';
import { fromB64 } from '../../utils/base64';
import { type BasicStoreEntityCustomFieldDefinition, CUSTOM_FIELD_PREFIX, CUSTOM_FIELD_TYPES } from './custom-field-types';

// Filters are stored either as a FilterGroup or as its JSON string (saved filters).
// A malformed value is considered as not using any custom field.
export const isFilterGroupUsingCustomField = (filters: unknown): boolean => {
  if (filters === null || filters === undefined || filters === '') {
    return false;
  }
  try {
    const filterGroup = (typeof filters === 'string' ? JSON.parse(filters) : filters) as FilterGroup;
    return extractFilterKeys(filterGroup).some((key) => key.startsWith(CUSTOM_FIELD_PREFIX));
  } catch {
    return false;
  }
};

// A dashboard manifest is a base64 JSON whose widgets hold their filters in dataSelection.
export const isDashboardManifestUsingCustomField = (manifest: string | null | undefined): boolean => {
  if (!manifest) {
    return false;
  }
  try {
    const { widgets } = fromB64(manifest);
    return Object.values(widgets ?? {}).some((widget: any) => (widget?.dataSelection ?? []).some((selection: any) => (
      isFilterGroupUsingCustomField(selection?.filters)
      || isFilterGroupUsingCustomField(selection?.dynamicFrom)
      || isFilterGroupUsingCustomField(selection?.dynamicTo)
    )));
  } catch {
    return false;
  }
};

export const buildCustomFieldsTelemetryItems = (definitions: BasicStoreEntityCustomFieldDefinition[]) => {
  const countByEntityType = new Map<string, number>();
  definitions.forEach((definition) => {
    (definition.entity_types ?? []).forEach((entityType) => {
      countByEntityType.set(entityType, (countByEntityType.get(entityType) ?? 0) + 1);
    });
  });
  const byEntityType: DimensionalGaugeItem[] = Array.from(countByEntityType.entries())
    .map(([entity_type, value]) => ({ value, attributes: { entity_type } }));
  // Bounded dimension: every field type is reported, including the unused ones
  const byFieldType: DimensionalGaugeItem[] = CUSTOM_FIELD_TYPES
    .map((field_type) => ({ value: definitions.filter((d) => d.field_type === field_type).length, attributes: { field_type } }));
  return { byEntityType, byFieldType };
};
