import * as Yup from 'yup';
import type { CustomFieldsInputQuery$data } from '../private/components/common/custom_fields/__generated__/CustomFieldsInputQuery.graphql';
import { resolveCustomFieldDefaultValue } from './customFieldDefaults';
import type { WidgetColumn, WidgetColumnAttributeType } from './widget/widget';

export type CustomFieldDef = NonNullable<NonNullable<CustomFieldsInputQuery$data['customFieldDefinitionsForEntityType']>['edges']>[number]['node'];
export type CustomFieldValue = string | boolean | string[];
export type CustomFieldFormValues = Record<string, CustomFieldValue>;

// Shape of a stored custom field value on an entity (matches the CustomFieldValue GraphQL type).
export interface CustomFieldStoredValue {
  field_id: string;
  field_name: string;
  int_value?: number | null;
  string_value?: string | null;
  boolean_value?: boolean | null;
  date_value?: string | null;
  select_value?: string | null;
  select_values?: readonly string[] | null;
}

export const getCustomFieldSetting = (definition: CustomFieldDef, entityType: string) => (
  (definition.entity_type_settings ?? []).find((setting) => setting.entity_type === entityType)
);

// Form state is keyed by definition ID; defaults are configured separately for each entity type.
export const getCustomFieldsInitialValues = (
  definitions: readonly CustomFieldDef[],
  entityType: string,
): CustomFieldFormValues => Object.fromEntries(
  definitions.map((def) => {
    const rawDefaultValue = getCustomFieldSetting(def, entityType)?.default_value ?? null;
    const defaultValue = def.field_type === 'date' ? resolveCustomFieldDefaultValue(rawDefaultValue) : rawDefaultValue;
    if (def.field_type === 'boolean') {
      return [def.id, defaultValue === 'true'];
    }
    if (def.field_type === 'multi_select') {
      return [def.id, defaultValue ? [defaultValue] : []];
    }
    return [def.id, defaultValue ?? ''];
  }),
);

export const buildCustomFieldsValidationSchema = (
  definitions: readonly CustomFieldDef[],
  entityType: string,
  requiredMessage: string,
) => Yup.object().shape(
  Object.fromEntries(
    definitions.map((def) => {
      const isMandatory = getCustomFieldSetting(def, entityType)?.mandatory ?? false;
      if (def.field_type === 'multi_select') {
        return [def.id, isMandatory ? Yup.array().min(1, requiredMessage) : Yup.array().nullable()];
      }
      if (def.field_type === 'boolean') {
        return [def.id, Yup.boolean().nullable()];
      }
      return [def.id, isMandatory ? Yup.string().required(requiredMessage) : Yup.string().nullable()];
    }),
  ),
);

// Reads the current UI value from the entity's stored custom_field_values array.
export const getCustomFieldCurrentValue = (
  definition: CustomFieldDef,
  storedValues: readonly CustomFieldStoredValue[],
): CustomFieldValue => {
  const entry = storedValues.find((v) => v.field_id === definition.id);
  if (!entry) {
    if (definition.field_type === 'boolean') return false;
    if (definition.field_type === 'multi_select') return [];
    return '';
  }
  switch (definition.field_type) {
    case 'integer':
      return entry.int_value != null ? String(entry.int_value) : '';
    case 'boolean':
      return entry.boolean_value ?? false;
    case 'date':
      return entry.date_value ?? '';
    case 'select':
      return entry.select_value ?? '';
    case 'multi_select':
      return entry.select_values ? [...entry.select_values] : [];
    default:
      return entry.string_value ?? '';
  }
};

const parseCustomFieldRawValue = (definition: CustomFieldDef, rawValue: CustomFieldValue) => {
  switch (definition.field_type) {
    case 'integer': {
      const parsed = parseInt(String(rawValue), 10);
      return Number.isNaN(parsed) ? undefined : parsed;
    }
    case 'boolean':
      return rawValue === true;
    case 'multi_select':
      return Array.isArray(rawValue) ? rawValue : [];
    default:
      return String(rawValue);
  }
};

// Creation uses field_name and a value array, unlike the typed stored-value shape used by edition.
export const buildCustomFieldValueAddInputEntry = (
  definition: CustomFieldDef,
  rawValue: CustomFieldValue | undefined,
) => {
  if (rawValue === undefined || rawValue === '' || (Array.isArray(rawValue) && rawValue.length === 0)) {
    return undefined;
  }
  const parsedValue = parseCustomFieldRawValue(definition, rawValue);
  return { field_name: definition.name, value: Array.isArray(parsedValue) ? parsedValue : [parsedValue] };
};

export const buildCustomFieldValuesAddInput = (
  definitions: readonly CustomFieldDef[],
  values: CustomFieldFormValues,
) => definitions
  .map((def) => buildCustomFieldValueAddInputEntry(def, values[def.id]))
  .filter((entry) => entry !== undefined);

// CustomFieldsFormik supplies the serialized payload to existing entity-specific submitters.
// Explicit input builders use this helper; spread-based builders preserve it automatically.
export const getCustomFieldValues = (values: object): {
  customFieldValues?: ReturnType<typeof buildCustomFieldValuesAddInput>;
} => ('customFieldValues' in values
  ? { customFieldValues: values.customFieldValues as ReturnType<typeof buildCustomFieldValuesAddInput> }
  : {});

export const buildCustomFieldValueEntry = (
  definition: CustomFieldDef,
  rawValue: CustomFieldValue,
): CustomFieldStoredValue => {
  const base = { field_id: definition.id, field_name: definition.name };
  const parsedValue = parseCustomFieldRawValue(definition, rawValue);
  switch (definition.field_type) {
    case 'integer':
      return { ...base, int_value: parsedValue as number };
    case 'boolean':
      return { ...base, boolean_value: parsedValue as boolean };
    case 'date':
      return { ...base, date_value: parsedValue as string };
    case 'select':
      return { ...base, select_value: parsedValue as string };
    case 'multi_select':
      return { ...base, select_values: parsedValue as string[] };
    default:
      return { ...base, string_value: parsedValue as string };
  }
};

// Empty non-boolean values are dropped from the stored array.
export const isCustomFieldValueSet = (rawValue: CustomFieldValue | number | undefined): boolean => {
  if (Array.isArray(rawValue)) return rawValue.length > 0;
  if (typeof rawValue === 'boolean') return true;
  return (rawValue ?? '') !== '';
};

// fieldPatch replaces the whole array: retain all unrelated fields without mutating Relay data.
export const updateCustomFieldValues = (
  definition: CustomFieldDef,
  rawValue: CustomFieldValue,
  storedValues: readonly CustomFieldStoredValue[],
): CustomFieldStoredValue[] => {
  const withoutField = storedValues.filter((v) => v.field_id !== definition.id);
  const entry = buildCustomFieldValueEntry(definition, rawValue);
  const isValidValue = definition.field_type === 'integer'
    ? entry.int_value !== undefined
    : isCustomFieldValueSet(rawValue);
  return isValidValue ? [...withoutField, entry] : withoutField;
};

export const getCustomFieldLabel = (
  value: CustomFieldStoredValue,
  definitions: readonly CustomFieldDef[],
): string => {
  const label = definitions.find((def) => def.id === value.field_id)?.label;
  if (label !== undefined) return label;
  const spaced = value.field_name.replace(/_/g, ' ');
  return spaced.charAt(0).toUpperCase() + spaced.slice(1);
};

// Inject localization so this helper can be used outside React as well as in any SDO view.
export const getCustomFieldDisplayValue = (
  value: CustomFieldStoredValue,
  { t_i18n, fldt }: { t_i18n: (key: string) => string; fldt: (date: string) => string },
): string => {
  if (value.boolean_value !== null && value.boolean_value !== undefined) {
    return value.boolean_value ? t_i18n('True') : t_i18n('False');
  }
  if (value.date_value) {
    return fldt(value.date_value);
  }
  if (value.int_value !== null && value.int_value !== undefined) {
    return String(value.int_value);
  }
  if (value.select_values && value.select_values.length > 0) {
    return value.select_values.join(', ');
  }
  if (value.select_value) {
    return value.select_value;
  }
  return value.string_value ?? '';
};
// Prefix enforced backend-side for every custom field technical name (see CUSTOM_FIELD_PREFIX
// in opencti-graphql/src/modules/customField/custom-field-types.ts). Used to identify a widget
// column / attribute path as referring to a custom field rather than a built-in schema attribute.
export const CUSTOM_FIELD_PREFIX = 'x_opencti_cf_';
export const isCustomFieldAttribute = (attribute?: string | null): boolean => (
  !!attribute && attribute.startsWith(CUSTOM_FIELD_PREFIX)
);
// ----------------------------------------------------------------------------------------------------------------------
// Widgets integration (attribute widget & list/custom-attributes widget columns)
// Minimal shape needed from a CustomFieldDefinition to build a widget column / resolve its rendering.
export interface CustomFieldWidgetDefinition {
  name: string;
  label: string;
  field_type: string;
  entity_types?: readonly string[] | null;
}
// Maps a custom field's field_type to the closest existing WidgetColumnAttributeType so widgets
// reuse their standard renderers (boolean/date/markdown, tags for select values, etc.).
// Types without a good match (text, integer) are left undefined and rendered as plain text.
export const mapCustomFieldTypeToWidgetColumnAttributeType = (fieldType: string): WidgetColumnAttributeType | undefined => {
  switch (fieldType) {
    case 'boolean':
      return 'boolean';
    case 'date':
      return 'date';
    case 'markdown':
      return 'markdown';
    case 'select':
      return 'tag';
    case 'multi_select':
      return 'tag_list';
    default:
      return undefined;
  }
};
// The widget column's `attribute` is the custom field technical name (already unique and prefixed
// with CUSTOM_FIELD_PREFIX), so no extra identifier is needed to resolve it back to its definition.
export const customFieldDefinitionToWidgetColumn = (definition: CustomFieldWidgetDefinition): WidgetColumn => ({
  attribute: definition.name,
  label: definition.label,
  attributeType: mapCustomFieldTypeToWidgetColumnAttributeType(definition.field_type),
});
export const customFieldDefinitionsToWidgetColumns = (
  definitions: readonly CustomFieldWidgetDefinition[],
  entityType?: string,
): WidgetColumn[] => definitions
  .filter((def) => !entityType || !def.entity_types || def.entity_types.length === 0 || def.entity_types.includes(entityType))
  .map(customFieldDefinitionToWidgetColumn);
// Extracts the raw, correctly-typed value (string | number | boolean | string[] | undefined) of a
// custom field from an entity's stored `customFieldValues`, matched by field_name (== WidgetColumn.attribute).
// Field type doesn'"'"'t need to be known here: exactly one of the typed slots is populated per entry.
export const getCustomFieldRawValueByFieldName = (
  customFieldValues: readonly CustomFieldStoredValue[] | null | undefined,
  fieldName: string,
): unknown => {
  const entry = (customFieldValues ?? []).find((v) => v.field_name === fieldName);
  if (!entry) return undefined;
  if (entry.boolean_value !== null && entry.boolean_value !== undefined) return entry.boolean_value;
  if (entry.date_value !== null && entry.date_value !== undefined) return entry.date_value;
  if (entry.int_value !== null && entry.int_value !== undefined) return entry.int_value;
  if (entry.select_values && entry.select_values.length > 0) return [...entry.select_values];
  if (entry.select_value !== null && entry.select_value !== undefined) return entry.select_value;
  return entry.string_value ?? undefined;
};
