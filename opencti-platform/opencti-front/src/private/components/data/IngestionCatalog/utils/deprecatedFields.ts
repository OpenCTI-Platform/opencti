import { IngestionTypedProperty } from '@components/data/IngestionCatalog';

type ConnectorValues = Record<string, unknown>;

export interface DeprecatedFieldDescriptor {
  key: string;
  property: IngestionTypedProperty;
}

export interface DeprecatedEditionVisibility {
  showDeprecatedAlert: boolean;
  visibleDeprecatedProperties: Record<string, IngestionTypedProperty>;
}

/**
 * Merges optional properties with deprecated properties that must stay visible,
 * while preserving the original manifest order from allProperties.
 */
export const buildOptionalPropertiesWithDeprecated = (
  allProperties: Record<string, IngestionTypedProperty>,
  optionalProperties: Record<string, IngestionTypedProperty> | undefined,
  visibleDeprecatedProperties: Record<string, IngestionTypedProperty>,
) => {
  return Object.fromEntries(
    Object.entries(allProperties)
      .filter(([key]) => {
        const isOptionalBase = Boolean(optionalProperties?.[key]);
        const isVisibleDeprecated = Boolean(visibleDeprecatedProperties[key]);
        return isOptionalBase || isVisibleDeprecated;
      })
      .map(([key]) => {
        const optionalProperty = optionalProperties?.[key];
        return [key, optionalProperty ?? visibleDeprecatedProperties[key]];
      }),
  );
};

/** Returns true when a schema property is marked as deprecated. */
const isDeprecated = (property?: IngestionTypedProperty) => {
  return Boolean((property as { deprecated?: boolean } | undefined)?.deprecated);
};

/** Returns true when a deprecated field defines a non-null default value. */
const hasDefinedDefault = (property: IngestionTypedProperty) => {
  return property.default !== undefined && property.default !== null;
};

/**
 * Normalizes empty values across types (blank strings, nullish values, empty arrays)
 * so visibility rules can be applied consistently.
 */
const isEmptyValue = (value: unknown) => {
  if (typeof value === 'string' && value.trim() === '') return true;
  if (value === null || value === undefined || value === '') return true;
  if (Array.isArray(value) && value.length === 0) return true;
  return false;
};

/**
 * Coerces runtime values to schema-compatible shapes before comparisons
 * (e.g. numeric strings, boolean strings, and comma-separated arrays).
 */
const normalizeBySchemaType = (value: unknown, property: IngestionTypedProperty) => {
  if (value === null || value === undefined) return value;

  const propertyType = Array.isArray(property.type) ? property.type[0] : property.type;

  if ((propertyType === 'integer' || propertyType === 'number') && typeof value === 'string') {
    const trimmed = value.trim();
    if (trimmed === '') return value;
    const parsed = Number(trimmed);
    return Number.isNaN(parsed) ? value : parsed;
  }

  if (propertyType === 'boolean' && typeof value === 'string') {
    const normalized = value.trim().toLowerCase();
    if (normalized === 'true') return true;
    if (normalized === 'false') return false;
  }

  if (propertyType === 'array' && typeof value === 'string') {
    if (value.trim() === '') return [];
    return value.split(',').map((item) => item.trim());
  }

  return value;
};

/**
 * Compares two values after schema-aware normalization to avoid false positives
 * caused by string/typed representation differences.
 */
const areEquivalent = (
  left: unknown,
  right: unknown,
  property: IngestionTypedProperty,
) => {
  const normalizedLeft = normalizeBySchemaType(left, property);
  const normalizedRight = normalizeBySchemaType(right, property);
  return JSON.stringify(normalizedLeft) === JSON.stringify(normalizedRight);
};

/** Removes deprecated properties from a schema property map. */
export const filterOutDeprecatedProperties = (
  properties: Record<string, IngestionTypedProperty>,
) => {
  return Object.fromEntries(
    Object.entries(properties).filter(([, property]) => !isDeprecated(property)),
  );
};

/** Removes deprecated keys from a required field list. */
export const filterOutDeprecatedRequired = (
  required: string[],
  properties: Record<string, IngestionTypedProperty>,
) => required.filter((key) => !isDeprecated(properties[key]));

/**
 * Returns deprecated fields that are still effectively configured in edition mode,
 * meaning they are deprecated, have defaults, and currently differ from defaults.
 */
export const getDeprecatedDescriptorsForEdition = (
  properties: Record<string, IngestionTypedProperty>,
  values: ConnectorValues,
) => {
  const descriptors: DeprecatedFieldDescriptor[] = [];

  Object.entries(properties).forEach(([key, property]) => {
    if (!isDeprecated(property)) return;

    const value = values[key];
    const hasDefault = hasDefinedDefault(property);

    if (hasDefault) {
      if (isEmptyValue(value)) return;
      if (areEquivalent(value, property.default, property)) return;
      descriptors.push({ key, property });
      return;
    }
  });

  return descriptors;
};

/** Returns true when at least one deprecated descriptor should trigger an alert. */
export const shouldShowDeprecatedAlert = (descriptors: DeprecatedFieldDescriptor[]) => descriptors.length > 0;

/**
 * Filters edition payload values by keeping all non-deprecated fields and only
 * deprecated fields that are still configured with non-default values.
 */
export const filterValuesForEditionPayload = (
  values: ConnectorValues,
  properties: Record<string, IngestionTypedProperty>,
) => {
  const deprecatedDescriptors = getDeprecatedDescriptorsForEdition(properties, values);
  const keepDeprecatedKeys = new Set(
    deprecatedDescriptors.map((descriptor) => descriptor.key),
  );

  return Object.fromEntries(
    Object.entries(values).filter(([key]) => {
      const property = properties[key];
      if (!isDeprecated(property)) return true;
      return keepDeprecatedKeys.has(key);
    }),
  );
};

/**
 * Detects deprecated keys that were non-default when the form opened and are now
 * cleared or reset to default during the current edition session.
 */
export const getDeprecatedKeysClearedForReset = (
  initialValues: ConnectorValues,
  currentValues: ConnectorValues,
  properties: Record<string, IngestionTypedProperty>,
) => {
  return Object.entries(properties)
    .filter(([, property]) => isDeprecated(property) && hasDefinedDefault(property))
    .map(([key, property]) => ({
      key,
      property,
      initialValue: initialValues[key],
      currentValue: currentValues[key],
    }))
    .filter(({ property, initialValue, currentValue }) => {
      if (isEmptyValue(initialValue)) return false;
      if (areEquivalent(initialValue, property.default, property)) return false;
      return isEmptyValue(currentValue) || areEquivalent(currentValue, property.default, property);
    })
    .map(({ key }) => key);
};

/**
 * Computes deprecated field visibility for edition UI by combining:
 * - currently configured deprecated fields
 * - deprecated fields just cleared/reset in-session (for continuity/awareness)
 */
export const computeDeprecatedEditionVisibility = (
  properties: Record<string, IngestionTypedProperty>,
  initialValues: ConnectorValues,
  currentValues: ConnectorValues,
): DeprecatedEditionVisibility => {
  const deprecatedDescriptors = getDeprecatedDescriptorsForEdition(properties, currentValues);
  const clearedDeprecatedKeys = getDeprecatedKeysClearedForReset(
    initialValues,
    currentValues,
    properties,
  );

  const visibleDeprecatedProperties = Object.fromEntries(
    deprecatedDescriptors.map((descriptor) => [descriptor.key, descriptor.property]),
  ) as Record<string, IngestionTypedProperty>;

  clearedDeprecatedKeys.forEach((key) => {
    if (properties[key]) {
      visibleDeprecatedProperties[key] = properties[key];
    }
  });

  return {
    showDeprecatedAlert: shouldShowDeprecatedAlert(deprecatedDescriptors) || clearedDeprecatedKeys.length > 0,
    visibleDeprecatedProperties,
  };
};
