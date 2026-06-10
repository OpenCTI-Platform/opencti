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

const isDeprecated = (property?: IngestionTypedProperty) => property?.deprecated === true;

const hasDefinedDefault = (property: IngestionTypedProperty) => {
  return property.default !== undefined && property.default !== null;
};

const isEmptyValue = (value: unknown) => {
  if (typeof value === 'string' && value.trim() === '') return true;
  if (value === null || value === undefined || value === '') return true;
  if (Array.isArray(value) && value.length === 0) return true;
  return false;
};

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

const areEquivalent = (
  left: unknown,
  right: unknown,
  property: IngestionTypedProperty,
) => {
  const normalizedLeft = normalizeBySchemaType(left, property);
  const normalizedRight = normalizeBySchemaType(right, property);
  return JSON.stringify(normalizedLeft) === JSON.stringify(normalizedRight);
};

export const filterOutDeprecatedProperties = (
  properties: Record<string, IngestionTypedProperty>,
) => {
  return Object.fromEntries(
    Object.entries(properties).filter(([, property]) => !isDeprecated(property)),
  );
};

export const filterOutDeprecatedRequired = (
  required: string[],
  properties: Record<string, IngestionTypedProperty>,
) => required.filter((key) => !isDeprecated(properties[key]));

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

export const shouldShowDeprecatedAlert = (descriptors: DeprecatedFieldDescriptor[]) => descriptors.length > 0;

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
