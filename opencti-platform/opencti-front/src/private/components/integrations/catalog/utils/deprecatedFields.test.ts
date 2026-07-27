import { describe, expect, it } from 'vitest';
import type { IngestionTypedProperty } from '@components/integrations/catalog/types';
import {
  buildOptionalPropertiesWithDeprecated,
  computeDeprecatedEditionVisibility,
  filterOutDeprecatedProperties,
  filterOutDeprecatedRequired,
  filterValuesForEditionPayload,
  getDeprecatedDescriptorsForEdition,
  getDeprecatedKeysClearedForReset,
  shouldShowDeprecatedAlert,
} from './deprecatedFields';

type TestStringProperty = IngestionTypedProperty<'string'> & {
  deprecated?: boolean;
};

const makeStringProp = (overrides: Partial<TestStringProperty> = {}): TestStringProperty => ({
  type: 'string',
  default: 'default',
  description: 'prop',
  ...overrides,
});

describe('deprecatedFields utils', () => {
  describe('connector-like fixture scenarios', () => {
    const connectorProperties: Record<string, IngestionTypedProperty> = {
      ACTIVE_NAME: {
        type: 'string',
        description: 'active',
        default: 'active-default',
      } as IngestionTypedProperty,
      DEPRECATED_WITH_DEFAULT_STRING: {
        type: 'string',
        description: 'deprecated-string',
        default: 'legacy-default',
        deprecated: true,
      } as IngestionTypedProperty,
      DEPRECATED_WITH_DEFAULT_INTEGER: {
        type: 'integer',
        description: 'deprecated-int',
        default: 1800,
        deprecated: true,
      } as IngestionTypedProperty,
      DEPRECATED_NO_DEFAULT: {
        type: 'string',
        description: 'deprecated-no-default',
        default: undefined,
        deprecated: true,
      } as unknown as IngestionTypedProperty,
    };

    it('keeps only deprecated fields configured with non-default values', () => {
      const simulatedConnectorValues = {
        ACTIVE_NAME: 'my-connector',
        DEPRECATED_WITH_DEFAULT_STRING: 'custom-legacy',
        DEPRECATED_WITH_DEFAULT_INTEGER: '1800',
        DEPRECATED_NO_DEFAULT: 'old-value',
      };

      const descriptors = getDeprecatedDescriptorsForEdition(
        connectorProperties,
        simulatedConnectorValues,
      );

      expect(descriptors.map(({ key }) => key)).toEqual(['DEPRECATED_WITH_DEFAULT_STRING']);

      const payload = filterValuesForEditionPayload(simulatedConnectorValues, connectorProperties);

      expect(payload).toHaveProperty('ACTIVE_NAME', 'my-connector');
      expect(payload).toHaveProperty('DEPRECATED_WITH_DEFAULT_STRING', 'custom-legacy');
      expect(payload).not.toHaveProperty('DEPRECATED_WITH_DEFAULT_INTEGER');
      expect(payload).not.toHaveProperty('DEPRECATED_NO_DEFAULT');
    });

    it('filters deprecated fields when values are empty or default-equivalent', () => {
      const simulatedConnectorValues = {
        ACTIVE_NAME: 'my-connector',
        DEPRECATED_WITH_DEFAULT_STRING: 'legacy-default',
        DEPRECATED_WITH_DEFAULT_INTEGER: '1800',
        DEPRECATED_NO_DEFAULT: '',
      };

      const descriptors = getDeprecatedDescriptorsForEdition(
        connectorProperties,
        simulatedConnectorValues,
      );

      expect(descriptors).toEqual([]);

      const payload = filterValuesForEditionPayload(simulatedConnectorValues, connectorProperties);

      expect(payload).toHaveProperty('ACTIVE_NAME', 'my-connector');
      expect(payload).not.toHaveProperty('DEPRECATED_WITH_DEFAULT_STRING');
      expect(payload).not.toHaveProperty('DEPRECATED_WITH_DEFAULT_INTEGER');
      expect(payload).not.toHaveProperty('DEPRECATED_NO_DEFAULT');
    });
  });

  describe('optional + deprecated composition', () => {
    it('keeps manifest order when merging optional and visible deprecated fields', () => {
      const allProperties: Record<string, IngestionTypedProperty> = {
        FIRST_OPTIONAL: makeStringProp({ default: 'a' }),
        DEPRECATED_VISIBLE: makeStringProp({ deprecated: true, default: 'b' }),
        HIDDEN_FIELD: makeStringProp({ default: 'c' }),
      };

      const optionalProperties: Record<string, IngestionTypedProperty> = {
        FIRST_OPTIONAL: allProperties.FIRST_OPTIONAL,
      };

      const visibleDeprecatedProperties: Record<string, IngestionTypedProperty> = {
        DEPRECATED_VISIBLE: allProperties.DEPRECATED_VISIBLE,
      };

      const result = buildOptionalPropertiesWithDeprecated(
        allProperties,
        optionalProperties,
        visibleDeprecatedProperties,
      );

      expect(Object.keys(result)).toEqual(['FIRST_OPTIONAL', 'DEPRECATED_VISIBLE']);
      expect(result.FIRST_OPTIONAL).toBe(allProperties.FIRST_OPTIONAL);
      expect(result.DEPRECATED_VISIBLE).toBe(allProperties.DEPRECATED_VISIBLE);
    });

    it('returns only visible deprecated when there are no optional base fields', () => {
      const allProperties: Record<string, IngestionTypedProperty> = {
        DEPRECATED_VISIBLE: makeStringProp({ deprecated: true, default: 'b' }),
        DEPRECATED_HIDDEN: makeStringProp({ deprecated: true, default: 'c' }),
      };

      const result = buildOptionalPropertiesWithDeprecated(
        allProperties,
        {},
        {
          DEPRECATED_VISIBLE: allProperties.DEPRECATED_VISIBLE,
        },
      );

      expect(Object.keys(result)).toEqual(['DEPRECATED_VISIBLE']);
    });
  });

  describe('creation path', () => {
    it('filters deprecated fields from properties', () => {
      const properties: Record<string, IngestionTypedProperty> = {
        ACTIVE: makeStringProp(),
        DEPRECATED_A: makeStringProp({ deprecated: true }),
        DEPRECATED_B: makeStringProp({ deprecated: true }),
      };

      const result = filterOutDeprecatedProperties(properties);

      expect(result).toEqual({
        ACTIVE: properties.ACTIVE,
      });
    });

    it('filters deprecated keys from required list', () => {
      const properties: Record<string, IngestionTypedProperty> = {
        ACTIVE: makeStringProp(),
        DEPRECATED_A: makeStringProp({ deprecated: true }),
      };

      expect(filterOutDeprecatedRequired(['ACTIVE', 'DEPRECATED_A'], properties)).toEqual(['ACTIVE']);
    });
  });

  describe('edition path visibility', () => {
    const properties: Record<string, IngestionTypedProperty> = {
      DEPRECATED_WITH_DEFAULT: makeStringProp({ deprecated: true, default: 'same' }),
      DEPRECATED_NO_DEFAULT: { ...makeStringProp({ deprecated: true }), default: undefined } as unknown as IngestionTypedProperty,
      NORMAL_FIELD: makeStringProp({ deprecated: false }),
    };

    it('hides deprecated with default when value equals default', () => {
      const descriptors = getDeprecatedDescriptorsForEdition(properties, {
        DEPRECATED_WITH_DEFAULT: 'same',
      });

      expect(descriptors).toEqual([]);
    });

    it('shows editable deprecated with default when current value differs from default', () => {
      const descriptors = getDeprecatedDescriptorsForEdition(properties, {
        DEPRECATED_WITH_DEFAULT: 'custom',
      });

      expect(descriptors).toHaveLength(1);
      expect(descriptors[0]).toMatchObject({
        key: 'DEPRECATED_WITH_DEFAULT',
      });
    });

    it('hides deprecated with no default when no value', () => {
      const descriptors = getDeprecatedDescriptorsForEdition(properties, {
        DEPRECATED_NO_DEFAULT: '',
      });

      expect(descriptors).toEqual([]);
    });

    it('hides deprecated with no default even when there is a value', () => {
      const descriptors = getDeprecatedDescriptorsForEdition(properties, {
        DEPRECATED_NO_DEFAULT: 'legacy-value',
      });

      expect(descriptors).toEqual([]);
    });

    it('hides deprecated with default when value is whitespace only', () => {
      const descriptors = getDeprecatedDescriptorsForEdition(properties, {
        DEPRECATED_WITH_DEFAULT: '   ',
      });

      expect(descriptors).toEqual([]);
    });

    it('hides deprecated integer when connector value is equivalent numeric string', () => {
      const descriptors = getDeprecatedDescriptorsForEdition(
        {
          DEPRECATED_INT: {
            type: 'integer',
            deprecated: true,
            default: 1800,
            description: 'interval',
          } as IngestionTypedProperty,
        },
        {
          DEPRECATED_INT: '1800',
        },
      );

      expect(descriptors).toEqual([]);
    });

    it('hides deprecated boolean when connector value is equivalent boolean string', () => {
      const descriptors = getDeprecatedDescriptorsForEdition(
        {
          DEPRECATED_BOOL: {
            type: 'boolean',
            deprecated: true,
            default: true,
            description: 'flag',
          } as IngestionTypedProperty,
        },
        {
          DEPRECATED_BOOL: 'true',
        },
      );

      expect(descriptors).toEqual([]);
    });

    it('shows alert only when at least one deprecated field is visible', () => {
      const none = getDeprecatedDescriptorsForEdition(properties, {
        DEPRECATED_WITH_DEFAULT: 'same',
        DEPRECATED_NO_DEFAULT: '',
      });
      const some = getDeprecatedDescriptorsForEdition(properties, {
        DEPRECATED_WITH_DEFAULT: 'custom',
      });

      expect(shouldShowDeprecatedAlert(none)).toBe(false);
      expect(shouldShowDeprecatedAlert(some)).toBe(true);
    });

    it('does not show deprecated field when default is null and value is non-empty', () => {
      const descriptors = getDeprecatedDescriptorsForEdition(
        {
          DEPRECATED_NULL_DEFAULT: {
            type: 'string',
            deprecated: true,
            default: null,
            description: 'nullable',
          } as unknown as IngestionTypedProperty,
        },
        {
          DEPRECATED_NULL_DEFAULT: 'legacy-value',
        },
      );

      expect(descriptors).toEqual([]);
    });
  });

  describe('edition payload', () => {
    const properties: Record<string, IngestionTypedProperty> = {
      DEPRECATED_WITH_DEFAULT: makeStringProp({ deprecated: true, default: 'same' }),
      DEPRECATED_NO_DEFAULT: { ...makeStringProp({ deprecated: true }), default: undefined } as unknown as IngestionTypedProperty,
      NORMAL_FIELD: makeStringProp({ deprecated: false }),
    };

    it('keeps visible deprecated fields and omits hidden deprecated fields', () => {
      const payload = filterValuesForEditionPayload(
        {
          name: 'connector',
          DEPRECATED_WITH_DEFAULT: 'custom',
          DEPRECATED_NO_DEFAULT: 'legacy',
          NORMAL_FIELD: 'ok',
        },
        properties,
      );

      expect(payload).toHaveProperty('DEPRECATED_WITH_DEFAULT', 'custom');
      expect(payload).not.toHaveProperty('DEPRECATED_NO_DEFAULT');
      expect(payload).toHaveProperty('NORMAL_FIELD', 'ok');
      expect(payload).toHaveProperty('name', 'connector');
    });

    it('detects deprecated keys cleared for reset confirmation', () => {
      const cleared = getDeprecatedKeysClearedForReset(
        {
          DEPRECATED_WITH_DEFAULT: 'custom',
        },
        {
          DEPRECATED_WITH_DEFAULT: '',
        },
        properties,
      );

      expect(cleared).toEqual(['DEPRECATED_WITH_DEFAULT']);
    });

    it('does not flag clear when initial value already equals default', () => {
      const cleared = getDeprecatedKeysClearedForReset(
        {
          DEPRECATED_WITH_DEFAULT: 'same',
        },
        {
          DEPRECATED_WITH_DEFAULT: '',
        },
        properties,
      );

      expect(cleared).toEqual([]);
    });

    it('keeps cleared deprecated field visible in-session and keeps alert', () => {
      const visibility = computeDeprecatedEditionVisibility(
        properties,
        {
          DEPRECATED_WITH_DEFAULT: 'custom',
        },
        {
          DEPRECATED_WITH_DEFAULT: '',
        },
      );

      expect(visibility.showDeprecatedAlert).toBe(true);
      expect(Object.keys(visibility.visibleDeprecatedProperties)).toEqual(['DEPRECATED_WITH_DEFAULT']);
    });

    it('keeps deprecated field visible in-session when reset to default value', () => {
      const visibility = computeDeprecatedEditionVisibility(
        properties,
        {
          DEPRECATED_WITH_DEFAULT: 'custom',
        },
        {
          DEPRECATED_WITH_DEFAULT: 'same',
        },
      );

      expect(visibility.showDeprecatedAlert).toBe(true);
      expect(Object.keys(visibility.visibleDeprecatedProperties)).toEqual(['DEPRECATED_WITH_DEFAULT']);
    });

    it('flags deprecated key reset to default for in-session visibility', () => {
      const resetToDefault = getDeprecatedKeysClearedForReset(
        {
          DEPRECATED_WITH_DEFAULT: 'custom',
        },
        {
          DEPRECATED_WITH_DEFAULT: 'same',
        },
        properties,
      );

      expect(resetToDefault).toEqual(['DEPRECATED_WITH_DEFAULT']);
    });

    it('does not keep deprecated null-default field visible in-session when cleared', () => {
      const properties: Record<string, IngestionTypedProperty> = {
        DEPRECATED_NULL_DEFAULT: {
          type: 'string',
          deprecated: true,
          default: null,
          description: 'nullable',
        } as unknown as IngestionTypedProperty,
      };

      const visibility = computeDeprecatedEditionVisibility(
        properties,
        {
          DEPRECATED_NULL_DEFAULT: 'legacy-value',
        },
        {
          DEPRECATED_NULL_DEFAULT: '',
        },
      );

      expect(visibility.showDeprecatedAlert).toBe(false);
      expect(Object.keys(visibility.visibleDeprecatedProperties)).toEqual([]);
    });

    it('keeps deprecated null-default field in payload when non-empty', () => {
      const payload = filterValuesForEditionPayload(
        {
          DEPRECATED_NULL_DEFAULT: 'legacy-value',
          NORMAL_FIELD: 'ok',
        },
        {
          DEPRECATED_NULL_DEFAULT: {
            type: 'string',
            deprecated: true,
            default: null,
            description: 'nullable',
          } as unknown as IngestionTypedProperty,
          NORMAL_FIELD: makeStringProp({ deprecated: false }),
        },
      );

      expect(payload).toEqual({
        DEPRECATED_NULL_DEFAULT: 'legacy-value',
        NORMAL_FIELD: 'ok',
      });
    });
  });
});
