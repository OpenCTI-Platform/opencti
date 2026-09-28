import { describe, expect, it } from 'vitest';
import '../../../src/modules/index';
import { validateAndFormatSchemaAttribute } from '../../../src/schema/schema-validator';
import { schemaAttributesDefinition } from '../../../src/schema/schema-attributes';
import { ENTITY_TYPE_CONTAINER_OBSERVED_DATA } from '../../../src/schema/stixDomainObject';
import { type EditInput, EditOperation } from '../../../src/generated/graphql';

describe('schema validator observed data counters', () => {
  const validate = (attributeName: string, value: unknown) => {
    const definition = schemaAttributesDefinition.getAttribute(ENTITY_TYPE_CONTAINER_OBSERVED_DATA, attributeName);
    const editInput: EditInput = { key: attributeName, value: [value], operation: EditOperation.Replace };
    return validateAndFormatSchemaAttribute(attributeName, definition, editInput);
  };

  it('should accept non-negative integer counters', () => {
    expect(() => validate('number_seen', 0)).not.toThrow();
    expect(() => validate('number_seen', 12)).not.toThrow();
    expect(() => validate('max_distinct_count', 60000)).not.toThrow();
    // Numeric strings are accepted like any other numeric attribute (field patch from the UI)
    expect(() => validate('max_distinct_count', '60000')).not.toThrow();
  });

  it('should accept empty counters to allow attribute removal', () => {
    expect(() => validate('number_seen', '')).not.toThrow();
    expect(() => validate('max_distinct_count', null)).not.toThrow();
  });

  it('should reject negative or non-integer counters', () => {
    expect(() => validate('number_seen', -1)).toThrow('The counter should be a non-negative integer');
    expect(() => validate('max_distinct_count', -5)).toThrow('The counter should be a non-negative integer');
    expect(() => validate('number_seen', 1.5)).toThrow('The counter should be a non-negative integer');
    expect(() => validate('max_distinct_count', 'not-a-number')).toThrow('Attribute must be a numeric/string');
  });
});
