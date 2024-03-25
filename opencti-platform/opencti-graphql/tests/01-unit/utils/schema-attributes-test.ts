import { describe, expect, it } from 'vitest';
import { schemaAttributesDefinition } from '../../../src/schema/schema-attributes';

describe('Schema utilities', () => {
  let mapping;
  it('getAttributeMappingFromPath gives access to internal attribute definitions', () => {
    mapping = schemaAttributesDefinition.getAttributeMappingFromPath('name');
    expect(mapping).toEqual({
      editDefault: false,
      format: 'short',
      isFilterable: true,
      label: 'Name',
      mandatoryType: 'external',
      multiple: false,
      name: 'name',
      type: 'string',
      upsert: false,
    });
    mapping = schemaAttributesDefinition.getAttributeMappingFromPath('group_confidence_level.overrides.entity_type');
    expect(mapping).toEqual({
      editDefault: false,
      format: 'short',
      isFilterable: true,
      label: 'Entity Type',
      mandatoryType: 'external',
      multiple: false,
      name: 'entity_type',
      type: 'string',
      upsert: false,
    });
  });

  it('getAttributeMappingFromPath throws errors on schema inconsistencies', () => {
    mapping = () => schemaAttributesDefinition.getAttributeMappingFromPath('invalid_attribute');
    expect(mapping).toThrowError('Cannot resolve path [invalid_attribute], missing schema definition');
    mapping = () => schemaAttributesDefinition.getAttributeMappingFromPath('group_confidence_level.invalid_sub_attribute');
    expect(mapping).toThrowError('Schema definition named [group_confidence_level] is missing mapping for attribute [invalid_sub_attribute]');
    mapping = () => schemaAttributesDefinition.getAttributeMappingFromPath('name.fail');
    expect(mapping).toThrowError('Cannot resolve path [name.fail], [name] is not an object');
  });
});
