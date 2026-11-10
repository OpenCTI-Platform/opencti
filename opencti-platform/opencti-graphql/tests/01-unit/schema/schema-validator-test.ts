import { describe, expect, it } from 'vitest';
import '../../../src/modules/index';
import { validateAndFormatSchemaAttribute, validateInputCreation, validateSchemaMandatoryAttributesOnCreation } from '../../../src/schema/schema-validator';
import { schemaAttributesDefinition } from '../../../src/schema/schema-attributes';
import { ENTITY_TYPE_CONTAINER_OBSERVED_DATA } from '../../../src/schema/stixDomainObject';
import { ENTITY_TYPE_KILL_CHAIN_PHASE, ENTITY_TYPE_LABEL } from '../../../src/schema/stixMetaObject';
import { type EditInput, EditOperation } from '../../../src/generated/graphql';
import { SYSTEM_USER } from '../../../src/utils/access';
import type { AuthContext } from '../../../src/types/user';
import type { BasicStoreEntityEntitySetting } from '../../../src/modules/entitySetting/entitySetting-types';

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

describe('schema validator mandatory attributes of the schema at creation', () => {
  const phase = { kill_chain_name: 'mitre-attack', phase_name: 'execution', x_opencti_order: 0 };

  it('should accept a kill chain phase with all its mandatory attributes', () => {
    expect(() => validateSchemaMandatoryAttributesOnCreation(ENTITY_TYPE_KILL_CHAIN_PHASE, phase)).not.toThrow();
  });

  it('should reject a kill chain phase without kill chain name', () => {
    const { kill_chain_name: _, ...withoutKillChainName } = phase;
    expect(() => validateSchemaMandatoryAttributesOnCreation(ENTITY_TYPE_KILL_CHAIN_PHASE, withoutKillChainName)).toThrow('This attribute is mandatory');
    expect(() => validateSchemaMandatoryAttributesOnCreation(ENTITY_TYPE_KILL_CHAIN_PHASE, { ...phase, kill_chain_name: null })).toThrow('This attribute is mandatory');
    expect(() => validateSchemaMandatoryAttributesOnCreation(ENTITY_TYPE_KILL_CHAIN_PHASE, { ...phase, kill_chain_name: '' })).toThrow('This attribute is mandatory');
    expect(() => validateSchemaMandatoryAttributesOnCreation(ENTITY_TYPE_KILL_CHAIN_PHASE, { ...phase, kill_chain_name: [] })).toThrow('This attribute is mandatory');
  });

  it('should name the missing attribute in the error', () => {
    const { phase_name: _, ...withoutPhaseName } = phase;
    expect(() => validateSchemaMandatoryAttributesOnCreation(ENTITY_TYPE_KILL_CHAIN_PHASE, withoutPhaseName))
      .toThrow(expect.objectContaining({ extensions: expect.objectContaining({ data: expect.objectContaining({ field: 'phase_name' }) }) }));
  });

  it('should accept a zero order, which is a value', () => {
    expect(() => validateSchemaMandatoryAttributesOnCreation(ENTITY_TYPE_KILL_CHAIN_PHASE, { ...phase, x_opencti_order: 0 })).not.toThrow();
    const { x_opencti_order: _, ...withoutOrder } = phase;
    expect(() => validateSchemaMandatoryAttributesOnCreation(ENTITY_TYPE_KILL_CHAIN_PHASE, withoutOrder)).toThrow('This attribute is mandatory');
  });

  it('should not check the types that are not enforced yet', () => {
    // The value of a label is mandatory in the schema, the label is not part of the enforced types
    expect(schemaAttributesDefinition.getAttribute(ENTITY_TYPE_LABEL, 'value')?.mandatoryType).toEqual('external');
    expect(() => validateSchemaMandatoryAttributesOnCreation(ENTITY_TYPE_LABEL, { color: '#ffffff' })).not.toThrow();
  });

  it('should reject the creation even for a user allowed to bypass the mandatory attributes', async () => {
    const { kill_chain_name: _, ...withoutKillChainName } = phase;
    const entitySetting = {} as BasicStoreEntityEntitySetting;
    await expect(validateInputCreation({} as AuthContext, SYSTEM_USER, ENTITY_TYPE_KILL_CHAIN_PHASE, withoutKillChainName, entitySetting, { bypassMandatoryAttributes: true }))
      .rejects.toThrow('This attribute is mandatory');
    await expect(validateInputCreation({} as AuthContext, SYSTEM_USER, ENTITY_TYPE_KILL_CHAIN_PHASE, phase, entitySetting)).resolves.toBeUndefined();
  });
});
