import { describe, it, expect } from 'vitest';
import { validateFormSubmission } from '../../../../src/modules/form/form-validation';
import { type AdditionalEntity, FormFieldType, type FormSchemaDefinition } from '../../../../src/modules/form/form-types';

// ─── Helpers ────────────────────────────────────────────────────────────────

const makeField = (name: string, entity: string, overrides = {}) => ({
  id: name,
  name,
  label: name,
  type: 'text' as FormFieldType,
  isMandatory: false,
  required: false,
  attributeMapping: { entity, attributeName: name },
  ...overrides,
});

const makeAdditionalEntity = (id: string, entityType: string, overrides = {}): AdditionalEntity => ({
  id,
  label: id,
  entityType,
  multiple: false,
  parseFieldMapping: 'value',
  ...overrides,
});

const baseSchema = (overrides: Partial<FormSchemaDefinition> = {}): FormSchemaDefinition => ({
  mainEntityType: 'Malware',
  version: '1.0',
  fields: [],
  ...overrides,
});

// ─── Single entity mode ──────────────────────────────────────────────────────

describe('validateFormSubmission — single entity mode', () => {
  it('passes when all mandatory fields are present', () => {
    const schema = baseSchema({
      fields: [makeField('name', 'main_entity', { isMandatory: true })],
    });
    expect(() => validateFormSubmission(schema, { name: 'Emotet' })).not.toThrow();
  });

  it('throws when a mandatory field is missing', () => {
    const schema = baseSchema({
      fields: [makeField('name', 'main_entity', { isMandatory: true })],
    });
    expect(() => validateFormSubmission(schema, {}))
      .toThrow('Required field "name" is missing');
  });

  it('throws when a mandatory field is empty string', () => {
    const schema = baseSchema({
      fields: [makeField('name', 'main_entity', { isMandatory: true })],
    });
    expect(() => validateFormSubmission(schema, { name: '' }))
      .toThrow('Required field "name" is missing');
  });

  it('passes when optional fields are missing', () => {
    const schema = baseSchema({
      fields: [makeField('description', 'main_entity', { isMandatory: false })],
    });
    expect(() => validateFormSubmission(schema, {})).not.toThrow();
  });

  it('collects multiple errors and throws them together', () => {
    const schema = baseSchema({
      fields: [
        makeField('name', 'main_entity', { isMandatory: true }),
        makeField('description', 'main_entity', { required: true }),
      ],
    });
    expect(() => validateFormSubmission(schema, {}))
      .toThrow('Required field "name" is missing, Required field "description" is missing');
  });
});

// ─── Lookup mode ─────────────────────────────────────────────────────────────

describe('validateFormSubmission — mainEntityLookup', () => {
  it('throws when lookup value is missing', () => {
    const schema = baseSchema({ mainEntityLookup: true, fields: [] });
    expect(() => validateFormSubmission(schema, {}))
      .toThrow('Required field "mainEntityLookup" is missing');
  });

  it('throws when lookup value is empty array', () => {
    const schema = baseSchema({ mainEntityLookup: true, fields: [] });
    expect(() => validateFormSubmission(schema, { mainEntityLookup: [] }))
      .toThrow('Required field "mainEntityLookup" is missing');
  });

  it('passes when lookup value is present', () => {
    const schema = baseSchema({ mainEntityLookup: true, fields: [] });
    expect(() => validateFormSubmission(schema, { mainEntityLookup: 'some-id' })).not.toThrow();
  });
});

// ─── Multiple / multiple mode ─────────────────────────────────────────────────

describe('validateFormSubmission — mainEntityMultiple + multiple mode', () => {
  const schema = baseSchema({
    mainEntityMultiple: true,
    mainEntityFieldMode: 'multiple',
    fields: [makeField('value', 'main_entity', { isMandatory: true })],
  });

  it('throws when mainEntityGroups is missing', () => {
    expect(() => validateFormSubmission(schema, {}))
      .toThrow('Required field "mainEntityGroups" is missing');
  });

  it('throws when a group has a missing mandatory field', () => {
    expect(() => validateFormSubmission(schema, {
      mainEntityGroups: [{ value: '' }],
    })).toThrow('Required field "value" is missing');
  });

  it('passes when all groups have mandatory fields filled', () => {
    expect(() => validateFormSubmission(schema, {
      mainEntityGroups: [{ value: '192.168.1.1' }, { value: '10.0.0.1' }],
    })).not.toThrow();
  });
});

// ─── Multiple / parsed mode ───────────────────────────────────────────────────

describe('validateFormSubmission — mainEntityMultiple + parsed mode', () => {
  const schema = baseSchema({
    mainEntityMultiple: true,
    mainEntityFieldMode: 'parsed',
    fields: [makeField('confidence', 'main_entity', { isMandatory: true })],
  });

  it('throws when mainEntityParsed is missing', () => {
    expect(() => validateFormSubmission(schema, {}))
      .toThrow('Required field "mainEntityParsed" is missing');
  });

  it('throws when mainEntityParsed is empty string', () => {
    expect(() => validateFormSubmission(schema, { mainEntityParsed: '' }))
      .toThrow('Required field "mainEntityParsed" is missing');
  });

  it('throws when mainEntityFields has a missing mandatory field', () => {
    expect(() => validateFormSubmission(schema, {
      mainEntityParsed: '192.168.1.1',
      mainEntityFields: { confidence: '' },
    })).toThrow('Required field "confidence" is missing');
  });

  it('passes when mainEntityFields has all mandatory fields', () => {
    expect(() => validateFormSubmission(schema, {
      mainEntityParsed: '192.168.1.1',
      mainEntityFields: { confidence: 80 },
    })).not.toThrow();
  });

  it('passes when mainEntityFields is absent (optional additional fields)', () => {
    expect(() => validateFormSubmission(schema, {
      mainEntityParsed: '192.168.1.1',
    })).not.toThrow();
  });
});

// ─── Additional entities ──────────────────────────────────────────────────────

describe('validateFormSubmission — additionalEntities', () => {
  it('throws when required lookup is missing', () => {
    const schema = baseSchema({
      fields: [],
      additionalEntities: [makeAdditionalEntity('ent-1', 'Identity', { lookup: true, minAmount: 1 })],
    });
    expect(() => validateFormSubmission(schema, {}))
      .toThrow('Required field "additional_ent-1_lookup" is missing');
  });

  it('passes when optional lookup is missing', () => {
    const schema = baseSchema({
      fields: [],
      additionalEntities: [makeAdditionalEntity('ent-1', 'Identity', { lookup: true, minAmount: 0 })],
    });
    expect(() => validateFormSubmission(schema, {})).not.toThrow();
  });

  it('throws when additional multiple group has missing mandatory field', () => {
    const schema = baseSchema({
      fields: [makeField('name', 'ent-1', { isMandatory: true })],
      additionalEntities: [makeAdditionalEntity('ent-1', 'Identity', { multiple: true, fieldMode: 'multiple' })],
    });
    expect(() => validateFormSubmission(schema, {
      'additional_ent-1_groups': [{ name: '' }],
    })).toThrow('Required field "name" is missing');
  });

  it('throws when additional parsed mandatory field missing', () => {
    const schema = baseSchema({
      fields: [makeField('confidence', 'ent-1', { isMandatory: true })],
      additionalEntities: [makeAdditionalEntity('ent-1', 'Identity', { multiple: true, fieldMode: 'parsed', minAmount: 1 })],
    });
    expect(() => validateFormSubmission(schema, {
      'additional_ent-1_parsed': 'something',
      'additional_ent-1_fields': { confidence: null },
    })).toThrow('Required field "confidence" is missing');
  });

  it('throws for required single additional entity with missing mandatory field', () => {
    const schema = baseSchema({
      fields: [makeField('name', 'ent-1', { isMandatory: true })],
      additionalEntities: [makeAdditionalEntity('ent-1', 'Identity', { required: true })],
    });
    expect(() => validateFormSubmission(schema, {
      'additional_ent-1': { name: '' },
    })).toThrow('Required field "name" is missing');
  });

  it('skips optional single entity when no fields are filled', () => {
    const schema = baseSchema({
      fields: [makeField('name', 'ent-1', { isMandatory: true })],
      additionalEntities: [makeAdditionalEntity('ent-1', 'Identity', { required: false })],
    });
    expect(() => validateFormSubmission(schema, {})).not.toThrow();
  });

  it('validates optional single entity when at least one field is filled', () => {
    const schema = baseSchema({
      fields: [
        makeField('name', 'ent-1', { isMandatory: true }),
        makeField('description', 'ent-1', { isMandatory: false }),
      ],
      additionalEntities: [makeAdditionalEntity('ent-1', 'Identity', { required: false })],
    });
    expect(() => validateFormSubmission(schema, {
      'additional_ent-1': { description: 'something', name: '' },
    })).toThrow('Required field "name" is missing');
  });
});
