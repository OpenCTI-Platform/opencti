import { describe, expect, it } from 'vitest';
// The modules register their entity types and attributes in the schema; the platform imports them before anything
// else (src/back.ts), so the mapping measured here is the one generated at startup, not the core schema alone.
import '../../../src/modules/index';
import { Client as ElkClient } from '@elastic/elasticsearch';
import { computeMappingFieldsLimit, countMappingFields, ES_MAPPING_FIELDS_HEADROOM, ES_MAX_MAPPINGS } from '../../../src/database/engine';
import { engineMappingGenerator } from '../../../src/database/engine-mapping-generator';

// Fields a platform created years ago still carries in its indices although the attributes left the schema since.
// The engine never drops a mapped field, so every attribute the platform ever had counts against total_fields.
const LEGACY_FIELDS_OF_A_LONG_LIVED_PLATFORM = 800;

// Budget for the mapping generated from the current schema. It is deliberately below the default limit so that a
// long-lived index (current schema + legacy fields) keeps room under the default limit as long as possible, and the
// limit raise stays the exception. When the schema legitimately grows past it, raise the budget in the same change
// and check the warning "Index fields limit raised above the default" on a long-lived test platform.
const GENERATED_MAPPING_FIELDS_BUDGET = ES_MAX_MAPPINGS - ES_MAPPING_FIELDS_HEADROOM;

const engine = new ElkClient({ node: 'http://localhost:9200' });

describe('Search engine mapping fields limit', () => {
  it('should count every mapped field like the engine does (objects, sub-properties and multi-fields)', () => {
    const properties = {
      name: { type: 'text', fields: { keyword: { type: 'keyword' } } }, // 2
      created_at: { type: 'date' }, // 1
      context_data: { // 1
        properties: {
          id: { type: 'keyword' }, // 1
          message: { type: 'text', fields: { keyword: { type: 'keyword' } } }, // 2
          nested: { properties: { a: { type: 'long' }, b: { type: 'boolean' } } }, // 3
        },
      },
    };
    expect(countMappingFields(properties)).toBe(10);
    expect(countMappingFields(undefined)).toBe(0);
    expect(countMappingFields({})).toBe(0);
  });

  it('should keep the default limit for small mappings and raise it with headroom above it', () => {
    const small = Object.fromEntries(Array.from({ length: 10 }, (_, i) => [`field_${i}`, { type: 'keyword' }]));
    expect(computeMappingFieldsLimit(small)).toBe(ES_MAX_MAPPINGS);
    const large = Object.fromEntries(Array.from({ length: ES_MAX_MAPPINGS + 10 }, (_, i) => [`field_${i}`, { type: 'keyword' }]));
    expect(computeMappingFieldsLimit(large)).toBe(ES_MAX_MAPPINGS + 10 + ES_MAPPING_FIELDS_HEADROOM);
  });

  it('should generate a mapping that fits the fields budget of the current schema', () => {
    const generated = engineMappingGenerator(engine);
    const fields = countMappingFields(generated);
    // The number is printed so a budget raise can be decided with the real figure in the CI log.
    console.log(`[mapping] ${fields} fields generated from the current schema (budget ${GENERATED_MAPPING_FIELDS_BUDGET}, default limit ${ES_MAX_MAPPINGS})`);
    expect(fields).toBeGreaterThan(0);
    expect(fields).toBeLessThanOrEqual(GENERATED_MAPPING_FIELDS_BUDGET);
  });

  it('should raise the limit of a long-lived index carrying legacy fields instead of failing the mapping update', () => {
    const generated = engineMappingGenerator(engine);
    const legacy = Object.fromEntries(Array.from({ length: LEGACY_FIELDS_OF_A_LONG_LIVED_PLATFORM }, (_, i) => [`legacy_attribute_${i}`, { type: 'keyword' }]));
    const longLivedIndexMapping = { ...legacy, ...generated };
    const fields = countMappingFields(longLivedIndexMapping);
    const limit = computeMappingFieldsLimit(longLivedIndexMapping);
    // The limit applied to the index always leaves the headroom above the mapping it must hold.
    expect(limit).toBeGreaterThanOrEqual(fields + ES_MAPPING_FIELDS_HEADROOM);
    expect(limit).toBeGreaterThanOrEqual(ES_MAX_MAPPINGS);
  });
});
