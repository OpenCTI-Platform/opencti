import { describe, it, expect, vi, afterEach } from 'vitest';
// Registers the full schema (all entity types' attributes) as a side effect, required for
// getSchemaAttributeNames/getSchemaAttributes to find any concrete entity type (e.g. Case-Incident).
import '../../../src/modules/index';
import * as cacheModule from '../../../src/database/cache';
import { getSchemaAttributeNames, getSchemaAttributes } from '../../../src/domain/attribute';
import type { BasicStoreEntityCustomFieldDefinition } from '../../../src/modules/customField/custom-field-types';

const CONTEXT = {} as any;
const USER = { id: 'user-1' } as any;
const ENTITY_TYPE = 'Case-Incident';

const makeDefinition = (overrides: Partial<BasicStoreEntityCustomFieldDefinition> = {}): BasicStoreEntityCustomFieldDefinition => ({
  id: 'cf-id-1',
  standard_id: 'custom-field-definition--id-1',
  entity_type: 'CustomFieldDefinition',
  name: 'x_opencti_cf_score',
  label: 'Score',
  description: '',
  field_type: 'integer',
  entity_types: [ENTITY_TYPE],
  entity_type_settings: [],
  multiple: false,
  ...overrides,
} as unknown as BasicStoreEntityCustomFieldDefinition);

const seed = (...definitions: BasicStoreEntityCustomFieldDefinition[]) => {
  vi.spyOn(cacheModule, 'getEntitiesListFromCache').mockResolvedValue(definitions);
};

describe('attribute domain — custom field injection', () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe('getSchemaAttributeNames', () => {
    it('injects the custom field name for the given entity type, alongside the static schema attributes', async () => {
      seed(makeDefinition({ name: 'x_opencti_cf_score' }));
      const result = await getSchemaAttributeNames(CONTEXT, USER, [ENTITY_TYPE]);
      const ids = result.edges.map((e) => e.node.id);
      expect(ids).toContain('x_opencti_cf_score');
      // Static schema attributes (present regardless of custom fields) are still there
      expect(ids).toContain('name');
    });

    it('does not inject a custom field attached to a different entity type', async () => {
      seed(makeDefinition({ name: 'x_opencti_cf_score', entity_types: ['Report'] }));
      const result = await getSchemaAttributeNames(CONTEXT, USER, [ENTITY_TYPE]);
      const ids = result.edges.map((e) => e.node.id);
      expect(ids).not.toContain('x_opencti_cf_score');
    });

    it('does not duplicate a custom field name that already exists as a static attribute', async () => {
      // "name" already exists as a static attribute on every entity type
      seed(makeDefinition({ name: 'name' }));
      const result = await getSchemaAttributeNames(CONTEXT, USER, [ENTITY_TYPE]);
      const ids = result.edges.map((e) => e.node.id);
      expect(ids.filter((id) => id === 'name')).toHaveLength(1);
    });
  });

  describe('getSchemaAttributes', () => {
    it('injects a custom field as an additional attribute of its entity type, with the correct mapped type', async () => {
      seed(makeDefinition({
        name: 'x_opencti_cf_score',
        label: 'Score',
        field_type: 'integer',
        entity_type_settings: [{ entity_type: ENTITY_TYPE, mandatory: true }],
        multiple: false,
      }));
      const result = await getSchemaAttributes(CONTEXT, USER);
      const caseIncidentType = result.find((t) => t.type === ENTITY_TYPE);
      expect(caseIncidentType).toBeDefined();
      const injected = caseIncidentType?.attributes.find((a) => a.name === 'x_opencti_cf_score');
      expect(injected).toMatchObject({
        name: 'x_opencti_cf_score',
        type: 'numeric',
        label: 'Score',
        mandatory: true,
        mandatoryType: 'external',
        multiple: false,
        upsert: true,
      });
    });

    it('maps boolean and date custom field types to their respective schema attribute types', async () => {
      seed(
        makeDefinition({ id: 'cf-1', name: 'x_opencti_cf_flag', field_type: 'boolean' }),
        makeDefinition({ id: 'cf-2', name: 'x_opencti_cf_when', field_type: 'date' }),
      );
      const result = await getSchemaAttributes(CONTEXT, USER);
      const caseIncidentType = result.find((t) => t.type === ENTITY_TYPE);
      expect(caseIncidentType?.attributes.find((a) => a.name === 'x_opencti_cf_flag')).toMatchObject({ type: 'boolean' });
      expect(caseIncidentType?.attributes.find((a) => a.name === 'x_opencti_cf_when')).toMatchObject({ type: 'date' });
    });

    it('defaults non-mandatory custom fields to mandatoryType "no"', async () => {
      seed(makeDefinition({
        name: 'x_opencti_cf_score',
        entity_type_settings: [{ entity_type: ENTITY_TYPE, mandatory: false }],
      }));
      const result = await getSchemaAttributes(CONTEXT, USER);
      const caseIncidentType = result.find((t) => t.type === ENTITY_TYPE);
      expect(caseIncidentType?.attributes.find((a) => a.name === 'x_opencti_cf_score')).toMatchObject({
        mandatory: false,
        mandatoryType: 'no',
      });
    });
  });
});
