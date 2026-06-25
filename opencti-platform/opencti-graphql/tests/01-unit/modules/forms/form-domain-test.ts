import { describe, it, expect } from 'vitest';
import { resolveMainEntityAuthorFromValues } from '../../../../src/modules/form/form-domain';
import { FormFieldType, type FormSchemaDefinition } from '../../../../src/modules/form/form-types';

// ─── Helpers ────────────────────────────────────────────────────────────────

const makeCreatedByField = (name: string) => ({
  id: name,
  name,
  label: name,
  type: FormFieldType.CreatedBy,
  required: false,
  attributeMapping: { entity: 'main_entity', attributeName: 'createdBy' },
});

const baseSchema = (overrides: Partial<FormSchemaDefinition> = {}): FormSchemaDefinition => ({
  mainEntityType: 'Report',
  version: '2.0',
  fields: [],
  ...overrides,
});

// ─── resolveMainEntityAuthorFromValues ──────────────────────────────────────

describe('resolveMainEntityAuthorFromValues', () => {
  describe('direct values (single-entity mode)', () => {
    it('resolves author when field name is the default "createdBy"', () => {
      const schema = baseSchema({ fields: [makeCreatedByField('createdBy')] });
      const values = { createdBy: 'identity--org-1' };
      expect(resolveMainEntityAuthorFromValues(schema, values)).toBe('identity--org-1');
    });

    it('resolves author when field has a custom name from a renamed label', () => {
      const schema = baseSchema({ fields: [makeCreatedByField('author')] });
      const values = { author: 'identity--org-1' };
      expect(resolveMainEntityAuthorFromValues(schema, values)).toBe('identity--org-1');
    });

    it('returns null when the value is absent', () => {
      const schema = baseSchema({ fields: [makeCreatedByField('author')] });
      expect(resolveMainEntityAuthorFromValues(schema, {})).toBeNull();
    });

    it('resolves author from an option object with a value property', () => {
      const schema = baseSchema({ fields: [makeCreatedByField('author')] });
      const values = { author: { value: 'identity--org-1', label: 'Org 1' } };
      expect(resolveMainEntityAuthorFromValues(schema, values)).toBe('identity--org-1');
    });
  });

  describe('mainEntityFields mode (multiple=false, additional fields)', () => {
    it('resolves author from mainEntityFields when field name is the default "createdBy"', () => {
      const schema = baseSchema({ fields: [makeCreatedByField('createdBy')] });
      const values = { mainEntityFields: { createdBy: 'identity--org-2' } };
      expect(resolveMainEntityAuthorFromValues(schema, values)).toBe('identity--org-2');
    });

    it('resolves author from mainEntityFields when field has a custom name', () => {
      const schema = baseSchema({ fields: [makeCreatedByField('author')] });
      const values = { mainEntityFields: { author: 'identity--org-2' } };
      expect(resolveMainEntityAuthorFromValues(schema, values)).toBe('identity--org-2');
    });
  });

  describe('mainEntityGroups mode (multiple=true)', () => {
    it('resolves author from the first group when field name is the default "createdBy"', () => {
      const schema = baseSchema({ fields: [makeCreatedByField('createdBy')] });
      const values = { mainEntityGroups: [{ createdBy: 'identity--org-3' }, { createdBy: 'identity--org-4' }] };
      expect(resolveMainEntityAuthorFromValues(schema, values)).toBe('identity--org-3');
    });

    it('resolves author from the first group when field has a custom name', () => {
      const schema = baseSchema({ fields: [makeCreatedByField('auteur')] });
      const values = { mainEntityGroups: [{ auteur: 'identity--org-3' }] };
      expect(resolveMainEntityAuthorFromValues(schema, values)).toBe('identity--org-3');
    });

    it('returns null when mainEntityGroups is empty', () => {
      const schema = baseSchema({ fields: [makeCreatedByField('createdBy')] });
      const values = { mainEntityGroups: [] };
      expect(resolveMainEntityAuthorFromValues(schema, values)).toBeNull();
    });
  });

  describe('schema without a createdBy field', () => {
    it('falls back to "createdBy" key and resolves correctly when present', () => {
      const schema = baseSchema({ fields: [] }); // no createdBy field
      const values = { createdBy: 'identity--org-5' };
      expect(resolveMainEntityAuthorFromValues(schema, values)).toBe('identity--org-5');
    });

    it('returns null when no createdBy field in schema and value is absent', () => {
      const schema = baseSchema({ fields: [] });
      expect(resolveMainEntityAuthorFromValues(schema, {})).toBeNull();
    });
  });
});
