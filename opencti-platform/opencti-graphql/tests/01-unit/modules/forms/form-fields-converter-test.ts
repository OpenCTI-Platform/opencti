vi.mock('../../../../src/database/middleware-loader', () => ({
  storeLoadById: vi.fn(),
  internalLoadById: vi.fn(),
}));

vi.mock('../../../../src/database/utils', async (importOriginal) => {
  const actual = await importOriginal<typeof import('../../../../src/database/utils')>();
  return {
    ...actual,
    isEmptyField: vi.fn((v: any) => v === null || v === undefined || v === '' || (Array.isArray(v) && v.length === 0)),
  };
});

import { describe, it, expect, vi, beforeEach } from 'vitest';
import type { AuthContext } from '../../../../src/types/user';
import { internalLoadById } from '../../../../src/database/middleware-loader';
import { isEmptyField } from '../../../../src/database/utils';
import { convertFieldType, transformSpecialFields } from '../../../../src/modules/form/form-fields-converter';
import { SYSTEM_USER } from '../../../../src/utils/access';

const ctx = {} as AuthContext;
const user = SYSTEM_USER;

const makeField = (overrides = {}): any => ({
  id: 'f1',
  name: 'name',
  label: 'Name',
  type: 'text',
  attributeMapping: { entity: 'main_entity', attributeName: 'name' },
  ...overrides,
});

// ─── convertFieldType ─────────────────────────────────────────────────────────

describe('convertFieldType', () => {
  beforeEach(() => vi.clearAllMocks());

  describe('empty values', () => {
    it('should return null as-is', () => {
      expect(convertFieldType(null, makeField())).toBeNull();
    });

    it('should return undefined as-is', () => {
      expect(convertFieldType(undefined, makeField())).toBeUndefined();
    });

    it('should return empty string as-is', () => {
      expect(convertFieldType('', makeField())).toBe('');
    });
  });

  describe('checkbox / toggle fields', () => {
    it('should convert string "true" to boolean true', () => {
      expect(convertFieldType('true', makeField({ type: 'checkbox' }))).toBe(true);
    });

    it('should convert string "1" to boolean true', () => {
      expect(convertFieldType('1', makeField({ type: 'checkbox' }))).toBe(true);
    });

    it('should convert string "false" to boolean false', () => {
      expect(convertFieldType('false', makeField({ type: 'checkbox' }))).toBe(false);
    });

    it('should convert string "0" to boolean false', () => {
      expect(convertFieldType('0', makeField({ type: 'checkbox' }))).toBe(false);
    });

    it('should convert non-string truthy value to true', () => {
      expect(convertFieldType(1, makeField({ type: 'checkbox' }))).toBe(true);
    });

    it('should convert non-string falsy value to false', () => {
      expect(convertFieldType(0, makeField({ type: 'checkbox' }))).toBe(false);
    });

    it('should handle toggle type the same as checkbox', () => {
      expect(convertFieldType('true', makeField({ type: 'toggle' }))).toBe(true);
      expect(convertFieldType('false', makeField({ type: 'toggle' }))).toBe(false);
    });
  });

  describe('number fields', () => {
    it('should convert numeric string to number', () => {
      expect(convertFieldType('42', makeField({ type: 'number' }))).toBe(42);
    });

    it('should convert float string to float', () => {
      expect(convertFieldType('3.14', makeField({ type: 'number' }))).toBe(3.14);
    });

    it('should return the string as-is when not a valid number', () => {
      expect(convertFieldType('abc', makeField({ type: 'number' }))).toBe('abc');
    });

    it('should return number as-is when already a number', () => {
      expect(convertFieldType(42, makeField({ type: 'number' }))).toBe(42);
    });
  });

  describe('other field types', () => {
    it('should return value as-is for text fields', () => {
      expect(convertFieldType('hello', makeField({ type: 'text' }))).toBe('hello');
    });

    it('should return value as-is for unknown field types', () => {
      expect(convertFieldType('anything', makeField({ type: 'custom' }))).toBe('anything');
    });
  });
});

// ─── transformSpecialFields ───────────────────────────────────────────────────

describe('transformSpecialFields', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(internalLoadById).mockResolvedValue(undefined as any);
    vi.mocked(isEmptyField).mockImplementation(
      (v: any) => v === null || v === undefined || v === '' || (Array.isArray(v) && v.length === 0),
    );
  });

  describe('no special fields', () => {
    it('should return data unchanged when no fields match', async () => {
      const data = { name: 'Test', value: 42 };
      const result = await transformSpecialFields(ctx, user, data, []);
      expect(result).toEqual({ name: 'Test', value: 42 });
    });

    it('should return a new object (not the same reference)', async () => {
      const data = { name: 'Test' };
      const result = await transformSpecialFields(ctx, user, data, []);
      expect(result).not.toBe(data);
    });

    it('should skip fields with no value', async () => {
      const data = { name: 'Test' };
      const fields = [makeField({ type: 'createdBy', attributeMapping: { entity: 'main_entity', attributeName: 'createdBy' } })];
      const result = await transformSpecialFields(ctx, user, data, fields);
      expect(internalLoadById).not.toHaveBeenCalled();
      expect(result).toEqual({ name: 'Test' });
    });
  });

  describe('objectMarking field', () => {
    it('should skip markings where entity is not found', async () => {
      vi.mocked(internalLoadById).mockResolvedValue(undefined as any);

      const data = { objectMarking: ['unknown-id'] };
      const fields = [makeField({ type: 'objectMarking', attributeMapping: { entity: 'main_entity', attributeName: 'objectMarking' } })];

      const result = await transformSpecialFields(ctx, user, data, fields, false);

      expect(result.objectMarking).toEqual([]);
    });

    it('should skip objectMarking when value is not an array', async () => {
      const data = { objectMarking: 'not-an-array' };
      const fields = [makeField({ type: 'objectMarking', attributeMapping: { entity: 'main_entity', attributeName: 'objectMarking' } })];

      await transformSpecialFields(ctx, user, data, fields, false);

      expect(internalLoadById).not.toHaveBeenCalled();
    });
  });

  describe('objectLabel field', () => {
    it('should transform labels to object format for entities', async () => {
      const data = { objectLabel: ['label1', 'label2'] };
      const fields = [makeField({ type: 'objectLabel', attributeMapping: { entity: 'main_entity', attributeName: 'objectLabel' } })];

      const result = await transformSpecialFields(ctx, user, data, fields, false);

      expect(result.objectLabel).toEqual([{ value: 'label1' }, { value: 'label2' }]);
    });

    it('should keep labels as simple strings for relationships', async () => {
      const data = { labels: ['label1', 'label2'] };
      const fields = [makeField({ type: 'objectLabel', attributeMapping: { entity: 'main_entity', attributeName: 'labels' } })];

      const result = await transformSpecialFields(ctx, user, data, fields, true);

      expect(result.labels).toEqual(['label1', 'label2']);
    });

    it('should skip objectLabel when value is not an array', async () => {
      const data = { objectLabel: 'not-an-array' };
      const fields = [makeField({ type: 'objectLabel', attributeMapping: { entity: 'main_entity', attributeName: 'objectLabel' } })];

      const result = await transformSpecialFields(ctx, user, data, fields, false);

      expect(result.objectLabel).toBe('not-an-array');
    });
  });

  describe('files field', () => {
    it('should transform files to x_opencti_files format for entities', async () => {
      const data = {
        files: [
          { name: 'report.pdf', data: 'base64content', mime_type: 'application/pdf' },
        ],
      };
      const fields = [makeField({ type: 'files', attributeMapping: { entity: 'main_entity', attributeName: 'files' } })];

      const result = await transformSpecialFields(ctx, user, data, fields, false);

      expect(result.x_opencti_files).toEqual([
        { name: 'report.pdf', data: 'base64content', mime_type: 'application/pdf' },
      ]);
    });

    it('should use default mime_type when not provided', async () => {
      const data = { files: [{ name: 'file.bin', data: 'abc' }] };
      const fields = [makeField({ type: 'files', attributeMapping: { entity: 'main_entity', attributeName: 'files' } })];

      const result = await transformSpecialFields(ctx, user, data, fields, false);

      expect(result.x_opencti_files[0].mime_type).toBe('application/octet-stream');
    });

    it('should not set x_opencti_files for relationships', async () => {
      const data = { files: [{ name: 'file.bin', data: 'abc' }] };
      const fields = [makeField({ type: 'files', attributeMapping: { entity: 'main_entity', attributeName: 'files' } })];

      const result = await transformSpecialFields(ctx, user, data, fields, true);

      expect(result.x_opencti_files).toBeUndefined();
    });

    it('should skip files when value is not an array', async () => {
      const data = { files: 'not-an-array' };
      const fields = [makeField({ type: 'files', attributeMapping: { entity: 'main_entity', attributeName: 'files' } })];

      const result = await transformSpecialFields(ctx, user, data, fields, false);

      expect(result.x_opencti_files).toBeUndefined();
    });
  });

  describe('externalReferences field', () => {
    it('should skip entries where entity is not found', async () => {
      vi.mocked(internalLoadById).mockResolvedValue(undefined as any);

      const data = { externalReferences: ['unknown-id'] };
      const fields = [makeField({ type: 'externalReferences', attributeMapping: { entity: 'main_entity', attributeName: 'externalReferences' } })];

      const result = await transformSpecialFields(ctx, user, data, fields, false);

      expect(result.externalReferences).toEqual([]);
    });
  });

  describe('relationship passthrough fields', () => {
    it('should apply non-special fields directly for relationships', async () => {
      const data = { fields: { confidence: 80, lang: 'en' } };
      const fields = [
        makeField({ type: 'number', attributeMapping: { entity: 'main_entity', attributeName: 'confidence' } }),
        makeField({ id: 'f2', type: 'text', attributeMapping: { entity: 'main_entity', attributeName: 'lang' } }),
      ];

      const result = await transformSpecialFields(ctx, user, data, fields, true);

      expect(result.confidence).toBe(80);
      expect(result.lang).toBe('en');
    });

    it('should delete fields object after processing for relationships', async () => {
      const data = { fields: { confidence: 80 } };
      const fields = [makeField({ type: 'number', attributeMapping: { entity: 'main_entity', attributeName: 'confidence' } })];

      const result = await transformSpecialFields(ctx, user, data, fields, true);

      expect(result.fields).toBeUndefined();
    });

    it('should not delete fields for entities', async () => {
      const data = { fields: { confidence: 80 } };
      const fields = [makeField({ type: 'number', attributeMapping: { entity: 'main_entity', attributeName: 'confidence' } })];

      const result = await transformSpecialFields(ctx, user, data, fields, false);

      expect(result.fields).toEqual({ confidence: 80 });
    });
  });
});
