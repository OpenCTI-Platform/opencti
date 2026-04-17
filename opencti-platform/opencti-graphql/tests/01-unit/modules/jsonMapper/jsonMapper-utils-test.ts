import { describe, expect, it } from 'vitest';
import { parseJsonMapper } from '../../../../src/modules/internal/jsonMapper/jsonMapper-utils';
import { JsonMapperRepresentationType } from '../../../../src/modules/internal/jsonMapper/jsonMapper-types';

const makeBaseRepresentation = (overrides = {}) => ({
  id: 'rep-1',
  type: JsonMapperRepresentationType.Entity,
  target: { entity_type: 'Malware', path: '$.malware' },
  attributes: [],
  ...overrides,
});

describe('Function parseJsonMapper()', () => {
  describe('representations parsing', () => {
    it('should return representations unchanged when already an array', () => {
      const representations = [makeBaseRepresentation()];
      const result = parseJsonMapper({ name: 'test', representations });
      expect(result.representations).toEqual(representations);
    });

    it('should parse representations when given as a JSON string', () => {
      const representations = [makeBaseRepresentation()];
      const result = parseJsonMapper({ name: 'test', representations: JSON.stringify(representations) });
      expect(result.representations).toEqual(representations);
    });

    it('should default to empty array when representations is undefined', () => {
      const result = parseJsonMapper({ name: 'test' });
      expect(result.representations).toEqual([]);
    });

    it('should default to empty array when mapper is undefined', () => {
      const result = parseJsonMapper(undefined);
      expect(result.representations).toEqual([]);
    });

    it('should throw a FunctionalError when representations is an invalid JSON string', () => {
      expect(() => parseJsonMapper({ name: 'broken', representations: 'not valid json {' }))
        .toThrow('Could not parse JSON mapper: representations is not a valid JSON');
    });

    it('should spread all other mapper properties into the result', () => {
      const result = parseJsonMapper({ name: 'my-mapper', internal_id: 'abc-123', representations: [] });
      expect(result.name).toBe('my-mapper');
      expect(result.internal_id).toBe('abc-123');
    });
  });

  describe('based_on identifier normalization', () => {
    it('should keep based_on.identifier unchanged when already an array (new format)', () => {
      const identifierArray = [{ identifier: 'id-A', representation: 'rep-2' }];
      const representations = [
        makeBaseRepresentation({
          attributes: [{
            key: 'objectLabel',
            mode: 'base',
            based_on: { identifier: identifierArray, representations: ['rep-2'] },
          }],
        }),
      ];

      const result = parseJsonMapper({ name: 'test', representations });
      const attr = result.representations[0].attributes[0] as any;
      expect(attr.based_on.identifier).toEqual(identifierArray);
    });

    it('should convert based_on.identifier string to array of objects (old format)', () => {
      const representations = [
        makeBaseRepresentation({
          attributes: [{
            key: 'objectLabel',
            mode: 'base',
            based_on: { identifier: 'my-identifier', representations: ['rep-2', 'rep-3'] },
          }],
        }),
      ];

      const result = parseJsonMapper({ name: 'test', representations });
      const attr = result.representations[0].attributes[0] as any;
      expect(attr.based_on.identifier).toEqual([
        { identifier: 'my-identifier', representation: 'rep-2' },
        { identifier: 'my-identifier', representation: 'rep-3' },
      ]);
    });

    it('should convert old format from a JSON string representation', () => {
      const representations = [
        makeBaseRepresentation({
          attributes: [{
            key: 'objectLabel',
            mode: 'base',
            based_on: { identifier: 'my-identifier', representations: ['rep-2'] },
          }],
        }),
      ];

      const result = parseJsonMapper({ name: 'test', representations: JSON.stringify(representations) });
      const attr = result.representations[0].attributes[0] as any;
      expect(attr.based_on.identifier).toEqual([
        { identifier: 'my-identifier', representation: 'rep-2' },
      ]);
    });

    it('should result in an empty identifier array when based_on.representations is empty (old format)', () => {
      const representations = [
        makeBaseRepresentation({
          attributes: [{
            key: 'objectLabel',
            mode: 'base',
            based_on: { identifier: 'my-identifier', representations: [] },
          }],
        }),
      ];

      const result = parseJsonMapper({ name: 'test', representations });
      const attr = result.representations[0].attributes[0] as any;
      expect(attr.based_on.identifier).toEqual([]);
    });

    it('should result in an empty identifier array when based_on.representations is absent (old format)', () => {
      const representations = [
        makeBaseRepresentation({
          attributes: [{
            key: 'objectLabel',
            mode: 'base',
            based_on: { identifier: 'my-identifier' },
          }],
        }),
      ];

      const result = parseJsonMapper({ name: 'test', representations });
      const attr = result.representations[0].attributes[0] as any;
      expect(attr.based_on.identifier).toEqual([]);
    });

    it('should not modify attributes with mode "simple"', () => {
      const representations = [
        makeBaseRepresentation({
          attributes: [{
            key: 'name',
            mode: 'simple',
            attr_path: { path: '$.name' },
          }],
        }),
      ];

      const result = parseJsonMapper({ name: 'test', representations });
      const attr = result.representations[0].attributes[0] as any;
      expect(attr.attr_path).toEqual({ path: '$.name' });
      expect(attr.based_on).toBeUndefined();
    });

    it('should not modify attributes with mode "complex"', () => {
      const representations = [
        makeBaseRepresentation({
          attributes: [{
            key: 'name',
            mode: 'complex',
            complex_path: { formula: '$.a + $.b' },
          }],
        }),
      ];

      const result = parseJsonMapper({ name: 'test', representations });
      const attr = result.representations[0].attributes[0] as any;
      expect(attr.complex_path).toEqual({ formula: '$.a + $.b' });
      expect(attr.based_on).toBeUndefined();
    });

    it('should handle multiple representations each with mixed attribute modes', () => {
      const representations = [
        makeBaseRepresentation({
          id: 'rep-1',
          attributes: [{
            key: 'name',
            mode: 'simple',
            attr_path: { path: '$.name' },
          }],
        }),
        {
          id: 'rep-2',
          type: JsonMapperRepresentationType.Entity,
          target: { entity_type: 'ThreatActor', path: '$.actor' },
          attributes: [
            {
              key: 'objectLabel',
              mode: 'base',
              based_on: { identifier: 'old-id', representations: ['rep-1'] },
            },
          ],
        },
      ];

      const result = parseJsonMapper({ name: 'test', representations });
      // first rep's simple attribute untouched
      expect((result.representations[0].attributes[0] as any).attr_path).toEqual({ path: '$.name' });
      // second rep's based_on converted
      expect((result.representations[1].attributes[0] as any).based_on.identifier).toEqual([
        { identifier: 'old-id', representation: 'rep-1' },
      ]);
    });
  });
});
