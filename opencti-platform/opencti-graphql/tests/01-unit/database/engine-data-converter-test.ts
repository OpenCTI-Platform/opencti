import { describe, expect, it, vi } from 'vitest';

// isSingleRelationsRef / isStixRefUnidirectionalRelationship depend on the global schema
// registration state (populated by importing the whole modules tree). Mocking them here keeps
// this test focused purely on engine-data-converter's own conversion/accumulation logic instead
// of the schema classification of specific ref names, and keeps it fast & deterministic.
// Other exports of these modules are preserved (importOriginal) since they are used transitively
// by other schema code (e.g. convertTypeToStixType -> isBasicRelationship -> isStixRefRelationship).
vi.mock('../../../src/schema/stixEmbeddedRelationship', async (importOriginal) => ({
  ...(await importOriginal<object>()),
  isSingleRelationsRef: (_entityType: string, key: string) => key === 'created-by',
}));
vi.mock('../../../src/schema/stixRefRelationship', async (importOriginal) => ({
  ...(await importOriginal<object>()),
  isStixRefUnidirectionalRelationship: (key: string) => key === 'object-marking',
}));

const { elRebuildRelation, elConvertHits } = await import('../../../src/database/engine-data-converter');

describe('engine-data-converter', () => {
  describe('elRebuildRelation', () => {
    const buildRelationConcept = () => ({
      internal_id: 'relation--id',
      base_type: 'RELATION',
      entity_type: 'uses',
      connections: [
        { internal_id: 'malware--id', role: 'uses_from', name: 'A malware', types: ['Malware', 'Basic-Object', 'Stix-Object', 'Stix-Core-Object', 'Stix-Domain-Object'] },
        { internal_id: 'tool--id', role: 'uses_to', name: 'A tool', types: ['Tool', 'Basic-Object', 'Stix-Object', 'Stix-Core-Object', 'Stix-Domain-Object'] },
      ],
    });

    it('reconstructs from/to information in place and drops the raw connections array', () => {
      const concept = buildRelationConcept();
      const relation: any = elRebuildRelation(concept);
      expect(relation.internal_id).toEqual(concept.internal_id);
      expect(relation.fromId).toEqual('malware--id');
      expect(relation.fromRole).toEqual('uses_from');
      expect(relation.toId).toEqual('tool--id');
      expect(relation.toRole).toEqual('uses_to');
      expect(relation.relationship_type).toEqual('uses');
      expect(relation).not.toHaveProperty('connections');
      // elRebuildRelation mutates and returns the very same object instead of allocating a new one
      expect(relation).toBe(concept);
      expect(concept).not.toHaveProperty('connections');
    });

    it('returns the concept unchanged when it is not a relation', () => {
      const concept = { internal_id: 'entity--id', base_type: 'ENTITY', entity_type: 'Report' };
      const result = elRebuildRelation(concept);
      expect(result).toBe(concept);
    });
  });

  describe('elConvertHits', () => {
    const buildEsHit = () => ({
      _index: 'test-index',
      _id: 'es-doc-id',
      sort: [1],
      _source: {
        internal_id: 'report--id',
        entity_type: 'Report',
        base_type: 'ENTITY',
        name: 'My Report',
        // Two raw denormalized fields for the SAME cleaned ref key ('object-marking'): must accumulate & dedup
        'rel_object-marking.internal_id': ['marking-A', 'marking-B', 'marking-A'],
        'rel_object-marking.standard_id': ['marking-A-std'],
        // Single-value ref: must be unwrapped to a scalar, not left as an array
        'rel_created-by.internal_id': ['author-1'],
        // Rule inference entry
        i_rule_some_rule: {
          def1: { inferred: { field1: 'value1', field2: 2 }, explanation: ['expl-id'] },
        },
        event_data: { some: 'thing' },
      },
    });

    it('leaves plain attributes untouched', async () => {
      const [converted]: any = await elConvertHits([buildEsHit()]);
      expect(converted.name).toEqual('My Report');
      expect(converted.id).toEqual('report--id');
      expect(converted._index).toEqual('test-index');
    });

    it('accumulates and deduplicates a multi-value ref spread across several raw rel_ fields', async () => {
      const [converted]: any = await elConvertHits([buildEsHit()]);
      expect(converted['object-marking']).toEqual(['marking-A', 'marking-B', 'marking-A-std']);
    });

    it('unwraps a single-value ref to a scalar instead of an array', async () => {
      const [converted]: any = await elConvertHits([buildEsHit()]);
      expect(converted['created-by']).toEqual('author-1');
    });

    it('extracts rule inferences into x_opencti_inferences', async () => {
      const [converted]: any = await elConvertHits([buildEsHit()]);
      expect(converted.x_opencti_inferences).toEqual([
        {
          rule: 'some_rule',
          explanation: ['expl-id'],
          attributes: [
            { field: 'field1', value: 'value1' },
            { field: 'field2', value: '2' },
          ],
        },
      ]);
    });

    it('stringifies event_data when present', async () => {
      const [converted]: any = await elConvertHits([buildEsHit()]);
      expect(converted.event_data).toEqual(JSON.stringify({ some: 'thing' }));
    });
  });
});
