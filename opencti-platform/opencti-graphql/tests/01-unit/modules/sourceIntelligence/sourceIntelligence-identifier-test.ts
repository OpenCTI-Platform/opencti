import { describe, expect, it } from 'vitest';
import { generateStandardId } from '../../../../src/schema/identifier';
import { ENTITY_TYPE_COLLECTION_GAP, ENTITY_TYPE_SOURCE } from '../../../../src/modules/sourceIntelligence/sourceIntelligence-types';

import '../../../../src/modules/sourceIntelligence/sourceIntelligence';

describe('Source intelligence identifiers', () => {
  it('should derive one stable source id per kind and referenced element', () => {
    const connector = generateStandardId(ENTITY_TYPE_SOURCE, { source_kind: 'connector', ref_id: 'connector-1' });
    expect(connector).toMatch(/^source--/);
    expect(generateStandardId(ENTITY_TYPE_SOURCE, { source_kind: 'connector', ref_id: 'connector-1', name: 'Renamed' })).toEqual(connector);
    expect(generateStandardId(ENTITY_TYPE_SOURCE, { source_kind: 'connector', ref_id: 'connector-2' })).not.toEqual(connector);
    expect(generateStandardId(ENTITY_TYPE_SOURCE, { source_kind: 'author', ref_id: 'connector-1' })).not.toEqual(connector);
  });

  it('should derive one stable collection gap id per PIR criterion', () => {
    const gap = generateStandardId(ENTITY_TYPE_COLLECTION_GAP, { pir_id: 'pir-1', criterion_key: 'criterion-a' });
    expect(gap).toMatch(/^collectiongap--/);
    expect(generateStandardId(ENTITY_TYPE_COLLECTION_GAP, { pir_id: 'pir-1', criterion_key: 'criterion-a', coverage_score: 12 })).toEqual(gap);
    expect(generateStandardId(ENTITY_TYPE_COLLECTION_GAP, { pir_id: 'pir-1', criterion_key: 'criterion-b' })).not.toEqual(gap);
    expect(generateStandardId(ENTITY_TYPE_COLLECTION_GAP, { pir_id: 'pir-2', criterion_key: 'criterion-a' })).not.toEqual(gap);
  });
});
