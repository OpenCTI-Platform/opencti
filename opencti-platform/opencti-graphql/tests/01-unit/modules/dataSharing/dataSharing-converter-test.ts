import { describe, expect, it } from 'vitest';
import convertFeedToStix from '../../../../src/modules/dataSharing/feed-converter';
import convertTaxiiCollectionToStix from '../../../../src/modules/dataSharing/taxiiCollection-converter';
import convertStreamCollectionToStix from '../../../../src/modules/dataSharing/streamCollection-converter';

const BASE_INSTANCE = {
  _index: 'opencti_internal_objects-000001',
  internal_id: 'aaaaaaaa-aaaa-4aaa-aaaa-aaaaaaaaaaaa',
  standard_id: 'x-opencti-feed--aaaaaaaa-aaaa-4aaa-aaaa-aaaaaaaaaaaa',
  x_opencti_stix_ids: [],
  created_at: '2025-01-01T00:00:00.000Z',
  updated_at: '2025-01-02T00:00:00.000Z',
  base_type: 'ENTITY' as const,
  parent_types: ['Basic-Object', 'Internal-Object'],
};

describe('Feed converter', () => {
  it('should include feed_public and feed_public_user_id when set', () => {
    const instance = {
      ...BASE_INSTANCE,
      standard_id: 'x-opencti-feed--aaaaaaaa-aaaa-4aaa-aaaa-aaaaaaaaaaaa',
      entity_type: 'Feed',
      name: 'Test Feed',
      description: 'Test feed description',
      filters: '{}',
      separator: ';',
      rolling_time: 60,
      include_header: true,
      feed_public: true,
      feed_public_user_id: 'bbbbbbbb-bbbb-4bbb-bbbb-bbbbbbbbbbbb',
      feed_types: ['Report'],
      feed_date_attribute: 'created_at',
      feed_attributes: [],
    } as any;

    const result = convertFeedToStix(instance);
    expect(result.feed_public).toBe(true);
    expect(result.feed_public_user_id).toBe('bbbbbbbb-bbbb-4bbb-bbbb-bbbbbbbbbbbb');
  });

  it('should default feed_public_user_id to empty string when not set', () => {
    const instance = {
      ...BASE_INSTANCE,
      standard_id: 'x-opencti-feed--cccccccc-cccc-4ccc-cccc-cccccccccccc',
      entity_type: 'Feed',
      name: 'Test Feed No User',
      description: 'Test feed without public user',
      filters: '{}',
      separator: ',',
      rolling_time: 30,
      include_header: false,
      feed_public: false,
      feed_public_user_id: undefined,
      feed_types: ['Malware'],
      feed_date_attribute: 'created_at',
      feed_attributes: [],
    } as any;

    const result = convertFeedToStix(instance);
    expect(result.feed_public).toBe(false);
    expect(result.feed_public_user_id).toBe('');
  });
});

describe('TaxiiCollection converter', () => {
  it('should include taxii_public_user_id when set', () => {
    const instance = {
      ...BASE_INSTANCE,
      standard_id: 'x-opencti-taxii-collection--dddddddd-dddd-4ddd-dddd-dddddddddddd',
      entity_type: 'TaxiiCollection',
      name: 'Test Taxii',
      description: 'Test taxii description',
      filters: '{}',
      taxii_public: true,
      taxii_public_user_id: 'eeeeeeee-eeee-4eee-eeee-eeeeeeeeeeee',
      include_inferences: false,
      score_to_confidence: false,
    } as any;

    const result = convertTaxiiCollectionToStix(instance);
    expect(result.taxii_public_user_id).toBe('eeeeeeee-eeee-4eee-eeee-eeeeeeeeeeee');
  });

  it('should handle undefined taxii_public_user_id', () => {
    const instance = {
      ...BASE_INSTANCE,
      standard_id: 'x-opencti-taxii-collection--ffffffff-ffff-4fff-ffff-ffffffffffff',
      entity_type: 'TaxiiCollection',
      name: 'Test Taxii No User',
      description: 'Test taxii without public user',
      filters: '{}',
      taxii_public: false,
      taxii_public_user_id: undefined,
      include_inferences: true,
      score_to_confidence: true,
    } as any;

    const result = convertTaxiiCollectionToStix(instance);
    expect(result.taxii_public_user_id).toBeUndefined();
  });
});

describe('StreamCollection converter', () => {
  it('should include stream_public_user_id when set', () => {
    const instance = {
      ...BASE_INSTANCE,
      standard_id: 'x-opencti-stream-collection--11111111-1111-4111-8111-111111111111',
      entity_type: 'StreamCollection',
      name: 'Test Stream',
      description: 'Test stream description',
      filters: '{}',
      stream_public: true,
      stream_public_user_id: '22222222-2222-4222-8222-222222222222',
      stream_live: true,
    } as any;

    const result = convertStreamCollectionToStix(instance);
    expect(result.stream_public_user_id).toBe('22222222-2222-4222-8222-222222222222');
  });

  it('should handle undefined stream_public_user_id', () => {
    const instance = {
      ...BASE_INSTANCE,
      standard_id: 'x-opencti-stream-collection--33333333-3333-4333-8333-333333333333',
      entity_type: 'StreamCollection',
      name: 'Test Stream No User',
      description: 'Test stream without public user',
      filters: '{}',
      stream_public: false,
      stream_public_user_id: undefined,
      stream_live: false,
    } as any;

    const result = convertStreamCollectionToStix(instance);
    expect(result.stream_public_user_id).toBeUndefined();
  });
});
