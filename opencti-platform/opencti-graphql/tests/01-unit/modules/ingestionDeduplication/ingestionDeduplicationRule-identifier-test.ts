import { describe, expect, it } from 'vitest';
import { ENTITY_TYPE_INGESTION_DEDUPLICATION_RULE } from '../../../../src/modules/ingestionDeduplication/ingestionDeduplicationRule-types';
import { generateStandardId } from '../../../../src/schema/identifier';

import '../../../../src/modules/ingestionDeduplication/ingestionDeduplicationRule';

describe('IngestionDeduplicationRule identifier', () => {
  const generateId = (userId: string, targetType: string) => generateStandardId(
    ENTITY_TYPE_INGESTION_DEDUPLICATION_RULE,
    { user_id: userId, target_type: targetType, excluded_fields: ['modified'] },
  );

  it('should give the same identifier to the same user and type', () => {
    expect(generateId('user-1', 'Malware')).toEqual(generateId('user-1', 'Malware'));
  });

  it('should give different identifiers to another user or another type', () => {
    const identifiers = [
      generateId('user-1', 'Malware'),
      generateId('user-2', 'Malware'),
      generateId('user-1', 'Tool'),
    ];
    expect(new Set(identifiers).size).toEqual(identifiers.length);
  });
});
