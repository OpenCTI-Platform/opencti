import { describe, expect, it } from 'vitest';
import { checkStixCoreRelationshipMapping } from '../../../src/database/stix';
import { ENTITY_TYPE_MALWARE } from '../../../src/schema/stixDomainObject';
import { ENTITY_HASHED_OBSERVABLE_ARTIFACT, ENTITY_HASHED_OBSERVABLE_STIX_FILE } from '../../../src/schema/stixCyberObservable';
import { RELATION_INTERPRETED_BY } from '../../../src/schema/stixCoreRelationship';

describe('Interpreted-by relationship mapping', () => {
  it('should allow File -> File interpreted-by relationship', () => {
    const isValid = checkStixCoreRelationshipMapping(
      ENTITY_HASHED_OBSERVABLE_STIX_FILE,
      ENTITY_HASHED_OBSERVABLE_STIX_FILE,
      RELATION_INTERPRETED_BY,
    );
    expect(isValid).toBe(true);
  });

  it('should allow Artifact -> Artifact interpreted-by relationship', () => {
    const isValid = checkStixCoreRelationshipMapping(
      ENTITY_HASHED_OBSERVABLE_ARTIFACT,
      ENTITY_HASHED_OBSERVABLE_ARTIFACT,
      RELATION_INTERPRETED_BY,
    );
    expect(isValid).toBe(true);
  });

  it('should allow File -> Artifact interpreted-by relationship', () => {
    const isValid = checkStixCoreRelationshipMapping(
      ENTITY_HASHED_OBSERVABLE_STIX_FILE,
      ENTITY_HASHED_OBSERVABLE_ARTIFACT,
      RELATION_INTERPRETED_BY,
    );
    expect(isValid).toBe(true);
  });

  it('should allow Artifact -> File interpreted-by relationship', () => {
    const isValid = checkStixCoreRelationshipMapping(
      ENTITY_HASHED_OBSERVABLE_ARTIFACT,
      ENTITY_HASHED_OBSERVABLE_STIX_FILE,
      RELATION_INTERPRETED_BY,
    );
    expect(isValid).toBe(true);
  });

  it('should reject unrelated interpreted-by mapping', () => {
    const isValid = checkStixCoreRelationshipMapping(
      ENTITY_TYPE_MALWARE,
      ENTITY_HASHED_OBSERVABLE_STIX_FILE,
      RELATION_INTERPRETED_BY,
    );
    expect(isValid).toBe(false);
  });
});
