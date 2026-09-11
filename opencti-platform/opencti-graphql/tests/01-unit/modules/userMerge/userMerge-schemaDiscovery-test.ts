import { describe, expect, it, vi } from 'vitest';
import '../../../../src/modules/index';
import { findRegisterRow } from '../../../../src/modules/userMerge/userMerge-register';
import { discoverUserIdAttributes } from '../../../../src/modules/userMerge/userMerge-scalarDiscovery';
import { USER_MERGE_SCALAR_COMPLEMENTS } from '../../../../src/modules/userMerge/userMerge-scalarRules';
import { userMergeScalarResolution } from '../../../../src/modules/userMerge/userMerge-scalarTargets';
import { ENTITY_TYPE_USER } from '../../../../src/schema/internalObject';
import { schemaAttributesDefinition } from '../../../../src/schema/schema-attributes';

describe('userMerge schema discovery', () => {
  it('should give a disposition to every attribute the schema declares as a user reference', () => {
    expect(userMergeScalarResolution().unassigned).toEqual([]);
  });

  it('should distinguish the entities carrying the same attribute name', () => {
    const userId = discoverUserIdAttributes().find((attribute) => attribute.name === 'user_id');
    expect(userId?.entityTypes).toContain('Sync');
    expect(userId?.entityTypes).toContain('User-Account');
  });

  it('should treat an attribute declared on an abstract root as global', () => {
    const creatorId = discoverUserIdAttributes().find((attribute) => attribute.name === 'creator_id');
    expect(creatorId?.entityTypes).toBeUndefined();
    expect(creatorId?.multiple).toEqual(true);
  });

  /**
   * The schema registration guards the type and the format of a shared attribute name, but not
   * its cardinality, so two entities may legitimately reach here disagreeing on it. Resolving
   * that on the first declaration seen would rewrite one of them with the wrong script.
   */
  it('should refuse an attribute name carried with conflicting cardinalities', () => {
    const userReference = { type: 'string', format: 'id', entityTypes: [ENTITY_TYPE_USER] };
    const divergent: Record<string, Map<string, unknown>> = {
      Sync: new Map([['owner_id', { ...userReference, name: 'owner_id', multiple: false }]]),
      Feed: new Map([['owner_id', { ...userReference, name: 'owner_id', multiple: true }]]),
    };
    vi.spyOn(schemaAttributesDefinition, 'getRegisteredTypes').mockReturnValue(Object.keys(divergent));
    vi.spyOn(schemaAttributesDefinition, 'getAttributes').mockImplementation((entityType: string) => divergent[entityType] as never);
    try {
      expect(() => discoverUserIdAttributes()).toThrowError(/conflicting cardinalities/);
    } finally {
      vi.restoreAllMocks();
    }
  });

  it('should answer for an existing register row on every target', () => {
    userMergeScalarResolution().targets.forEach((target) => {
      expect(findRegisterRow(target.registerRow), target.id).toBeDefined();
    });
  });

  it('should say why each excluded attribute is not rewritten here', () => {
    userMergeScalarResolution().excluded.forEach((exclusion) => {
      expect(exclusion.detail.length, exclusion.key).toBeGreaterThan(0);
    });
  });

  /**
   * A complement exists because a declaration is missing or wrong. Once it is fixed the
   * attribute arrives through discovery and the complement becomes a duplicate.
   */
  it('should drop a complement once the schema starts yielding it', () => {
    const discovered = discoverUserIdAttributes().flatMap((attribute) => {
      return (attribute.entityTypes ?? ['*']).map((entityType) => `${entityType}.${attribute.name}`);
    });
    const redundant = USER_MERGE_SCALAR_COMPLEMENTS
      .flatMap((complement) => (complement.entityTypes ?? ['*']).map((entityType) => `${entityType}.${complement.path}`))
      .filter((key) => discovered.includes(key));
    expect(redundant).toEqual([]);
  });
});
