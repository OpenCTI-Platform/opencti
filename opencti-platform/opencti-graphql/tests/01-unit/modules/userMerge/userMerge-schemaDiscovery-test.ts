import { describe, expect, it, vi } from 'vitest';
import '../../../../src/modules/index';
import { findRegisterRow } from '../../../../src/modules/userMerge/userMerge-register';
import { discoverUserIdAttributes } from '../../../../src/modules/userMerge/userMerge-scalarDiscovery';
import { assertUserMergeTargetDeclared, userMergeScalarResolution } from '../../../../src/modules/userMerge/userMerge-scalarTargets';
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

  it('should reach a user reference held inside a standard object attribute', () => {
    const creatorId = discoverUserIdAttributes().find((attribute) => attribute.name === 'metaData.creator_id');
    expect(creatorId).toEqual({ name: 'metaData.creator_id', multiple: false, entityTypes: ['InternalFile'] });
    const target = userMergeScalarResolution().targets.find((candidate) => candidate.id === 'internal-file-metadata-creator-id');
    expect(target).toEqual({
      id: 'internal-file-metadata-creator-id',
      registerRow: 'internal-file.metadata-creator-id',
      entityTypes: ['InternalFile'],
      path: 'metaData.creator_id',
      shape: 'single',
    });
  });

  it('should reach the version author under each nested root of a workflow definition', () => {
    const targets = userMergeScalarResolution().targets.filter((target) => target.registerRow === 'workflow-definition.versions-created-by');
    expect(targets).toEqual([
      {
        id: 'workflow-definition-all-versions-created-by',
        registerRow: 'workflow-definition.versions-created-by',
        entityTypes: ['WorkflowDefinition'],
        path: 'all_versions.createdBy',
        shape: 'object-array',
        nestedRoot: 'all_versions',
      },
      {
        id: 'workflow-definition-draft-version-created-by',
        registerRow: 'workflow-definition.versions-created-by',
        entityTypes: ['WorkflowDefinition'],
        path: 'draft_version.createdBy',
        shape: 'single',
        nestedRoot: 'draft_version',
      },
      {
        id: 'workflow-definition-published-version-created-by',
        registerRow: 'workflow-definition.versions-created-by',
        entityTypes: ['WorkflowDefinition'],
        path: 'published_version.createdBy',
        shape: 'single',
        nestedRoot: 'published_version',
      },
    ]);
  });

  it('should record the nested root and the object array of a walked user reference', () => {
    const userReference = { type: 'string', format: 'id', entityTypes: [ENTITY_TYPE_USER], multiple: false };
    const versions = { type: 'object', format: 'nested', multiple: true, mappings: [{ ...userReference, name: 'author' }] };
    const fake: Record<string, Map<string, unknown>> = {
      Sync: new Map([
        ['holder', { type: 'object', format: 'standard', multiple: false, name: 'holder', mappings: [{ ...versions, name: 'versions' }] }],
        ['flat_holder', { type: 'object', format: 'flat', multiple: false, name: 'flat_holder' }],
      ]),
    };
    vi.spyOn(schemaAttributesDefinition, 'getRegisteredTypes').mockReturnValue(Object.keys(fake));
    vi.spyOn(schemaAttributesDefinition, 'getAttributes').mockImplementation((entityType: string) => fake[entityType] as never);
    try {
      expect(discoverUserIdAttributes()).toEqual([
        { name: 'holder.versions.author', multiple: false, entityTypes: ['Sync'], nestedRoot: 'holder.versions', arrayRoot: 'holder.versions' },
      ]);
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

  it('should find every resolved target declared as a user reference on its entity types', () => {
    userMergeScalarResolution().targets.forEach((target) => {
      expect(() => assertUserMergeTargetDeclared(target), target.id).not.toThrow();
    });
  });

  /**
   * Elasticsearch mappings are index-wide, so these queries would run on the strength of a
   * neighbouring declaration. They must be refused instead of silently matching nothing.
   */
  it('should refuse a target its entity type does not declare as a user reference', () => {
    const target = { id: 'fake', registerRow: 'fake', shape: 'single' as const };
    const refusal = 'not declared as a user reference';
    expect(() => assertUserMergeTargetDeclared({ ...target, entityTypes: ['Report'], path: 'user_id' })).toThrow(refusal);
    expect(() => assertUserMergeTargetDeclared({ ...target, entityTypes: ['Sync', 'Report'], path: 'user_id' })).toThrow(refusal);
    expect(() => assertUserMergeTargetDeclared({ ...target, entityTypes: ['Report'], path: 'name' })).toThrow(refusal);
    expect(() => assertUserMergeTargetDeclared({ ...target, entityTypes: ['WorkflowDefinition'], path: 'all_versions.unknown' })).toThrow(refusal);
    expect(() => assertUserMergeTargetDeclared({ ...target, path: 'user_id' })).toThrow(refusal);
  });
});
