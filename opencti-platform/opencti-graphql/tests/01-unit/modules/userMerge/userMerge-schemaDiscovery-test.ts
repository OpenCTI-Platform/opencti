import { describe, expect, it, vi } from 'vitest';
import { USER_MERGE_FILTER_TARGETS } from '../../../../src/modules/userMerge/userMerge-filterTargets';
import { registerModules } from '../../../../src/composition-root';
import { findRegisterRow } from '../../../../src/modules/userMerge/userMerge-register';
import { discoverUserIdAttributes } from '../../../../src/modules/userMerge/userMerge-scalarDiscovery';
import { userMergeScalarResolution } from '../../../../src/modules/userMerge/userMerge-scalarTargets';
import { ENTITY_TYPE_USER } from '../../../../src/schema/internalObject';
import { schemaAttributesDefinition } from '../../../../src/schema/schema-attributes';
import type { AttributeDefinition, MappingDefinition } from '../../../../src/schema/attribute-definition';

registerModules();

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
});

/**
 * A stored filter names users by value — `creator_id`, `objectAssignee`, `workflow_assignee`… — so
 * the schema discovery above cannot see it: the attribute is a string, not a typed reference. The
 * filter handler works from a hand-written list instead, and this suite is what keeps that list
 * from falling behind the schema.
 *
 * A filter attribute is recognised by its name, the convention every one of them follows today.
 */
const FILTER_ATTRIBUTE = /filters$/;

/**
 * Filter attributes the merge deliberately leaves alone, each with the register row that says so.
 * An attribute is listed here only when rewriting it would be wrong, not to make this suite pass.
 */
const UNREWRITTEN_FILTER_ATTRIBUTES: { path: string; entityTypes: string[]; registerRow: string }[] = [
  // Frozen snapshot of a recorded action, never re-executed.
  { path: 'context_data.filters', entityTypes: ['Activity', 'History', 'PirHistory'], registerRow: 'history.context-data-raw-payload' },
  // Provenance of a past export: rewriting it would misreport what was exported.
  { path: 'metaData.list_filters', entityTypes: ['InternalFile'], registerRow: 'internal-file.list-filters' },
];

const collectFilterAttributes = (attribute: AttributeDefinition | MappingDefinition, parentPath?: string): string[] => {
  const path = parentPath ? `${parentPath}.${attribute.name}` : attribute.name;
  if (attribute.type === 'string' && FILTER_ATTRIBUTE.test(attribute.name)) {
    return [path];
  }
  if (attribute.type === 'object' && 'mappings' in attribute && Array.isArray(attribute.mappings)) {
    return attribute.mappings.flatMap((mapping) => collectFilterAttributes(mapping, path));
  }
  return [];
};

const discoverFilterAttributes = (): { entityType: string; path: string }[] => {
  return schemaAttributesDefinition.getRegisteredTypes().flatMap((entityType) => {
    const attributes = Array.from(schemaAttributesDefinition.getAttributes(entityType).values());
    return attributes.flatMap((attribute) => collectFilterAttributes(attribute)).map((path) => ({ entityType, path }));
  });
};

describe('userMerge stored filters inventory', () => {
  it('should find the stored filters in the schema', () => {
    expect(discoverFilterAttributes()).toContainEqual({ entityType: 'Trigger', path: 'filters' });
  });

  it('should rewrite or deliberately leave every stored filter of the schema', () => {
    const answered = (entityType: string, path: string) => {
      return USER_MERGE_FILTER_TARGETS.some((target) => target.entityType === entityType && target.path === path)
        || UNREWRITTEN_FILTER_ATTRIBUTES.some((entry) => entry.path === path && entry.entityTypes.includes(entityType));
    };
    const unanswered = discoverFilterAttributes()
      .filter(({ entityType, path }) => !answered(entityType, path))
      .map(({ entityType, path }) => `${entityType}.${path}`);
    expect(unanswered, 'stored filters the user merge does not know: add them to USER_MERGE_FILTER_TARGETS with a register row').toEqual([]);
  });

  it('should name register rows that exist for the filters it leaves alone', () => {
    UNREWRITTEN_FILTER_ATTRIBUTES.forEach((entry) => {
      expect(findRegisterRow(entry.registerRow), entry.path).toBeDefined();
    });
  });

  // A target whose attribute was renamed or removed would rewrite nothing and say nothing.
  it('should point every filter target at an attribute the schema still declares', () => {
    const discovered = discoverFilterAttributes();
    USER_MERGE_FILTER_TARGETS
      .filter((target) => target.shape === 'field')
      .forEach((target) => {
        expect(discovered, target.id).toContainEqual({ entityType: target.entityType, path: target.path });
      });
  });
});
