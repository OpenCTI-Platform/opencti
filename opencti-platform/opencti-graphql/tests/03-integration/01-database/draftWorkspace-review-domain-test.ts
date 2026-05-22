import { afterAll, beforeAll, describe, it, expect } from 'vitest';
import { ADMIN_USER, getAuthUser, testContext, USER_EDITOR } from '../../utils/testQuery';
import {
  addDraftWorkspace,
  buildDraftVersion,
  getEntityContainerRefs,
  getEntityFields,
  getEntityRelations,
  getObjectsCount,
  listDraftContainerObjects,
  listDraftObjects,
  resolveIdRepresentatives,
} from '../../../src/modules/draftWorkspace/draftWorkspace-domain';
import type { AuthContext, AuthUser } from '../../../src/types/user';
import type { BasicStoreEntity, BasicStoreRelation, BasicStoreCommon } from '../../../src/types/store';
import type { DraftWorkspaceAddInput, CityAddInput, AdministrativeAreaAddInput, StixCoreRelationshipAddInput } from '../../../src/generated/graphql';
import { addCity } from '../../../src/domain/city';
import { addAdministrativeArea } from '../../../src/modules/administrativeArea/administrativeArea-domain';
import { addStixCoreRelationship } from '../../../src/domain/stixCoreRelationship';
import { addReport } from '../../../src/domain/report';
import { deleteElementById, updateAttribute } from '../../../src/database/middleware';
import { storeLoadById } from '../../../src/database/middleware-loader';
import { ENTITY_TYPE_DRAFT_WORKSPACE } from '../../../src/modules/draftWorkspace/draftWorkspace-types';
import { ENTITY_TYPE_LOCATION_CITY } from '../../../src/schema/stixDomainObject';
import { ENTITY_TYPE_LOCATION_ADMINISTRATIVE_AREA } from '../../../src/modules/administrativeArea/administrativeArea-types';
import { executionContext } from '../../../src/utils/access';
import { DRAFT_OPERATION_CREATE, DRAFT_OPERATION_UPDATE } from '../../../src/modules/draftWorkspace/draftOperations';

describe('Draft workspace review domain — new queries from PR #15637', () => {
  let testDraftId: string;
  let editorAuthUser: AuthUser;
  let testDraftContext: AuthContext;

  // Entities created inside the draft
  let city: BasicStoreEntity;
  let area: BasicStoreEntity;
  let report: BasicStoreEntity;
  let _relation: BasicStoreRelation;

  // A live entity modified inside the draft
  let liveCity: BasicStoreEntity;

  beforeAll(async () => {
    editorAuthUser = await getAuthUser(USER_EDITOR.id);

    const draftInput: DraftWorkspaceAddInput = {
      name: 'Draft review domain test',
      authorized_members: [{ id: editorAuthUser.internal_id, access_right: 'admin' }],
    };
    const draft = await addDraftWorkspace(testContext, editorAuthUser, draftInput);
    testDraftId = draft.id;

    testDraftContext = {
      ...executionContext('testing', editorAuthUser),
      draft_context: testDraftId,
    };

    // Create entities inside the draft
    city = await addCity(testDraftContext, editorAuthUser, { name: 'ReviewCity' } as CityAddInput);
    area = await addAdministrativeArea(testDraftContext, editorAuthUser, { name: 'ReviewArea' } as AdministrativeAreaAddInput);

    // Create a core relation between city → area (located-at)
    const relInput: StixCoreRelationshipAddInput = {
      relationship_type: 'located-at',
      fromId: city.id,
      toId: area.id,
      confidence: 100,
    };
    _relation = await addStixCoreRelationship(testDraftContext, editorAuthUser, relInput);

    // Create a Report container and add city as an object ref
    report = await addReport(testDraftContext, editorAuthUser, {
      name: 'ReviewReport',
      published: '2024-01-01T00:00:00Z',
      objects: [city.id],
    });

    // Load an existing live city from test fixtures (to avoid polluting stream event counts)
    liveCity = await storeLoadById(testContext, editorAuthUser, 'location--c3794ffd-0e71-4670-aa4d-978b4cbdc72c', ENTITY_TYPE_LOCATION_CITY) as BasicStoreEntity;
    // Modify it inside the draft to generate a draft_updates_patch
    await updateAttribute(testDraftContext, editorAuthUser, liveCity.id, ENTITY_TYPE_LOCATION_CITY, [
      { key: 'description', value: ['patched in draft'] },
    ]);
  });

  afterAll(async () => {
    if (testDraftId) {
      await deleteElementById(testContext, ADMIN_USER, testDraftId, ENTITY_TYPE_DRAFT_WORKSPACE);
    }
    // liveCity is a test fixture, no cleanup needed
  });

  // -----------------------------------------------------------------------
  // listDraftObjects — draftOperation filter
  // -----------------------------------------------------------------------

  describe('listDraftObjects with draftOperation filter', () => {
    it('should return all draft objects when no draftOperation is given', async () => {
      const result = await listDraftObjects(testContext, editorAuthUser, { draftId: testDraftId });
      expect(result.edges.length).toBeGreaterThanOrEqual(3); // city, area, report
    });

    it('should filter by draftOperation=create and return created objects', async () => {
      const result = await listDraftObjects(testContext, editorAuthUser, {
        draftId: testDraftId,
        draftOperation: DRAFT_OPERATION_CREATE,
      } as any);
      const types = result.edges.map((e) => e.node.entity_type);
      expect(types).toContain(ENTITY_TYPE_LOCATION_CITY);
      expect(types).toContain(ENTITY_TYPE_LOCATION_ADMINISTRATIVE_AREA);
    });

    it('should filter by draftOperation=update and return only updated objects', async () => {
      const result = await listDraftObjects(testContext, editorAuthUser, {
        draftId: testDraftId,
        draftOperation: DRAFT_OPERATION_UPDATE,
      } as any);
      // Only the live city that was modified should appear
      const ids = result.edges.map((e) => e.node.id);
      expect(ids).toContain(liveCity.id);
      // Entities created in draft should NOT appear under 'update'
      const cityNode = result.edges.find((e) => e.node.id === city.id);
      expect(cityNode).toBeUndefined();
    });

    it('should respect pagination (first: 1)', async () => {
      const result = await listDraftObjects(testContext, editorAuthUser, {
        draftId: testDraftId,
        first: 1,
      } as any);
      expect(result.edges.length).toBe(1);
    });
  });

  // -----------------------------------------------------------------------
  // getObjectsCount — reviewsCount
  // -----------------------------------------------------------------------

  describe('getObjectsCount — reviewsCount', () => {
    it('should return reviewsCount = entitiesCount + observablesCount + containersCount', async () => {
      const draft = await addDraftWorkspace(testContext, editorAuthUser, {
        name: 'Draft count test',
        authorized_members: [{ id: editorAuthUser.internal_id, access_right: 'admin' }],
      } as DraftWorkspaceAddInput);
      const countDraftContext = { ...executionContext('testing', editorAuthUser), draft_context: draft.id };
      await addCity(countDraftContext, editorAuthUser, { name: 'CountCity' } as CityAddInput);
      await addReport(countDraftContext, editorAuthUser, { name: 'CountReport', published: '2024-01-01T00:00:00Z' });

      const counts = await getObjectsCount(testContext, editorAuthUser, draft as any);

      expect(counts.reviewsCount).toBe(counts.entitiesCount + counts.observablesCount + counts.containersCount);
      expect(counts.reviewsCount).toBeGreaterThanOrEqual(2); // at least city + report

      await deleteElementById(testContext, ADMIN_USER, draft.id, ENTITY_TYPE_DRAFT_WORKSPACE);
    });
  });

  // -----------------------------------------------------------------------
  // listDraftContainerObjects
  // -----------------------------------------------------------------------

  describe('listDraftContainerObjects', () => {
    it('should return objects added to the container in the draft', async () => {
      const result = await listDraftContainerObjects(testContext, editorAuthUser, {
        draftId: testDraftId,
        containerId: report.id,
      });
      expect(result.length).toBeGreaterThan(0);
      const cityEntry = result.find((r) => r.entity_id === city.id);
      expect(cityEntry).toBeDefined();
      // The city was added to the report via object ref in draft → operation should be 'add'
      expect(cityEntry!.draft_operation).toBe('add');
      expect(cityEntry!.entity_type).toBe(ENTITY_TYPE_LOCATION_CITY);
      expect(cityEntry!.representative_main).toBe('ReviewCity');
    });

    it('should return empty for a container with no draft changes', async () => {
      // Create a report with no objects
      const emptyReport = await addReport(testDraftContext, editorAuthUser, {
        name: 'EmptyReport',
        published: '2024-01-01T00:00:00Z',
      });
      const result = await listDraftContainerObjects(testContext, editorAuthUser, {
        draftId: testDraftId,
        containerId: emptyReport.id,
      });
      // No RELATION_OBJECT with create/delete in draft for this container
      expect(result.length).toBe(0);
    });
  });

  // -----------------------------------------------------------------------
  // resolveIdRepresentatives
  // -----------------------------------------------------------------------

  describe('resolveIdRepresentatives', () => {
    it('should resolve standard_ids to their representative names', async () => {
      const draftCtx = { ...testContext, draft_context: testDraftId };
      const result = await resolveIdRepresentatives(draftCtx, editorAuthUser, {
        draftId: testDraftId,
        ids: [city.standard_id, area.standard_id],
      });
      expect(result.length).toBe(2);
      const cityRes = result.find((r) => r.id === city.standard_id);
      expect(cityRes?.representative_main).toBe('ReviewCity');
      const areaRes = result.find((r) => r.id === area.standard_id);
      expect(areaRes?.representative_main).toBe('ReviewArea');
    });

    it('should return null representative_main for unknown ids', async () => {
      const result = await resolveIdRepresentatives(
        { ...testContext, draft_context: testDraftId },
        editorAuthUser,
        { draftId: testDraftId, ids: ['non-existent-id'] },
      );
      expect(result.length).toBe(1);
      expect(result[0].representative_main).toBeNull();
    });

    it('should return empty for empty ids array', async () => {
      const result = await resolveIdRepresentatives(
        { ...testContext, draft_context: testDraftId },
        editorAuthUser,
        { draftId: testDraftId, ids: [] },
      );
      expect(result).toHaveLength(0);
    });
  });

  // -----------------------------------------------------------------------
  // getEntityFields
  // -----------------------------------------------------------------------

  describe('getEntityFields', () => {
    it('should return scalar fields of a draft entity', async () => {
      const result = await getEntityFields(testContext, editorAuthUser, {
        draftId: testDraftId,
        entityId: city.id,
      });
      expect(result.length).toBeGreaterThan(0);
      const nameField = result.find((f) => f.field === 'name');
      expect(nameField).toBeDefined();
      expect(nameField!.values).toContain('ReviewCity');
    });

    it('should not include internal/excluded fields', async () => {
      const result = await getEntityFields(testContext, editorAuthUser, {
        draftId: testDraftId,
        entityId: city.id,
      });
      const fieldNames = result.map((f) => f.field);
      expect(fieldNames).not.toContain('internal_id');
      expect(fieldNames).not.toContain('draft_ids');
      expect(fieldNames).not.toContain('draft_change');
      expect(fieldNames).not.toContain('parent_types');
    });

    it('should return empty for a non-existent entity', async () => {
      const result = await getEntityFields(testContext, editorAuthUser, {
        draftId: testDraftId,
        entityId: 'non-existent-id',
      });
      expect(result).toHaveLength(0);
    });
  });

  // -----------------------------------------------------------------------
  // getEntityRelations
  // -----------------------------------------------------------------------

  describe('getEntityRelations', () => {
    it('should return direct relations created in draft for the entity', async () => {
      const result = await getEntityRelations(testContext, editorAuthUser, {
        draftId: testDraftId,
        entityId: city.id,
      });
      expect(result.length).toBeGreaterThan(0);
      const locatedAt = result.find((r) => r.relationship_type === 'located-at');
      expect(locatedAt).toBeDefined();
      expect(locatedAt!.from_id).toBe(city.id);
      expect(locatedAt!.to_id).toBe(area.id);
      expect(locatedAt!.draft_operation).toBe('create');
    });

    it('should include relation id and type information', async () => {
      const result = await getEntityRelations(testContext, editorAuthUser, {
        draftId: testDraftId,
        entityId: city.id,
      });
      const locatedAt = result.find((r) => r.relationship_type === 'located-at')!;
      expect(locatedAt.relation_id).toBeDefined();
      expect(locatedAt.from_type).toBe(ENTITY_TYPE_LOCATION_CITY);
      expect(locatedAt.to_type).toBe(ENTITY_TYPE_LOCATION_ADMINISTRATIVE_AREA);
    });

    it('should return empty for an entity with no draft relations', async () => {
      const isolatedCity = await addCity(testDraftContext, editorAuthUser, { name: 'IsolatedCity' } as CityAddInput);
      const result = await getEntityRelations(testContext, editorAuthUser, {
        draftId: testDraftId,
        entityId: isolatedCity.id,
      });
      // No relations for this entity
      expect(result.every((r) => r.from_id !== isolatedCity.id && r.to_id !== isolatedCity.id)).toBe(true);
    });
  });

  // -----------------------------------------------------------------------
  // getEntityContainerRefs
  // -----------------------------------------------------------------------

  describe('getEntityContainerRefs', () => {
    it('should return containers that reference the entity in the draft', async () => {
      const result = await getEntityContainerRefs(testContext, editorAuthUser, {
        draftId: testDraftId,
        entityId: city.id,
      });
      expect(result.length).toBeGreaterThan(0);
      const reportRef = result.find((r) => r.container_id === report.id);
      expect(reportRef).toBeDefined();
      expect(reportRef!.draft_operation).toBe('add');
      expect(reportRef!.container_name).toBe('ReviewReport');
    });

    it('should return empty for an entity not referenced by any container', async () => {
      const result = await getEntityContainerRefs(testContext, editorAuthUser, {
        draftId: testDraftId,
        entityId: area.id,
      });
      // area was not added to any container
      expect(result.find((r) => r.container_id === report.id)).toBeUndefined();
    });
  });

  // -----------------------------------------------------------------------
  // buildDraftVersion
  // -----------------------------------------------------------------------

  describe('buildDraftVersion', () => {
    it('should include draft_updates_patch for an updated live entity', async () => {
      const draftCtx = { ...testContext, draft_context: testDraftId };
      const { elFindByIds } = await import('../../../src/database/engine');
      const results = await elFindByIds(draftCtx, editorAuthUser, [liveCity.id], { includeDeletedInDraft: true }) as BasicStoreCommon[];
      const draftLiveCity = results[0];
      expect(draftLiveCity).toBeDefined();

      const version = buildDraftVersion(draftLiveCity);
      expect(version).not.toBeNull();
      expect(version!.draft_id).toBe(testDraftId);
      expect(version!.draft_operation).toBe(DRAFT_OPERATION_UPDATE);
    });

    it('should return null for an entity without draft_ids', async () => {
      // Any live entity not in a draft has no draft_ids
      const version = buildDraftVersion({ draft_ids: [] } as any);
      expect(version).toBeNull();
    });
  });
});
