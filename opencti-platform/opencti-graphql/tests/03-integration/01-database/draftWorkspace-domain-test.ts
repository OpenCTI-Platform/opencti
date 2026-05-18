import { afterAll, beforeAll, describe, it, expect, vi } from 'vitest';
import { ADMIN_USER, getAuthUser, testContext, USER_DISINFORMATION_ANALYST, USER_EDITOR } from '../../utils/testQuery';
import { addDraftWorkspace, listDraftObjects, listDraftRelations, validateDraftWorkspace } from '../../../src/modules/draftWorkspace/draftWorkspace-domain';
import type { AdministrativeAreaAddInput, CityAddInput, DraftWorkspaceAddInput, StixCoreRelationshipAddInput } from '../../../src/generated/graphql';
import type { AuthContext, AuthUser } from '../../../src/types/user';
import { addCity } from '../../../src/domain/city';
import { addAdministrativeArea } from '../../../src/modules/administrativeArea/administrativeArea-domain';
import { addStixCoreRelationship } from '../../../src/domain/stixCoreRelationship';
import { ENTITY_TYPE_LOCATION_CITY } from '../../../src/schema/stixDomainObject';
import { deleteElementById } from '../../../src/database/middleware';
import type { BasicNodeEdge, BasicStoreEntity, BasicStoreRelation } from '../../../src/types/store';
import { ENTITY_TYPE_DRAFT_WORKSPACE } from '../../../src/modules/draftWorkspace/draftWorkspace-types';
import { ENTITY_TYPE_LOCATION_ADMINISTRATIVE_AREA } from '../../../src/modules/administrativeArea/administrativeArea-types';
import { RELATION_LOCATED_AT } from '../../../src/schema/stixCoreRelationship';
import * as rabbitMock from '../../../src/database/rabbitmq';
import { checkDraftInContext } from '../../../src/http/httpServer-draft';
import { executionContext } from '../../../src/utils/access';

describe('Drafts workspace domain testing', () => {
  let testDraftId: string;
  let editorAuthUser: AuthUser;
  let analystAuthUser: AuthUser;
  let testDraftContext: AuthContext;
  let city: BasicStoreEntity;
  let area: BasicStoreEntity;

  beforeAll(async () => {
    // GIVEN a draft for editor user with entities and relations
    editorAuthUser = await getAuthUser(USER_EDITOR.id);
    analystAuthUser = await getAuthUser(USER_DISINFORMATION_ANALYST.id);
    const input: DraftWorkspaceAddInput = {
      name: 'Draft workspace test domain',
      authorized_members: [
        {
          id: editorAuthUser.internal_id,
          access_right: 'admin',
        },
      ],
    };
    const created = await addDraftWorkspace(testContext, editorAuthUser, input);
    testDraftId = created.id;

    const editorContext = executionContext('testing', editorAuthUser);

    testDraftContext = {
      ...editorContext,
      draft_context: `${testDraftId}`,
    };

    // Add entity
    const cityInput: CityAddInput = {
      name: 'Testville',
    };
    city = await addCity(testDraftContext, editorAuthUser, cityInput);

    const areaInput: AdministrativeAreaAddInput = {
      name: 'TestArea',
    };
    area = await addAdministrativeArea(testDraftContext, editorAuthUser, areaInput);

    const relationInput: StixCoreRelationshipAddInput = {
      relationship_type: 'located-at',
      confidence: 100,
      fromId: city.id,
      toId: area.id,
    };
    await addStixCoreRelationship(testDraftContext, editorAuthUser, relationInput);
  });

  afterAll(async () => {
    // Delete draft
    if (testDraftId) {
      // Deleting draft delete everything inside, and anyway the validation step delete it.
      await deleteElementById(testContext, ADMIN_USER, testDraftId, ENTITY_TYPE_DRAFT_WORKSPACE);
    }
    vi.restoreAllMocks();
  });

  it('should checkDraftInContext as editor be all good on Opened draft', async () => {
    await checkDraftInContext(testDraftContext);
  });

  it('should editor listDraftObjects', async () => {
    const allDraftObjects = await listDraftObjects(testContext, editorAuthUser, { draftId: testDraftId });

    const foundCity: BasicNodeEdge<BasicStoreEntity> | undefined = allDraftObjects.edges.find((object) => object.node.entity_type === ENTITY_TYPE_LOCATION_CITY);
    expect(foundCity?.node.name).toBe('Testville');

    const foundArea: BasicNodeEdge<BasicStoreEntity> | undefined = allDraftObjects.edges.find((object) => object.node.entity_type === ENTITY_TYPE_LOCATION_ADMINISTRATIVE_AREA);
    expect(foundArea?.node.name).toBe('TestArea');
  });

  it('should analyst not listDraftObjects from editor', async () => {
    await expect(async () => {
      await listDraftObjects(testContext, analystAuthUser, { draftId: testDraftId });
    }).rejects.toThrowError(`Draft ${testDraftId} cannot be found`);
  });

  it('should listDraftRelations', async () => {
    const allDraftRelations = await listDraftRelations(testContext, editorAuthUser, { draftId: testDraftId });
    const foundLocatedAt: BasicNodeEdge<BasicStoreRelation> | undefined = allDraftRelations.edges.find((rel) => rel.node.entity_type === RELATION_LOCATED_AT);
    expect(foundLocatedAt?.node.fromId).toBe(city.id);
    expect(foundLocatedAt?.node.toId).toBe(area.id);
  });

  it('should analyst not listDraftRelations from editor', async () => {
    await expect(async () => {
      await listDraftRelations(testContext, analystAuthUser, { draftId: testDraftId });
    }).rejects.toThrowError(`Draft ${testDraftId} cannot be found`);
  });

  it('should not be able to validateDraftWorkspace as analyst', async () => {
    await expect(async () => {
      await validateDraftWorkspace(testContext, analystAuthUser, testDraftId);
    }).rejects.toThrowError(`Draft ${testDraftId} cannot be found`);
  });

  it('should validateDraftWorkspace as editor', async () => {
    // Mock pushToWorkerForConnector => we don't want the bundle to be ingested for counters
    vi.spyOn(rabbitMock, 'pushToWorkerForConnector').mockResolvedValue(true);
    const validateDraftWorkId = await validateDraftWorkspace(testContext, editorAuthUser, testDraftId);
    expect(validateDraftWorkId).toBeDefined();
  });

  it('should checkDraftInContext as editor throw error on closed draft', async () => {
    await expect(async () => {
      await checkDraftInContext(testDraftContext);
    }).rejects.toThrowError('Draft is in a locked state, no request can be done within this draft');
  });
});
