import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { ADMIN_USER, testContext } from '../../../utils/testQuery';
import * as cache from '../../../../src/database/cache';
import { addIndividual } from '../../../../src/domain/individual';
import { addNote } from '../../../../src/domain/note';
import { addUser } from '../../../../src/domain/user';
import { deleteMergeableUser } from './userMerge-testFixtures';
import { deleteElementById } from '../../../../src/database/middleware';
import { fullEntitiesList, storeLoadById } from '../../../../src/database/middleware-loader';
import { READ_INDEX_STIX_DOMAIN_OBJECTS } from '../../../../src/database/utils';
import { ENTITY_TYPE_CONTAINER_NOTE, ENTITY_TYPE_IDENTITY_INDIVIDUAL } from '../../../../src/schema/stixDomainObject';
import { RELATION_CREATED_BY } from '../../../../src/schema/stixRefRelationship';
import { FilterMode } from '../../../../src/generated/graphql';
import type { BasicStoreEntity } from '../../../../src/types/store';
import type { AuthUser } from '../../../../src/types/user';
import { executeUserMerge } from '../../../../src/modules/userMerge/userMerge-engine';
import { registerUserMergeHandler, resetUserMergeHandlers, userMergeHandlers } from '../../../../src/modules/userMerge/userMerge-registry';
import type { UserMergeHandler } from '../../../../src/modules/userMerge/userMerge-handler';
import { userMergeIndividualHandler } from '../../../../src/modules/userMerge/userMerge-individualHandler';
import { UserMergeRightsStrategy, UserMergeStatus } from '../../../../src/modules/userMerge/userMerge-types';

const SOURCE_EMAIL = 'usermerge-individual-source@opencti.invalid';
const TARGET_EMAIL = 'usermerge-individual-target@opencti.invalid';

let sourceId: string;
let targetId: string;

const created: string[] = [];
const createdNotes: string[] = [];

const merge = (dryRun: boolean) => executeUserMerge(
  testContext,
  sourceId,
  targetId,
  { dryRun, rightsStrategy: UserMergeRightsStrategy.Strict, acknowledgeExposureChange: false },
);

const individualsCarrying = async (email: string) => {
  const filters = { mode: FilterMode.And, filters: [{ key: ['contact_information'], values: [email] }], filterGroups: [] };
  return fullEntitiesList<BasicStoreEntity>(testContext, ADMIN_USER, [ENTITY_TYPE_IDENTITY_INDIVIDUAL], {
    indices: [READ_INDEX_STIX_DOMAIN_OBJECTS],
    filters,
    noFiltersChecking: true,
  });
};

const createIndividual = async (name: string, email: string) => {
  const individual = await addIndividual(testContext, ADMIN_USER, { name, contact_information: email });
  created.push(individual.id);
  return individual;
};

let registeredHandlers: UserMergeHandler[];

describe('userMerge individual handler', () => {
  beforeAll(async () => {
    registeredHandlers = userMergeHandlers();
    resetUserMergeHandlers();
    registerUserMergeHandler(userMergeIndividualHandler);
    // Both users have to exist for real: `patchAttribute` refuses to touch an individual whose
    // contact information answers to a user, which is exactly the state the re-point runs in.
    const source = await addUser(testContext, ADMIN_USER, { name: 'userMerge individual source user', password: 'userMerge', user_email: SOURCE_EMAIL });
    const target = await addUser(testContext, ADMIN_USER, { name: 'userMerge individual target user', password: 'userMerge', user_email: TARGET_EMAIL });
    sourceId = source.id;
    targetId = target.id;
    // The engine reads the two users from the cache, which is not refreshed inside a test run.
    vi.spyOn(cache, 'getEntitiesMapFromCache').mockResolvedValue(new Map<string, AuthUser>([
      [sourceId, { id: sourceId, user_email: SOURCE_EMAIL } as unknown as AuthUser],
      [targetId, { id: targetId, user_email: TARGET_EMAIL } as unknown as AuthUser],
    ]));
  });

  afterAll(async () => {
    vi.restoreAllMocks();
    resetUserMergeHandlers();
    registeredHandlers.forEach((handler) => registerUserMergeHandler(handler));
    for (let i = 0; i < createdNotes.length; i += 1) {
      await deleteElementById(testContext, ADMIN_USER, createdNotes[i], ENTITY_TYPE_CONTAINER_NOTE);
    }
    await deleteMergeableUser(sourceId);
    await deleteMergeableUser(targetId);
    for (let i = 0; i < created.length; i += 1) {
      const individual = await storeLoadById(testContext, ADMIN_USER, created[i], ENTITY_TYPE_IDENTITY_INDIVIDUAL);
      if (individual) {
        await deleteElementById(testContext, ADMIN_USER, created[i], ENTITY_TYPE_IDENTITY_INDIVIDUAL);
      }
    }
  });

  it('should re-point the source individual when the target has none', async () => {
    await createIndividual('userMerge individual source', SOURCE_EMAIL);
    const dryRun = await merge(true);
    expect(dryRun.status).toEqual(UserMergeStatus.Success);
    const result = await merge(false);
    expect(result.status).toEqual(UserMergeStatus.Success);
    expect(await individualsCarrying(SOURCE_EMAIL)).toHaveLength(0);
    expect(await individualsCarrying(TARGET_EMAIL)).toHaveLength(1);
  });

  it('should fold the source individual into the target one', async () => {
    const individual = await createIndividual('userMerge individual source again', SOURCE_EMAIL);
    // The collaborative ownership check of Note and Opinion compares `created-by` against the
    // individual the session resolves from the user email, so the fold is what keeps the target
    // an owner of what the source authored.
    const note = await addNote(testContext, ADMIN_USER, { content: 'userMerge individual note', createdBy: individual.id });
    createdNotes.push(note.id);
    const result = await merge(false);
    expect(result.status).toEqual(UserMergeStatus.Success);
    expect(await individualsCarrying(SOURCE_EMAIL)).toHaveLength(0);
    const targetIndividuals = await individualsCarrying(TARGET_EMAIL);
    expect(targetIndividuals).toHaveLength(1);
    const authored = await storeLoadById<BasicStoreEntity>(testContext, ADMIN_USER, note.id, ENTITY_TYPE_CONTAINER_NOTE);
    expect(authored[RELATION_CREATED_BY]).toEqual(targetIndividuals[0].internal_id);
  });

  it('should be a no-op when neither user has an individual left to move', async () => {
    const result = await merge(false);
    expect(result.report?.total_updated).toEqual(0);
    expect(await individualsCarrying(TARGET_EMAIL)).toHaveLength(1);
  });
});
