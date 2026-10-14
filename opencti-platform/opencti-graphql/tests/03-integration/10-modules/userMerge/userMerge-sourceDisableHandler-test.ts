import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { ADMIN_USER, testContext } from '../../../utils/testQuery';
import { ACCOUNT_STATUS_EXPIRED } from '../../../../src/config/conf';
import { addIndividual } from '../../../../src/domain/individual';
import { addUser, userEditField } from '../../../../src/modules/user/user-domain';
import { deleteMergeableUser } from './userMerge-testFixtures';
import { deleteElementById } from '../../../../src/database/middleware';
import { storeLoadById } from '../../../../src/database/middleware-loader';
import { ENTITY_TYPE_IDENTITY_INDIVIDUAL } from '../../../../src/schema/stixDomainObject';
import { ENTITY_TYPE_USER } from '../../../../src/schema/internalObject';
import type { BasicStoreEntity } from '../../../../src/types/store';
import type { UserMergeHandlerContext } from '../../../../src/modules/userMerge/userMerge-handler';
import { userMergeSourceDisableHandler } from '../../../../src/modules/userMerge/userMerge-sourceDisableHandler';

const SOURCE_EMAIL = 'usermerge-disable-source@opencti.invalid';
const TARGET_EMAIL = 'usermerge-disable-target@opencti.invalid';
const EDITED_EMAIL = 'usermerge-disable-edited@opencti.invalid';

type StoredIndividual = BasicStoreEntity & { x_opencti_firstname?: string; x_opencti_lastname?: string };

const users: string[] = [];
const individuals: string[] = [];

const addNamedUser = async (name: string, email: string) => {
  const user = await addUser(testContext, ADMIN_USER, { name, firstname: 'First', lastname: 'Last', password: 'userMerge', user_email: email });
  users.push(user.id);
  return user;
};

// Created the way the platform creates one on a first Note: name and email, no first or last name.
const addBareIndividual = async (name: string, email: string) => {
  const individual = await addIndividual(testContext, ADMIN_USER, { name, contact_information: email });
  individuals.push(individual.id);
  return individual;
};

const loadIndividual = (id: string) => storeLoadById<StoredIndividual>(testContext, ADMIN_USER, id, ENTITY_TYPE_IDENTITY_INDIVIDUAL);

describe('userMerge source disable handler', () => {
  let sourceId: string;
  let targetId: string;

  beforeAll(async () => {
    sourceId = (await addNamedUser('userMerge disable source', SOURCE_EMAIL)).id;
    targetId = (await addNamedUser('userMerge disable target', TARGET_EMAIL)).id;
  });

  afterAll(async () => {
    for (let i = 0; i < users.length; i += 1) {
      await deleteMergeableUser(users[i]);
    }
    for (let i = 0; i < individuals.length; i += 1) {
      await deleteElementById(testContext, ADMIN_USER, individuals[i], ENTITY_TYPE_IDENTITY_INDIVIDUAL);
    }
  });

  // The control case: an ordinary edit still re-aligns the individual. Without it, the next test
  // would also pass on a platform where the re-alignment had silently stopped everywhere.
  it('should leave the platform re-alignment of the individual in place outside the merge', async () => {
    const edited = await addNamedUser('userMerge disable edited', EDITED_EMAIL);
    const individual = await addBareIndividual('userMerge disable edited', EDITED_EMAIL);
    await userEditField(testContext, ADMIN_USER, edited.id, [{ key: 'description', value: ['edited'] }]);
    const realigned = await loadIndividual(individual.id);
    expect(realigned?.x_opencti_firstname).toEqual('First');
    expect(realigned?.x_opencti_lastname).toEqual('Last');
  });

  // Re-aligning it here is a write on a STIX entity that the history manager records, attributed to
  // the source, while the merge is running — the history handler then counts one more reference to
  // the source between its dry pass and its recompute, and aborts the merge.
  it('should disable the source without touching the individual joined on its email', async () => {
    const individual = await addBareIndividual('userMerge disable source', SOURCE_EMAIL);
    const handlerContext = { context: testContext, sourceId, targetId } as unknown as UserMergeHandlerContext;
    const plan = await userMergeSourceDisableHandler.compute(handlerContext);
    expect(await userMergeSourceDisableHandler.apply(handlerContext, plan)).toEqual(1);
    const source = await storeLoadById<BasicStoreEntity & { account_status?: string; merged_into?: string }>(testContext, ADMIN_USER, sourceId, ENTITY_TYPE_USER);
    expect(source?.account_status).toEqual(ACCOUNT_STATUS_EXPIRED);
    expect(source?.merged_into).toEqual(targetId);
    const untouched = await loadIndividual(individual.id);
    expect(untouched?.x_opencti_firstname ?? null).toBeNull();
    expect(untouched?.x_opencti_lastname ?? null).toBeNull();
  });
});
