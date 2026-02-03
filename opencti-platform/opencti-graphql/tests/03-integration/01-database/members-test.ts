import { describe, expect, it, beforeAll } from 'vitest';
import { loadCreator, loadCreators } from '../../../src/database/members';
import { ADMIN_USER, USER_EDITOR } from '../../utils/testQuery';
import { executionContext, PIR_MANAGER_USER, SYSTEM_USER } from '../../../src/utils/access';
import type { BasicStoreEntity } from '../../../src/types/store';
import { computeLoaders } from '../../../src/http/httpAuthenticatedContext';

describe('Members loader function testing', () => {
  const execContext = executionContext('test', ADMIN_USER);
  beforeAll(() => {
    execContext.batch = computeLoaders(execContext, ADMIN_USER);
  });

  it('Should load creator return SYSTEM_USER if creator id is undefined or corresponds to no user', async () => {
    let creator = await loadCreator(execContext, ADMIN_USER, undefined);
    expect(creator.name).toEqual(SYSTEM_USER.name);
    expect(creator.id).toEqual(SYSTEM_USER.id);

    creator = await loadCreator(execContext, ADMIN_USER, 'fake-userId');
    expect(creator.name).toEqual(SYSTEM_USER.name);
    expect(creator.id).toEqual(SYSTEM_USER.id);
  });

  it('Should load creator', async () => {
    let creator = await loadCreator(execContext, ADMIN_USER, PIR_MANAGER_USER.id);
    expect(creator.name).toEqual(PIR_MANAGER_USER.name);
    expect(creator.id).toEqual(PIR_MANAGER_USER.id);

    creator = await loadCreator(execContext, ADMIN_USER, USER_EDITOR.id);
    expect(creator.name).toEqual(USER_EDITOR.email);
  });

  it('Should load creators return SYSTEM_USER if creator id corresponds to no user', async () => {
    const creators = await loadCreators(execContext, ADMIN_USER, { creator_id: 'fakeUserId' } as BasicStoreEntity);
    expect(creators.length).toEqual(1);
    expect(creators[0].name).toEqual(SYSTEM_USER.name);
  });

  it('Should load creators', async () => {
    const creators = await loadCreators(execContext, ADMIN_USER, { creator_id: USER_EDITOR.id } as BasicStoreEntity);
    expect(creators.length).toEqual(1);
    expect(creators[0].name).toEqual(USER_EDITOR.email);
  });
});
