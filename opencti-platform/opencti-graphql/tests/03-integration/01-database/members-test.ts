import { describe, expect, it } from 'vitest';
import { loadCreator } from '../../../src/database/members';
import { ADMIN_USER, testContext } from '../../utils/testQuery';
import { SYSTEM_USER } from '../../../src/utils/access';

describe('Members loader function testing', () => {
  it('Should load creator return SYSTEM_USER if creator id is undefined or creator user doesnt exist', async () => {
    let creator = await loadCreator(testContext, ADMIN_USER, undefined);
    expect(creator.name).toEqual(SYSTEM_USER.name);
    expect(creator.id).toEqual(SYSTEM_USER.id);

    creator = await loadCreator(testContext, ADMIN_USER, 'fake-userId');
    expect(creator.name).toEqual(SYSTEM_USER.name);
    expect(creator.id).toEqual(SYSTEM_USER.id);
  });
});
