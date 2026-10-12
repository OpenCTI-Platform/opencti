import { describe, expect, it } from 'vitest';
import '../../../../src/modules/index';
import convertUserToStix from '../../../../src/modules/user/user-converter';
import { convertStoreToStix_2_1 } from '../../../../src/database/stix-2-1-converter';
import { ENTITY_TYPE_USER, type StoreEntityUser } from '../../../../src/modules/user/user-types';

describe('User STIX converter', () => {
  it('should produce the same output as the generic internal object conversion', () => {
    const user = {
      id: 'a8f7e6b5-1111-4222-8333-944455556666',
      internal_id: 'a8f7e6b5-1111-4222-8333-944455556666',
      standard_id: 'user--b8f7e6b5-1111-4222-8333-944455556666',
      entity_type: ENTITY_TYPE_USER,
      base_type: 'ENTITY',
      parent_types: ['Basic-Object', 'Internal-Object'],
      name: 'John Doe',
      user_email: 'john@doe.com',
      created_at: new Date('2024-01-01'),
      updated_at: new Date('2024-01-02'),
      creator_id: ['88ec0c6a-13ce-5e39-b486-354fe4a7084f'],
    } as unknown as StoreEntityUser;
    expect(convertUserToStix(user)).toEqual(convertStoreToStix_2_1(user));
  });
});
