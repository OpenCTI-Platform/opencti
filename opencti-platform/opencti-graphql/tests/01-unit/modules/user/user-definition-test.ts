import { describe, expect, it } from 'vitest';
import '../../../../src/modules/index';
import convertUserToStix from '../../../../src/modules/user/user-converter';
import { extractStixRepresentative } from '../../../../src/database/stix-representative';
import { generateStandardId } from '../../../../src/schema/identifier';
import { ENTITY_TYPE_USER, type StoreEntityUser } from '../../../../src/modules/user/user-types';

const buildUser = (name?: string) => ({
  id: 'a8f7e6b5-1111-4222-8333-944455556666',
  internal_id: 'a8f7e6b5-1111-4222-8333-944455556666',
  standard_id: 'user--b8f7e6b5-1111-4222-8333-944455556666',
  entity_type: ENTITY_TYPE_USER,
  base_type: 'ENTITY',
  parent_types: ['Basic-Object', 'Internal-Object'],
  name,
  user_email: 'john@doe.com',
  created_at: new Date('2024-01-01'),
  updated_at: new Date('2024-01-02'),
  creator_id: ['88ec0c6a-13ce-5e39-b486-354fe4a7084f'],
}) as unknown as StoreEntityUser;

describe('User module definition', () => {
  describe('representative', () => {
    it('should expose the user name', () => {
      expect(extractStixRepresentative(convertUserToStix(buildUser('John Doe')))).toEqual('John Doe');
    });

    it('should fall back to undefined when the name is missing', () => {
      expect(extractStixRepresentative(convertUserToStix(buildUser()))).toEqual('undefined');
    });
  });

  describe('standard id', () => {
    it('should normalize the email before generating the identifier', () => {
      const normalized = generateStandardId(ENTITY_TYPE_USER, { user_email: 'john.doe@example.com' });
      expect(generateStandardId(ENTITY_TYPE_USER, { user_email: '  John.Doe@Example.COM  ' })).toEqual(normalized);
    });

    it('should generate different identifiers for different emails', () => {
      const first = generateStandardId(ENTITY_TYPE_USER, { user_email: 'john.doe@example.com' });
      expect(generateStandardId(ENTITY_TYPE_USER, { user_email: 'jane.doe@example.com' })).not.toEqual(first);
    });
  });
});
