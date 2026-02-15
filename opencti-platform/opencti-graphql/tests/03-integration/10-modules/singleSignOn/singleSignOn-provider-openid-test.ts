import { describe, expect, it } from 'vitest';
import { convertKeyValueToJsConfiguration } from '../../../../src/modules/__singleSignOn/singleSignOn-providers';
import type { BasicStoreEntitySingleSignOn, GroupsManagement, OrganizationsManagement } from '../../../../src/modules/__singleSignOn/singleSignOn-types';
import { computeOpenIdUserInfo, computeOpenIdGroupsMapping, computeOpenIdOrganizationsMapping } from '../../../../src/modules/__singleSignOn/singleSignOn-provider-openid';

describe('OpenID Single sign on Provider coverage tests', () => {
  describe('OpenID userInfo mapping coverage', () => {
    it('should OpenID user info with default config', async () => {
      const openIdProfile = { name: 'Winry', email: 'winry.rockbell@anime.jp', given_name: 'Winry Mechanic expert', family_name: 'Rockbell' };
      const result = computeOpenIdUserInfo({}, openIdProfile);
      expect(result.email).toBe('winry.rockbell@anime.jp');
      expect(result.name).toBe('Winry');
      expect(result.lastname).toBe('Rockbell');
      expect(result.firstname).toBe('Winry Mechanic expert');
    });

    it('should OpenID user info with advanced config works', async () => {
      const openIdProfile = { theName: 'Winry', theMail: 'winry.rockbell@anime.jp', theFirstname: 'Winry Mechanic expert', theLastName: 'Rockbell' };
      const ssoEntity: Partial<BasicStoreEntitySingleSignOn> = {
        identifier: 'openid',
        configuration: [
          { key: 'name_attribute', type: 'string', value: 'theName' },
          { key: 'email_attribute', type: 'string', value: 'theMail' },
          { key: 'firstname_attribute', type: 'string', value: 'theFirstname' },
          { key: 'lastname_attribute', type: 'string', value: 'theLastName' },
        ],
      };
      const ssoConfiguration: any = await convertKeyValueToJsConfiguration(ssoEntity as BasicStoreEntitySingleSignOn);

      const result = computeOpenIdUserInfo(ssoConfiguration, openIdProfile);
      expect(result.email).toBe('winry.rockbell@anime.jp');
      expect(result.name).toBe('Winry');
      expect(result.lastname).toBe('Rockbell');
      expect(result.firstname).toBe('Winry Mechanic expert');
    });
  });

  describe('OpenID groups and org mapping coverage', () => {
    it('should OpenID group mapping be computed correctly with default', async () => {
      const decodedUser = { groups: ['oicGroupA', 'oicGroupD'] };
      const groupManagementConfig: GroupsManagement = {
        groups_mapping: ['oicGroupA:openCTIGroupA', 'oicGroupB:openCTIGroupB', 'oicGroupC:openCTIGroupC'],
      };
      // no config on read user info => userInfo can be undefined
      const result = computeOpenIdGroupsMapping(groupManagementConfig, decodedUser, undefined);
      expect(result).toStrictEqual(['openCTIGroupA']);
    });

    it('should OpenID group mapping be computed correctly with userInfo', async () => {
      const userInfo = { groups: ['oicGroupA', 'oicGroupD'] };
      const groupManagementConfig: GroupsManagement = {
        groups_mapping: ['oicGroupA:openCTIGroupA', 'oicGroupB:openCTIGroupB', 'oicGroupC:openCTIGroupC'],
        read_userinfo: true,
      };
      // read user info enabled => decodedUser can be undefined
      const result = computeOpenIdGroupsMapping(groupManagementConfig, undefined, userInfo);
      expect(result).toStrictEqual(['openCTIGroupA']);
    });

    it('should OpenID group mapping be computed correctly with custom config', async () => {
      const decodedUser = { theG1: ['oicGroupA', 'oicGroupD'], theG2: ['oicGroupB', 'oicGroupD'] };
      const groupManagementConfig: GroupsManagement = {
        groups_mapping: ['oicGroupA:openCTIGroupA', 'oicGroupB:openCTIGroupB', 'oicGroupC:openCTIGroupC'],
        groups_path: ['theG1', 'theG2'],
      };
      // no config on read user info => userInfo can be undefined
      const result = computeOpenIdGroupsMapping(groupManagementConfig, decodedUser, undefined);
      expect(result).toStrictEqual(['openCTIGroupA', 'openCTIGroupB']);
    });

    it('should OpenID org mapping be computed correctly with default', async () => {
      const decodedUser = { organizations: ['oicOrgA', 'oicOrgD'] };
      const orgManagementConfig: OrganizationsManagement = {
        organizations_mapping: ['oicOrgA:openCTIOrgA', 'oicOrgB:openCTIOrgB', 'oicOrgC:openCTIOrgC'],
      };
      // no config on read user info => userInfo can be undefined
      const result = computeOpenIdOrganizationsMapping(orgManagementConfig, decodedUser, undefined, ['openCTIOrgB']);
      expect(result).toStrictEqual(['openCTIOrgB', 'openCTIOrgA']);// A from profile + B from default
    });

    it('should OpenID org mapping be computed correctly with default', async () => {
      const decodedUser = { theOrg: ['oicOrgC'], organizations: ['oicOrgC'] };
      const userInfo = { theOrg: ['oicOrgA', 'oicOrgD'], organizations: ['oicOrgC'] };
      const orgManagementConfig: OrganizationsManagement = {
        organizations_mapping: ['oicOrgA:openCTIOrgA', 'oicOrgB:openCTIOrgB', 'oicOrgC:openCTIOrgC'],
        read_userinfo: true,
        organizations_path: ['theOrg'],
      };
      // no config on read user info => userInfo can be undefined
      const result = computeOpenIdOrganizationsMapping(orgManagementConfig, decodedUser, userInfo, ['openCTIOrgDefault']);
      expect(result).toStrictEqual(['openCTIOrgDefault', 'openCTIOrgA']);// A from profile + B from default
    });
  });
});
