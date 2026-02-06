import { describe, expect, it } from 'vitest';
import type { BasicStoreEntitySingleSignOn } from '../../../../src/modules/singleSignOn/singleSignOn-types';
import { convertKeyValueToJsConfiguration } from '../../../../src/modules/singleSignOn/singleSignOn-providers';
import { computeGroupsMapping, computeOrganizationsMapping, computeHeaderUserInfo } from '../../../../src/modules/singleSignOn/singleSignOn-provider-header';

describe('Header Single sign on Provider coverage tests', () => {
  describe('Header userInfo mapping coverage', () => {
    it('should Header user info with default config', async () => {
      const HeaderProfile = { name: 'Winry', email: 'winry.rockbell@anime.jp', given_name: 'Winry Mechanic expert', family_name: 'Rockbell' };
      const result = computeHeaderUserInfo({}, HeaderProfile);
      expect(result.email).toBe('winry.rockbell@anime.jp');
      expect(result.name).toBe('Winry');
      expect(result.lastname).toBe('Rockbell');
      expect(result.firstname).toBe('Winry Mechanic expert');
    });

    it('should Header user info with advanced config works', async () => {
      const headerProfile = { theName: 'Winry', theMail: 'winry.rockbell@anime.jp', theFirstname: 'Winry Mechanic expert', theLastName: 'Rockbell' };
      const ssoEntity: Partial<BasicStoreEntitySingleSignOn> = {
        identifier: 'openid',
        configuration: [
          { key: 'account_attribute', type: 'string', value: 'theName' },
          { key: 'header_email', type: 'string', value: 'theMail' },
          { key: 'header_firstname', type: 'string', value: 'theFirstname' },
          { key: 'header_lastname', type: 'string', value: 'theLastName' },
        ],
      };
      const ssoConfiguration: any = convertKeyValueToJsConfiguration(ssoEntity as BasicStoreEntitySingleSignOn);

      const result = computeHeaderUserInfo(ssoConfiguration, headerProfile);
      expect(result.email).toBe('winry.rockbell@anime.jp');
      expect(result.name).toBe('Winry');
      expect(result.lastname).toBe('Rockbell');
      expect(result.firstname).toBe('Winry Mechanic expert');
    });
  });

  describe('Header groups and org mapping coverage', () => {
    it('should Header group mapping be computed correctly with default', async () => {
      const headers: Record<string, string> = { 'X-MY-USER-GROUPS': 'headerGroupA' };
      const req = { header: (key: string) => headers[key] };
      const groupManagementConfig: Partial <BasicStoreEntitySingleSignOn> = {
        groups_management: {
          groups_mapping: ['headerGroupA:openCTIGroupA', 'headerGroupB:openCTIGroupB', 'headerGroupC:openCTIGroupC'],
          groups_header: 'X-MY-USER-GROUPS',
        },
      };
      // no config on read user info => userInfo can be undefined
      const result = computeGroupsMapping(groupManagementConfig as BasicStoreEntitySingleSignOn, req);
      expect(result).toStrictEqual(['openCTIGroupA']);
    });

    it('should Header group mapping be computed correctly with splitter', async () => {
      const headers: Record<string, string> = { 'X-MY-USER-GROUPS': 'headerGroupA;headerGroupB' };
      const req = { header: (key: string) => headers[key] };
      const groupManagementConfig: Partial <BasicStoreEntitySingleSignOn> = {
        groups_management: {
          groups_mapping: ['headerGroupA:openCTIGroupA', 'headerGroupB:openCTIGroupB', 'headerGroupC:openCTIGroupC'],
          groups_header: 'X-MY-USER-GROUPS',
          groups_splitter: ';',
        },
      };
      const result = computeGroupsMapping(groupManagementConfig as BasicStoreEntitySingleSignOn, req);
      expect(result).toStrictEqual(['openCTIGroupA', 'openCTIGroupB']);
    });

    it('should Header org mapping be computed correctly with default org', async () => {
      const headers: Record<string, string> = { 'X-MY-USER-ORG': 'headerOrgA;headerOrgB' };
      const req = { header: (key: string) => headers[key] };
      const orgManagementConfig: Partial <BasicStoreEntitySingleSignOn> = {
        organizations_management: {
          organizations_mapping: ['headerOrgA:openCTIOrgA', 'headerOrgB:openCTIOrgB', 'headerOrgC:openCTIOrgC'],
          organizations_header: 'X-MY-USER-ORG',
          organizations_splitter: ';',
        },
      };
      const result = computeOrganizationsMapping(orgManagementConfig as BasicStoreEntitySingleSignOn, ['openCTIOrgC'], req);
      expect(result).toStrictEqual(['openCTIOrgC', 'openCTIOrgA', 'openCTIOrgB']);
    });
  });
});
