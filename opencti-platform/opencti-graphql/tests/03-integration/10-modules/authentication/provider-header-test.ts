import { describe, expect, it } from 'vitest';
import type { BasicStoreEntityAuthenticationProvider } from '../../../../src/modules/authenticationProvider/authenticationProvider-types';
import { convertKeyValueToJsConfiguration } from '../../../../src/modules/authenticationProvider/providers';
import { computeGroupsMapping, computeOrganizationsMapping, computeHeaderUserInfo } from '../../../../src/modules/authenticationProvider/provider-header';

describe('Header Single sign on Provider coverage tests', () => {
  describe('Header userInfo mapping coverage', () => {
    it('should Header user info with default config', () => {
      const HeaderProfile = { name: 'Winry', email: 'winry.rockbell@anime.jp', given_name: 'Winry Mechanic expert', family_name: 'Rockbell' };
      const result = computeHeaderUserInfo({}, HeaderProfile);
      expect(result.email).toBe('winry.rockbell@anime.jp');
      expect(result.name).toBe('Winry');
      expect(result.lastname).toBe('Rockbell');
      expect(result.firstname).toBe('Winry Mechanic expert');
    });

    it('should Header user info with advanced config works', async () => {
      const headerProfile = { theName: 'Winry', theMail: 'winry.rockbell@anime.jp', theFirstname: 'Winry Mechanic expert', theLastName: 'Rockbell' };
      const ssoEntity: Partial<BasicStoreEntityAuthenticationProvider> = {
        configuration: [
          { key: 'account_attribute', type: 'string', value: 'theName' },
          { key: 'header_email', type: 'string', value: 'theMail' },
          { key: 'header_firstname', type: 'string', value: 'theFirstname' },
          { key: 'header_lastname', type: 'string', value: 'theLastName' },
        ],
      };
      const ssoConfiguration: any = await convertKeyValueToJsConfiguration(ssoEntity as BasicStoreEntityAuthenticationProvider);
      const result = computeHeaderUserInfo(ssoConfiguration, headerProfile);
      expect(result.email).toBe('winry.rockbell@anime.jp');
      expect(result.name).toBe('Winry');
      expect(result.lastname).toBe('Rockbell');
      expect(result.firstname).toBe('Winry Mechanic expert');
    });
  });

  describe('Header groups and org mapping coverage', () => {
    it('should Header group mapping be computed correctly with default', () => {
      const headers: Record<string, string> = { 'X-MY-USER-GROUPS': 'headerGroupA' };
      const req = { header: (key: string) => headers[key] };
      const groupManagementConfig: Partial <BasicStoreEntityAuthenticationProvider> = {
        groups_management: {
          groups_mapping: ['headerGroupA:openCTIGroupA', 'headerGroupB:openCTIGroupB', 'headerGroupC:openCTIGroupC'],
          groups_header: 'X-MY-USER-GROUPS',
        },
      };
      // no config on read user info => userInfo can be undefined
      const result = computeGroupsMapping(groupManagementConfig as BasicStoreEntityAuthenticationProvider, req);
      expect(result).toStrictEqual(['openCTIGroupA']);
    });

    it('should Header group mapping be computed correctly with splitter', () => {
      const headers: Record<string, string> = { 'X-MY-USER-GROUPS': 'headerGroupA;headerGroupB' };
      const req = { header: (key: string) => headers[key] };
      const groupManagementConfig: Partial <BasicStoreEntityAuthenticationProvider> = {
        groups_management: {
          groups_mapping: ['headerGroupA:openCTIGroupA', 'headerGroupB:openCTIGroupB', 'headerGroupC:openCTIGroupC'],
          groups_header: 'X-MY-USER-GROUPS',
          groups_splitter: ';',
        },
      };
      const result = computeGroupsMapping(groupManagementConfig as BasicStoreEntityAuthenticationProvider, req);
      expect(result).toStrictEqual(['openCTIGroupA', 'openCTIGroupB']);
    });

    it('should Header org mapping be computed correctly with default org', () => {
      const headers: Record<string, string> = { 'X-MY-USER-ORG': 'headerOrgA;headerOrgB' };
      const req = { header: (key: string) => headers[key] };
      const orgManagementConfig: Partial <BasicStoreEntityAuthenticationProvider> = {
        organizations_management: {
          organizations_mapping: ['headerOrgA:openCTIOrgA', 'headerOrgB:openCTIOrgB', 'headerOrgC:openCTIOrgC'],
          organizations_header: 'X-MY-USER-ORG',
          organizations_splitter: ';',
        },
      };
      const result = computeOrganizationsMapping(orgManagementConfig as BasicStoreEntityAuthenticationProvider, ['openCTIOrgC'], req);
      expect(result).toStrictEqual(['openCTIOrgC', 'openCTIOrgA', 'openCTIOrgB']);
    });
  });
});
