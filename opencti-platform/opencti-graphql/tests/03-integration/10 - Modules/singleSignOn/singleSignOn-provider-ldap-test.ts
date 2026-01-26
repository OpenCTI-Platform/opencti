import { describe, expect, it } from 'vitest';
import { convertKeyValueToJsConfiguration } from '../../../../src/modules/singleSignOn/singleSignOn-providers';
import type { BasicStoreEntitySingleSignOn } from '../../../../src/modules/singleSignOn/singleSignOn-types';
import { computeLdapGroups, computeLdapOrganizations, computeLdapUserInfo } from '../../../../src/modules/singleSignOn/singleSignOn-provider-ldap';

describe('LDAP Single sign on Provider coverage tests', () => {
  describe('LDAP userInfo mapping coverage', () => {
    it('should LDAP user info with default config', async () => {
      const ldapProfile = { mail: 'ldap1@opencti.io', givenName: 'ldap1' };
      const ssoEntity: Partial<BasicStoreEntitySingleSignOn> = {
        identifier: 'ldap',
        configuration: [
          { key: 'url', type: 'string', value: 'ldap://localhost:389' },
          { key: 'bindDN', type: 'string', value: 'cn=admin,dc=example,dc=org' },
          { key: 'bindCredentials', type: 'string', value: 'youShallNotPass' },
          { key: 'searchBase', type: 'string', value: 'dc=example,dc=org' },
          { key: 'searchFilter', type: 'string', value: 'mail={{username}}' },
        ],
      };
      const ssoConfiguration: any = convertKeyValueToJsConfiguration(ssoEntity as BasicStoreEntitySingleSignOn);

      const result = computeLdapUserInfo(ssoConfiguration, ldapProfile);
      expect(result.email).toBe('ldap1@opencti.io');
      expect(result.name).toBe('ldap1');
      expect(result.firstname).toBe('');
      expect(result.lastname).toBe('');
    });

    it('should LDAP user info with advanced config works', async () => {
      const ldapProfile = { theMail: 'samltestuser1@opencti.io', theFirsname: 'Ada', theLastName: 'Lovelace', theAccount: 'Duchess Ada' };
      const ssoEntity: Partial<BasicStoreEntitySingleSignOn> = {
        identifier: 'ldap',
        configuration: [
          { key: 'url', type: 'string', value: 'ldap://localhost:389' },
          { key: 'bindDN', type: 'string', value: 'cn=admin,dc=example,dc=org' },
          { key: 'bindCredentials', type: 'string', value: 'youShallNotPass' },
          { key: 'searchBase', type: 'string', value: 'dc=example,dc=org' },
          { key: 'searchFilter', type: 'string', value: 'mail={{username}}' },
          { key: 'account_attribute', type: 'string', value: 'theAccount' },
          { key: 'firstname_attribute', type: 'string', value: 'theFirsname' },
          { key: 'lastname_attribute', type: 'string', value: 'theLastName' },
          { key: 'mail_attribute', type: 'string', value: 'theMail' },
        ],
      };
      const ssoConfiguration: any = convertKeyValueToJsConfiguration(ssoEntity as BasicStoreEntitySingleSignOn);

      const result = computeLdapUserInfo(ssoConfiguration, ldapProfile);
      expect(result.email).toBe('samltestuser1@opencti.io');
      expect(result.name).toBe('Duchess Ada');
      expect(result.firstname).toBe('Ada');
      expect(result.lastname).toBe('Lovelace');
    });
  });

  describe('LDAP groups and org mapping coverage', () => {
    it('should LDAP group mapping be computed correctly with default group attribute', async () => {
      const ldapProfile = { mail: 'ldap1@opencti.io', givenName: 'ldap1', _groups: [{ cn: 'ldapGroupA' }, { cn: 'ldapGroupD' }] };
      const ssoEntity: Partial<BasicStoreEntitySingleSignOn> = {
        identifier: 'ldap',
        configuration: [
          { key: 'url', type: 'string', value: 'ldap://localhost:389' },
          { key: 'bindDN', type: 'string', value: 'cn=admin,dc=example,dc=org' },
          { key: 'bindCredentials', type: 'string', value: 'youShallNotPass' },
          { key: 'searchBase', type: 'string', value: 'dc=example,dc=org' },
          { key: 'searchFilter', type: 'string', value: 'mail={{username}}' },
        ],
        groups_management: {
          groups_mapping: ['ldapGroupA:openCTIGroupA', 'ldapGroupB:openCTIGroupB', 'ldapGroupC:openCTIGroupC'],
        },
      };
      const result = computeLdapGroups(ssoEntity as BasicStoreEntitySingleSignOn, ldapProfile);
      expect(result).toStrictEqual(['openCTIGroupA']);
    });

    it('should LDAP group mapping be computed correctly with default group attribute', async () => {
      const ldapProfile = { mail: 'ldap1@opencti.io', givenName: 'ldap1', _groups: [{ ccn: 'ldapGroupA', cn: 'ldapGroupB' }, { ccn: 'ldapGroupD', cn: 'ldapGroupB' }] };
      const ssoEntity: Partial<BasicStoreEntitySingleSignOn> = {
        identifier: 'ldap',
        configuration: [
          { key: 'url', type: 'string', value: 'ldap://localhost:389' },
          { key: 'bindDN', type: 'string', value: 'cn=admin,dc=example,dc=org' },
          { key: 'bindCredentials', type: 'string', value: 'youShallNotPass' },
          { key: 'searchBase', type: 'string', value: 'dc=example,dc=org' },
          { key: 'searchFilter', type: 'string', value: 'mail={{username}}' },
        ],
        groups_management: {
          groups_mapping: ['ldapGroupA:openCTIGroupA', 'ldapGroupB:openCTIGroupB', 'ldapGroupC:openCTIGroupC'],
          group_attribute: 'ccn',
        },
      };
      const result = computeLdapGroups(ssoEntity as BasicStoreEntitySingleSignOn, ldapProfile);
      expect(result).toStrictEqual(['openCTIGroupA']);
    });

    it('should LDAP org mapping be computed correctly with default attribute', async () => {
      const ldapProfile = { mail: 'ldap2@opencti.io', givenName: 'ldap1', organizations: ['LDAPOrg1'] };
      const ssoEntity: Partial<BasicStoreEntitySingleSignOn> = {
        identifier: 'ldap',
        configuration: [
          { key: 'url', type: 'string', value: 'ldap://localhost:389' },
          { key: 'bindDN', type: 'string', value: 'cn=admin,dc=example,dc=org' },
          { key: 'bindCredentials', type: 'string', value: 'youShallNotPass' },
          { key: 'searchBase', type: 'string', value: 'dc=example,dc=org' },
          { key: 'searchFilter', type: 'string', value: 'mail={{username}}' },
        ],
        organizations_management: {
          organizations_mapping: ['LDAPOrg1:openCTIOrg1'],
        },
      };
      const result = computeLdapOrganizations(ssoEntity as BasicStoreEntitySingleSignOn, ldapProfile, undefined);
      expect(result).toStrictEqual(['openCTIOrg1']);
    });

    it('should LDAP org mapping be computed correctly with custom path attribute', async () => {
      const ldapProfile = { mail: 'ldap2@opencti.io', givenName: 'ldap1', org: { inner: ['LDAPOrg1'] } };
      const ssoEntity: Partial<BasicStoreEntitySingleSignOn> = {
        identifier: 'ldap',
        configuration: [
          { key: 'url', type: 'string', value: 'ldap://localhost:389' },
          { key: 'bindDN', type: 'string', value: 'cn=admin,dc=example,dc=org' },
          { key: 'bindCredentials', type: 'string', value: 'youShallNotPass' },
          { key: 'searchBase', type: 'string', value: 'dc=example,dc=org' },
          { key: 'searchFilter', type: 'string', value: 'mail={{username}}' },
        ],
        organizations_management: {
          organizations_mapping: ['LDAPOrg1:openCTIOrg1'],
          organizations_path: ['org.inner'],
        },
      };
      const result = computeLdapOrganizations(ssoEntity as BasicStoreEntitySingleSignOn, ldapProfile, undefined);
      expect(result).toStrictEqual(['openCTIOrg1']);
    });
  });
});
