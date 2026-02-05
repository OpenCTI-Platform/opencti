import { describe, expect, it } from 'vitest';
import { convertKeyValueToJsConfiguration } from '../../../../src/modules/singleSignOn/singleSignOn-providers';
import type { BasicStoreEntitySingleSignOn } from '../../../../src/modules/singleSignOn/singleSignOn-types';
import { type GroupsManagement, type OrganizationsManagement, StrategyType } from '../../../../src/generated/graphql';
import { buildSAMLOptions, computeSamlGroupAndOrg, computeSamlUserInfo } from '../../../../src/modules/singleSignOn/singleSignOn-provider-saml';
import { encryptAuthValue } from '../../../../src/modules/singleSignOn/singleSignOn-domain';

describe('SAML Single sign on Provider coverage tests', () => {
  describe('SAML configuration coverage', () => {
    it('should build correct options for SAML', async () => {
      const encryptedKey = await encryptAuthValue('kkkkkkkkkkkkk');

      const samlEntity: Partial<BasicStoreEntitySingleSignOn> = {
        strategy: StrategyType.SamlStrategy,
        configuration: [
          {
            key: 'issuer',
            value: 'openctisaml',
            type: 'string',
          },
          {
            key: 'entryPoint',
            value: 'http://localhost:9999/realms/master/protocol/saml',
            type: 'string',
          },
          {
            key: 'callbackUrl',
            value: 'http://localhost:4000/auth/saml/callback',
            type: 'string',
          },
          {
            key: 'idpCert',
            value: 'MIICmzCxxxxuJ1ZY=',
            type: 'string',
          },
          {
            key: 'wantAuthnResponseSigned',
            value: 'false',
            type: 'boolean',
          },
          {
            key: 'acceptedClockSkewMs',
            value: '3',
            type: 'number',
          },
          {
            key: 'privateKey',
            value: `${encryptedKey}`,
            type: 'secret',
          },
        ],
      };

      const result = await buildSAMLOptions(samlEntity as BasicStoreEntitySingleSignOn);
      expect(result).toStrictEqual({
        issuer: 'openctisaml',
        entryPoint: 'http://localhost:9999/realms/master/protocol/saml',
        callbackUrl: 'http://localhost:4000/auth/saml/callback',
        idpCert: 'MIICmzCxxxxuJ1ZY=',
        wantAuthnResponseSigned: false,
        acceptedClockSkewMs: 3,
        privateKey: 'kkkkkkkkkkkkk',
      });
    });
  });

  describe('SAML userInfo mapping coverage', () => {
    it('should SAML user info with default config', async () => {
      const samlProfile = { nameID: 'samltestuser1@opencti.io' };
      const ssoEntity: Partial<BasicStoreEntitySingleSignOn> = {
        identifier: 'saml',
        configuration: [
          { key: 'issuer', type: 'string', value: 'openctisaml_default' },
          { key: 'entryPoint', type: 'string', value: 'http://localhost:8888/realms/master/protocol/saml' },
          { key: 'callbackUrl', type: 'string', value: 'http://localhost:3000/auth/saml/callback' },
          { key: 'idpCert', type: 'string', value: 'totallyFakeCertGroups' },
        ],
      };
      const ssoConfiguration: any = await convertKeyValueToJsConfiguration(ssoEntity as BasicStoreEntitySingleSignOn);

      const result = computeSamlUserInfo(ssoConfiguration, samlProfile);
      expect(result.email).toBe('samltestuser1@opencti.io');
      expect(result.name).toBe('');
      expect(result.firstname).toBe('');
      expect(result.lastname).toBe('');
    });

    it('should SAML user info with advanced config works', async () => {
      const samlProfile = { nameID: 'ada', theMail: 'samltestuser1@opencti.io', theFirsname: 'Ada', theLastName: 'Lovelace', theAccount: 'Duchess Ada' };
      const ssoEntity: Partial<BasicStoreEntitySingleSignOn> = {
        identifier: 'saml',
        configuration: [
          { key: 'issuer', type: 'string', value: 'openctisaml_default' },
          { key: 'entryPoint', type: 'string', value: 'http://localhost:8888/realms/master/protocol/saml' },
          { key: 'callbackUrl', type: 'string', value: 'http://localhost:3000/auth/saml/callback' },
          { key: 'account_attribute', type: 'string', value: 'theAccount' },
          { key: 'firstname_attribute', type: 'string', value: 'theFirsname' },
          { key: 'lastname_attribute', type: 'string', value: 'theLastName' },
          { key: 'mail_attribute', type: 'string', value: 'theMail' },
        ],
      };
      const ssoConfiguration: any = await convertKeyValueToJsConfiguration(ssoEntity as BasicStoreEntitySingleSignOn);

      const result = computeSamlUserInfo(ssoConfiguration, samlProfile);
      expect(result.email).toBe('samltestuser1@opencti.io');
      expect(result.name).toBe('Duchess Ada');
      expect(result.firstname).toBe('Ada');
      expect(result.lastname).toBe('Lovelace');
    });
  });

  describe('SAML groups and org mapping coverage', () => {
    it('should SAML group mapping be computed correctly with default group attributes', async () => {
    // default mail attribute is nameID, let's use another one like emailID
      const samlProfile = { attributes: { groups: ['samlGroupB', 'samlGroupD', 'samlGroupC'] }, nameID: 'samltest4@opencti.io' };
      const groupsManagement: GroupsManagement = {
        groups_mapping: ['samlGroupA:openCTIGroupA', 'samlGroupB:openCTIGroupB', 'samlGroupC:openCTIGroupC'],
      };
      const ssoEntity: Partial<BasicStoreEntitySingleSignOn> = {
        identifier: 'saml',
        configuration: [
          { key: 'issuer', type: 'string', value: 'openctisaml_default' },
          { key: 'entryPoint', type: 'string', value: 'http://localhost:8888/realms/master/protocol/saml' },
          { key: 'callbackUrl', type: 'string', value: 'http://localhost:3000/auth/saml/callback' },
          { key: 'idpCert', type: 'string', value: 'totallyFakeCertGroups' },
        ],
      };
      const ssoConfiguration: any = await convertKeyValueToJsConfiguration(ssoEntity as BasicStoreEntitySingleSignOn);

      const result = computeSamlGroupAndOrg(ssoConfiguration, samlProfile, groupsManagement, undefined);
      expect(result.providerGroups).toStrictEqual(['openCTIGroupB', 'openCTIGroupC']); // no mapping for D, so should have only B and C
    });

    it('should SAML group mapping be computed correctly with another group attributes', async () => {
    // default mail attribute is nameID, let's use another one like emailID
      const samlProfile = { attributes: { membership: ['samlGroupB1', 'samlGroupD1'], membership2: ['samlGroupC2'] }, nameID: 'samltest5@opencti.io' };
      const groupsManagement: GroupsManagement = {
        groups_mapping: ['samlGroupA:openCTIGroupA', 'samlGroupB1:openCTIGroupB', 'samlGroupC2:openCTIGroupC'],
        group_attributes: ['membership', 'membership2'],
      };
      const ssoEntity: Partial<BasicStoreEntitySingleSignOn> = {
        identifier: 'saml',
        configuration: [
          { key: 'issuer', type: 'string', value: 'openctisaml_default' },
          { key: 'entryPoint', type: 'string', value: 'http://localhost:8888/realms/master/protocol/saml' },
          { key: 'callbackUrl', type: 'string', value: 'http://localhost:3000/auth/saml/callback' },
          { key: 'idpCert', type: 'string', value: 'totallyFakeCertGroups' },
        ],
      };
      const ssoConfiguration: any = await convertKeyValueToJsConfiguration(ssoEntity as BasicStoreEntitySingleSignOn);

      const result = computeSamlGroupAndOrg(ssoConfiguration, samlProfile, groupsManagement, undefined);
      expect(result.providerGroups).toStrictEqual(['openCTIGroupB', 'openCTIGroupC']); // no mapping for D, so should have only B and C
    });

    it('should SAML organization mapping works with default attribute', async () => {
    // default mail attribute is nameID, let's use another one like emailID
      const samlProfile = { attributes: { groups: ['samlGroupC2'] }, nameID: 'samltest6@opencti.io', organizations: ['samlOrgA', 'samlOrgB'] };
      const orgsManagement: OrganizationsManagement = {
        organizations_mapping: ['samlOrgB:OpenCTIOrgB', 'samlOrgC:OpenCTIOrgC'],
      };
      const ssoEntity: Partial<BasicStoreEntitySingleSignOn> = {
        identifier: 'saml',
        configuration: [
          { key: 'issuer', type: 'string', value: 'openctisaml_default' },
          { key: 'entryPoint', type: 'string', value: 'http://localhost:8888/realms/master/protocol/saml' },
          { key: 'callbackUrl', type: 'string', value: 'http://localhost:3000/auth/saml/callback' },
          { key: 'idpCert', type: 'string', value: 'totallyFakeCertGroups' },
        ],
      };
      const ssoConfiguration: any = await convertKeyValueToJsConfiguration(ssoEntity as BasicStoreEntitySingleSignOn);

      const result = computeSamlGroupAndOrg(ssoConfiguration, samlProfile, undefined, orgsManagement);
      expect(result.providerOrganizations).toStrictEqual(['OpenCTIOrgB']); // no mapping for D, so should have only B
    });

    it('should SAML organization mapping works with org default', async () => {
    // default mail attribute is nameID, let's use another one like emailID
      const samlProfile = { attributes: { groups: ['samlGroupC2'] }, nameID: 'samltest7@opencti.io', organizations: ['samlOrgA', 'samlOrgB'] };
      const orgsManagement: OrganizationsManagement = {
        organizations_mapping: ['samlOrgB:OpenCTIOrgB', 'samlOrgC:OpenCTIOrgC'],
      };
      const ssoEntity: Partial<BasicStoreEntitySingleSignOn> = {
        identifier: 'saml',
        configuration: [
          { key: 'issuer', type: 'string', value: 'openctisaml_default' },
          { key: 'entryPoint', type: 'string', value: 'http://localhost:8888/realms/master/protocol/saml' },
          { key: 'callbackUrl', type: 'string', value: 'http://localhost:3000/auth/saml/callback' },
          { key: 'idpCert', type: 'string', value: 'totallyFakeCertGroups' },
          { key: 'organizations_default', type: 'array', value: '["OrgDefA", "OrgDefB"]' },
        ],
      };
      const ssoConfiguration: any = await convertKeyValueToJsConfiguration(ssoEntity as BasicStoreEntitySingleSignOn);

      const result = computeSamlGroupAndOrg(ssoConfiguration, samlProfile, undefined, orgsManagement);
      // The 2 default org in config + the one mapped from saml profile
      expect(result.providerOrganizations).toStrictEqual(['OrgDefA', 'OrgDefB', 'OpenCTIOrgB']);
    });
  });
});
