import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { ADMIN_USER, testContext } from '../../utils/testQuery';
import {
  buildSAMLOptions,
  callSamlLoginCallback,
  computeSamlGroupAndOrg,
  convertKeyValueToJsConfiguration,
  initAuthenticationProviders,
  registerLocalStrategy,
} from '../../../src/modules/singleSignOn/singleSignOn-providers';
import { type ProviderConfiguration, PROVIDERS } from '../../../src/config/providers-configuration';
import type { BasicStoreEntitySingleSignOn } from '../../../src/modules/singleSignOn/singleSignOn-types';
import { type GroupsManagement, type OrganizationsManagement, StrategyType } from '../../../src/generated/graphql';

describe('Single sign on Provider coverage tests', () => {
  describe('initialization coverage', () => {
    const clearProvider = async () => {
      for (let i = 0; i < PROVIDERS.length; i++) {
        PROVIDERS.pop();
      }
      expect(PROVIDERS).toStrictEqual([]);
    };

    let PROVIDERS_SAVE: ProviderConfiguration[];
    beforeAll(async () => {
      // Copy existing configuration and reset it for tests purpose.
      PROVIDERS_SAVE = [...PROVIDERS];
    });

    afterAll(async () => {
      // Reinstall initial configuration
      await clearProvider();
      for (let i = 0; i < PROVIDERS_SAVE.length; i++) {
        PROVIDERS.push(PROVIDERS_SAVE[i]);
      }
      expect(PROVIDERS).toStrictEqual(PROVIDERS_SAVE);
    });

    it('should an empty configuration works', async () => {
      // GIVEN no SSO configuration at all
      await clearProvider();
      expect(PROVIDERS).toStrictEqual([]);

      // WHEN initialization is done
      await initAuthenticationProviders(testContext, ADMIN_USER);
      console.log('PROVIDERS:', PROVIDERS);

      // THEN local strategy is configured and enabled
      expect(PROVIDERS).toStrictEqual([
        {
          name: 'local',
          type: 'FORM',
          strategy: 'LocalStrategy',
          provider: 'local',
        },
      ]);
    });

    it('should keep only last local strategy', async () => {
      // GIVEN no SSO configuration at all
      await clearProvider();
      expect(PROVIDERS).toStrictEqual([]);

      // WHEN calling addLocalStrategy twice
      await registerLocalStrategy();
      console.log('PROVIDERS:', PROVIDERS);
      await registerLocalStrategy();

      // THEN only last local strategy is configured and enabled
      expect(PROVIDERS).toStrictEqual([
        {
          name: 'local',
          type: 'FORM',
          strategy: 'LocalStrategy',
          provider: 'local',
        },
      ]);
    });
  });

  describe('configuration computation coverage', () => {
    it('should build correct options for SAML', async () => {
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
      });
    });
  });

  describe('SAML callback coverage', () => {
    it('should callback without profile raise error', async () => {
      const done = () => {};
      const ssoEntity: Partial<BasicStoreEntitySingleSignOn> = {
        identifier: 'saml',
        configuration: [
          { key: 'issuer', type: 'string', value: 'openctisaml_default' },
          { key: 'entryPoint', type: 'string', value: 'http://localhost:8888/realms/master/protocol/saml' },
          { key: 'callbackUrl', type: 'string', value: 'http://localhost:3000/auth/saml/callback' },
          { key: 'idpCert', type: 'string', value: 'totallyFakeCertGroups' },
        ],
      };
      expect(() => callSamlLoginCallback(undefined, done, ssoEntity as BasicStoreEntitySingleSignOn))
        .toThrowError('No profile in SAML response, please verify SAML server configuration');
    });
  });

  describe('SAML userInfo mapping coverage', () => {
    it.todo('should SAML user info work', async () => {
      // need to cover computeSamlUserInfo
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
      const ssoConfiguration: any = convertKeyValueToJsConfiguration(ssoEntity as BasicStoreEntitySingleSignOn);

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
      const ssoConfiguration: any = convertKeyValueToJsConfiguration(ssoEntity as BasicStoreEntitySingleSignOn);

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
      const ssoConfiguration: any = convertKeyValueToJsConfiguration(ssoEntity as BasicStoreEntitySingleSignOn);

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
      const ssoConfiguration: any = convertKeyValueToJsConfiguration(ssoEntity as BasicStoreEntitySingleSignOn);

      const result = computeSamlGroupAndOrg(ssoConfiguration, samlProfile, undefined, orgsManagement);
      // The 2 default org in config + the one mapped from saml profile
      expect(result.providerOrganizations).toStrictEqual(['OrgDefA', 'OrgDefB', 'OpenCTIOrgB']);
    });
  });
});
