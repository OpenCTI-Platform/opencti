import { describe, expect, it } from 'vitest';
import { parseSingleSignOnRunConfiguration } from '../../../src/modules/singleSignOn/singleSignOn-migration';
import { ADMIN_USER, testContext } from '../../utils/testQuery';
import { deleteSingleSignOn, findSingleSignOnById } from '../../../src/modules/singleSignOn/singleSignOn-domain';

describe('Migration of SSO environment test coverage', () => {
  describe.only('Dry run of migrations', () => {
    it('should default configuration with only local works', async () => {
      const configuration = {
        local: {
          strategy: 'LocalStrategy',
        },
      };

      const result = await parseSingleSignOnRunConfiguration(testContext, ADMIN_USER, configuration, true);
      expect(result[0].strategy).toBe('LocalStrategy');
      expect(result[0].name).toMatch(/local-*/);
      expect(result[0].enabled).toBeTruthy();
      expect(result.length).toBe(1);
    });

    it('should SAML minimal configuration works', async () => {
      const configuration = {
        saml_minimal: {
          identifier: 'saml_minimal',
          strategy: 'SamlStrategy',
          config: {
            issuer: 'openctisaml',
            entry_point: 'http://localhost:9999/realms/master/protocol/saml',
            saml_callback_url: 'http://localhost:4000/auth/saml/callback',
            cert: 'totallyFakeCert',
          },
        },
      };

      const result = await parseSingleSignOnRunConfiguration(testContext, ADMIN_USER, configuration, true);

      const minimalSamlConfiguration = result[0];

      expect(minimalSamlConfiguration.strategy).toBe('SamlStrategy');
      expect(minimalSamlConfiguration.name).toMatch(/saml_minimal-*/);
      expect(minimalSamlConfiguration.label).toBe('saml_minimal');
      expect(minimalSamlConfiguration.enabled).toBeTruthy();
      expect(minimalSamlConfiguration.configuration).toStrictEqual([
        { key: 'issuer', type: 'string', value: 'openctisaml' },
        { key: 'entryPoint', type: 'string', value: 'http://localhost:9999/realms/master/protocol/saml' },
        { key: 'callbackUrl', type: 'string', value: 'http://localhost:4000/auth/saml/callback' },
        { key: 'idpCert', type: 'string', value: 'totallyFakeCert' },
      ]);
    });

    it('should SAML with all types in configuration works', async () => {
      const configuration = {
        saml_all_types: {
          identifier: 'saml_all_types',
          strategy: 'SamlStrategy',
          config: {
            label: 'My test SAML with Types',
            issuer: 'openctisaml_all_types',
            entry_point: 'http://localhost:7777/realms/master/protocol/saml',
            saml_callback_url: 'http://localhost:2000/auth/saml/callback',
            cert: 'totallyFakeCert3',
            acceptedClockSkewMs: 5,
            xmlSignatureTransforms: ['http://www.w3.org/2000/09/xmldsig#enveloped-signature', 'http://www.w3.org/2001/10/xml-exc-c14n#'],
            want_assertions_signed: true,
          },
        },
      };

      const result = await parseSingleSignOnRunConfiguration(testContext, ADMIN_USER, configuration, true);

      const allTypesSamlConfiguration = result[0];

      expect(allTypesSamlConfiguration.strategy).toBe('SamlStrategy');
      expect(allTypesSamlConfiguration.name).toMatch(/My test SAML with Types-*/);
      expect(allTypesSamlConfiguration.label).toBe('My test SAML with Types');
      expect(allTypesSamlConfiguration.enabled).toBeTruthy();
      expect(allTypesSamlConfiguration.configuration).toStrictEqual([
        { key: 'issuer', type: 'string', value: 'openctisaml_all_types' },
        { key: 'entryPoint', type: 'string', value: 'http://localhost:7777/realms/master/protocol/saml' },
        { key: 'callbackUrl', type: 'string', value: 'http://localhost:2000/auth/saml/callback' },
        { key: 'idpCert', type: 'string', value: 'totallyFakeCert3' },
        { key: 'acceptedClockSkewMs', type: 'number', value: '5' },
        { key: 'xmlSignatureTransforms', type: 'array', value: ['http://www.w3.org/2000/09/xmldsig#enveloped-signature', 'http://www.w3.org/2001/10/xml-exc-c14n#'] },
        { key: 'wantAssertionsSigned', type: 'boolean', value: 'true' },
      ]);
    });

    it('should SAML with groups mapping in configuration works', async () => {
      const configuration = {
        saml_groups: {
          identifier: 'saml_groups',
          strategy: 'SamlStrategy',
          config: {
            label: 'My test SAML with Groups',
            issuer: 'openctisaml_groups',
            entry_point: 'http://localhost:8888/realms/master/protocol/saml',
            saml_callback_url: 'http://localhost:3000/auth/saml/callback',
            cert: 'totallyFakeCertGroups',
            groups_management: {
              group_attributes: ['samlgroup1', 'samlgroup2'],
              groups_path: ['groups'],
              groups_mapping: ['group1:Administrators', 'group2:Connectors'],
            },
          },
        },
        saml_groups2: {
          identifier: 'saml_groups_default',
          strategy: 'SamlStrategy',
          config: {
            label: 'My test SAML with Groups Mapping empty',
            issuer: 'openctisaml_groups',
            entry_point: 'http://localhost:8888/realms/master/protocol/saml',
            saml_callback_url: 'http://localhost:3000/auth/saml/callback',
            cert: 'totallyFakeCertGroups',
            groups_management: {
            },
          },
        },
      };

      const result = await parseSingleSignOnRunConfiguration(testContext, ADMIN_USER, configuration, true);

      const groupManagementSAMLConfiguration = result[0];
      expect(groupManagementSAMLConfiguration.strategy).toBe('SamlStrategy');
      expect(groupManagementSAMLConfiguration.name).toMatch(/My test SAML with Groups-*/);
      expect(groupManagementSAMLConfiguration.label).toBe('My test SAML with Groups');
      expect(groupManagementSAMLConfiguration.enabled).toBeTruthy();
      expect(groupManagementSAMLConfiguration.configuration).toStrictEqual([
        { key: 'issuer', type: 'string', value: 'openctisaml_groups' },
        { key: 'entryPoint', type: 'string', value: 'http://localhost:8888/realms/master/protocol/saml' },
        { key: 'callbackUrl', type: 'string', value: 'http://localhost:3000/auth/saml/callback' },
        { key: 'idpCert', type: 'string', value: 'totallyFakeCertGroups' },
      ]);

      expect(groupManagementSAMLConfiguration.groups_management).toStrictEqual({
        group_attributes: ['samlgroup1', 'samlgroup2'],
        groups_path: ['groups'],
        groups_mapping: ['group1:Administrators', 'group2:Connectors'],
      });

      const groupManagementEmptyConfiguration = result[1];
      expect(groupManagementEmptyConfiguration.strategy).toBe('SamlStrategy');
      expect(groupManagementEmptyConfiguration.name).toMatch(/My test SAML with Groups Mapping empty-*/);
      expect(groupManagementEmptyConfiguration.label).toBe('My test SAML with Groups Mapping empty');
      expect(groupManagementEmptyConfiguration.enabled).toBeTruthy();
      expect(groupManagementEmptyConfiguration.configuration).toStrictEqual([
        { key: 'issuer', type: 'string', value: 'openctisaml_groups' },
        { key: 'entryPoint', type: 'string', value: 'http://localhost:8888/realms/master/protocol/saml' },
        { key: 'callbackUrl', type: 'string', value: 'http://localhost:3000/auth/saml/callback' },
        { key: 'idpCert', type: 'string', value: 'totallyFakeCertGroups' },
      ]);

      expect(groupManagementEmptyConfiguration.groups_management).toStrictEqual({
        group_attributes: ['groups'],
        groups_mapping: [],
      });
    });

    it('should SAML with deprecated role mapping configuration works', async () => {
      const configuration = {
        saml: {
          identifier: 'saml',
          strategy: 'SamlStrategy',
          config: {
            issuer: 'openctisaml',
            entry_point: 'http://localhost:9999/realms/master/protocol/saml',
            saml_callback_url: 'http://localhost:4000/auth/saml/callback',
            cert: 'totallyFakeCert',
            roles_management: {
              roles_attributes: ['role1', 'role2'],
            },
          },
        },
      };

      const result = await parseSingleSignOnRunConfiguration(testContext, ADMIN_USER, configuration, true);

      const deprecatedSamlConfiguration = result[0];

      expect(deprecatedSamlConfiguration.strategy).toBe('SamlStrategy');
      expect(deprecatedSamlConfiguration.name).toMatch(/saml-*/);
      expect(deprecatedSamlConfiguration.label).toBe('saml');
      expect(deprecatedSamlConfiguration.enabled).toBeTruthy();
      expect(deprecatedSamlConfiguration.configuration).toStrictEqual([
        { key: 'issuer', type: 'string', value: 'openctisaml' },
        { key: 'entryPoint', type: 'string', value: 'http://localhost:9999/realms/master/protocol/saml' },
        { key: 'callbackUrl', type: 'string', value: 'http://localhost:4000/auth/saml/callback' },
        { key: 'idpCert', type: 'string', value: 'totallyFakeCert' },
      ]);
    });

    it('should SAML with several SAML config works', async () => {
      const configuration = {
        saml_1: {
          identifier: 'saml_1',
          strategy: 'SamlStrategy',
          config: {
            issuer: 'openctisaml',
            entry_point: 'http://localhost:9999/realms/master/protocol/saml',
            saml_callback_url: 'http://localhost:4000/auth/saml/callback',
            cert: 'totallyFakeCert',
          },
        },
        saml_2: {
          identifier: 'saml_2',
          strategy: 'SamlStrategy',
          config: {
            issuer: 'openctisaml',
            entry_point: 'http://localhost:9999/realms/master/protocol/saml',
            saml_callback_url: 'http://localhost:4000/auth/saml/callback',
            cert: 'totallyFakeCert2',
          },
        },
      };

      const multiSamlConfigurations = await parseSingleSignOnRunConfiguration(testContext, ADMIN_USER, configuration, true);

      expect(multiSamlConfigurations[0].strategy).toBe('SamlStrategy');
      expect(multiSamlConfigurations[0].name).toMatch(/saml_1-*/);
      expect(multiSamlConfigurations[0].label).toBe('saml_1');
      expect(multiSamlConfigurations[0].enabled).toBeTruthy();
      expect(multiSamlConfigurations[0].configuration).toStrictEqual([
        { key: 'issuer', type: 'string', value: 'openctisaml' },
        { key: 'entryPoint', type: 'string', value: 'http://localhost:9999/realms/master/protocol/saml' },
        { key: 'callbackUrl', type: 'string', value: 'http://localhost:4000/auth/saml/callback' },
        { key: 'idpCert', type: 'string', value: 'totallyFakeCert' },
      ]);
      expect(multiSamlConfigurations[1].strategy).toBe('SamlStrategy');
      expect(multiSamlConfigurations[1].name).toMatch(/saml_2-*/);
      expect(multiSamlConfigurations[1].label).toBe('saml_2');
      expect(multiSamlConfigurations[1].enabled).toBeTruthy();
      expect(multiSamlConfigurations[1].configuration).toStrictEqual([
        { key: 'issuer', type: 'string', value: 'openctisaml' },
        { key: 'entryPoint', type: 'string', value: 'http://localhost:9999/realms/master/protocol/saml' },
        { key: 'callbackUrl', type: 'string', value: 'http://localhost:4000/auth/saml/callback' },
        { key: 'idpCert', type: 'string', value: 'totallyFakeCert2' },
      ]);
    });

    it('should SAML with default values works', async () => {
      const configuration = {
        saml_default: {
          identifier: 'saml_default',
          strategy: 'SamlStrategy',
          config: {
            label: 'My test SAML with default values',
            issuer: 'openctisaml_default',
            entry_point: 'http://localhost:8888/realms/master/protocol/saml',
            saml_callback_url: 'http://localhost:3000/auth/saml/callback',
            cert: 'totallyFakeCertGroups',
            groups_management: {
            },
            organizations_management: {
            },
          },
        },
      };

      const result = await parseSingleSignOnRunConfiguration(testContext, ADMIN_USER, configuration, true);
      const defaultValuesConfiguration = result[0];
      expect(defaultValuesConfiguration.strategy).toBe('SamlStrategy');
      expect(defaultValuesConfiguration.name).toMatch(/My test SAML with default values*/);
      expect(defaultValuesConfiguration.label).toBe('My test SAML with default values');
      expect(defaultValuesConfiguration.enabled).toBeTruthy();
      expect(defaultValuesConfiguration.configuration).toStrictEqual([
        { key: 'issuer', type: 'string', value: 'openctisaml_default' },
        { key: 'entryPoint', type: 'string', value: 'http://localhost:8888/realms/master/protocol/saml' },
        { key: 'callbackUrl', type: 'string', value: 'http://localhost:3000/auth/saml/callback' },
        { key: 'idpCert', type: 'string', value: 'totallyFakeCertGroups' },
      ]);

      expect(defaultValuesConfiguration.groups_management).toStrictEqual({
        group_attributes: ['groups'],
        groups_mapping: [],
      });
      expect(defaultValuesConfiguration.organizations_management).toStrictEqual({
        organizations_mapping: [],
        organizations_path: ['organizations'],
      });
    });

    it('should OpenID configuration works', async () => {
      const configuration = {
        oic_simple: {
          identifier: 'oic_simple',
          strategy: 'OpenIDConnectStrategy',
          config: {
            issuer: 'http://localhost:9999/realms/master',
            client_id: 'openctioid',
            client_secret: 'youShallNotPass',
            redirect_uris: ['http://localhost:4000/auth/oic/callback'],
            logout_remote: true,
            prevent_default_groups: false,
          },
        },
        oic_groups: {
          identifier: 'oic_groups',
          strategy: 'OpenIDConnectStrategy',
          config: {
            label: 'OpenID for migration test with groups',
            issuer: 'http://localhost:9999/realms/master',
            client_id: 'openctioid',
            client_secret: 'youShallNotPass',
            redirect_uris: ['http://localhost:4000/auth/oic/callback'],
            logout_remote: true,
            prevent_default_groups: false,
            groups_management: {
              groups_attributes: ['roles'],
              groups_path: ['realm_access.roles'],
              groups_mapping: ['default-roles-master:Connectors'],
              read_userinfo: false,
            },
          },
        },
        oic_orgs: {
          identifier: 'oic_orgs',
          strategy: 'OpenIDConnectStrategy',
          config: {
            label: 'OpenID for migration test with organizations',
            issuer: 'http://localhost:9999/realms/master',
            client_id: 'openctioid',
            client_secret: 'youShallNotPass',
            redirect_uris: ['http://localhost:4000/auth/oic/callback'],
            logout_remote: true,
            prevent_default_groups: false,
            organizations_management: {
              organizations_path: ['Role'],
              organizations_mapping: ['manage-authorization:Filigran', 'create-realm:Filigran', 'uma_authorization:Filigran', 'offline_access:Filigran'],
            },
          },
        },
      };

      const result = await parseSingleSignOnRunConfiguration(testContext, ADMIN_USER, configuration, true);

      const simpleOpenIdConfiguration = result[0];
      const groupManagementOpenIdConfiguration = result[1];
      const orgManagementOpenIdConfiguration = result[2];

      expect(simpleOpenIdConfiguration.strategy).toBe('OpenIDConnectStrategy');
      expect(simpleOpenIdConfiguration.name).toMatch(/oic_simple-*/);
      expect(simpleOpenIdConfiguration.enabled).toBeTruthy();

      expect(groupManagementOpenIdConfiguration.strategy).toBe('OpenIDConnectStrategy');
      expect(groupManagementOpenIdConfiguration.name).toMatch(/OpenID for migration test with groups-*/);
      expect(groupManagementOpenIdConfiguration.enabled).toBeTruthy();

      expect(orgManagementOpenIdConfiguration.strategy).toBe('OpenIDConnectStrategy');
      expect(orgManagementOpenIdConfiguration.name).toMatch(/OpenID for migration test with organizations-*/);
      expect(orgManagementOpenIdConfiguration.enabled).toBeTruthy();

      expect(result.length).toBe(3);
    });
  });

  describe('Actual run of migrations', () => {
    it('should default configuration with only local works', async () => {
      const configuration = {
        local: {
          strategy: 'LocalStrategy',
        },
      };

      const result = await parseSingleSignOnRunConfiguration(testContext, ADMIN_USER, configuration, false);
      expect(result[0].strategy).toBe('LocalStrategy');
      expect(result[0].name).toMatch(/local-*/);
      expect(result[0].enabled).toBeTruthy();
      expect(result.length).toBe(1);

      const entity = await findSingleSignOnById(testContext, ADMIN_USER, result[0].id);
      expect(entity.strategy).toBe('LocalStrategy');
      expect(entity.name).toMatch(/local-*/);
      expect(entity.enabled).toBeTruthy();

      await deleteSingleSignOn(testContext, ADMIN_USER, result[0].id);
    });
  });
});
