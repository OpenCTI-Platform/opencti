import { describe, expect, it } from 'vitest';
import { parseSingleSignOnRunConfiguration } from '../../../src/modules/singleSignOn/singleSignOn-migration';
import { ADMIN_USER, testContext } from '../../utils/testQuery';
import { deleteSingleSignOn } from '../../../src/modules/singleSignOn/singleSignOn-domain';
import { MIGRATED_STRATEGY } from '../../../src/config/providers-initialization';
import { EnvStrategyType } from '../../../src/config/providers-configuration';

describe('Migration of SSO environment test coverage', () => {
  describe('Dry run of SAML migrations', () => {
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

    it('should SAML disabled configuration works', async () => {
      const configuration = {
        saml_minimal: {
          identifier: 'saml_minimal',
          strategy: 'SamlStrategy',
          config: {
            disabled: true,
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
      expect(minimalSamlConfiguration.enabled).toBeFalsy();
      expect(minimalSamlConfiguration.configuration).toStrictEqual([
        { key: 'issuer', type: 'string', value: 'openctisaml' },
        { key: 'entryPoint', type: 'string', value: 'http://localhost:9999/realms/master/protocol/saml' },
        { key: 'callbackUrl', type: 'string', value: 'http://localhost:4000/auth/saml/callback' },
        { key: 'idpCert', type: 'string', value: 'totallyFakeCert' },
      ]);
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
            organizations_default: ['OpenCTI'],
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
        { key: 'xmlSignatureTransforms', type: 'array', value: '["http://www.w3.org/2000/09/xmldsig#enveloped-signature","http://www.w3.org/2001/10/xml-exc-c14n#"]' },
        { key: 'wantAssertionsSigned', type: 'boolean', value: 'true' },
        { key: 'organizations_default', type: 'array', value: '["OpenCTI"]' },
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
  });
  describe('Dry run of OpenId migrations', () => {
    it('should OpenId minimal configuration works', async () => {
      if (!MIGRATED_STRATEGY.some((strat) => strat === EnvStrategyType.STRATEGY_OPENID)) {
        return;
      }
      const configuration = {
        oic_minimal: {
          identifier: 'oic_minimal',
          strategy: 'OpenIDConnectStrategy',
          config: {
            issuer: 'http://localhost:9999/realms/master',
            client_id: 'openctioid',
            client_secret: 'youShallNotPass',
            redirect_uris: ['http://localhost:4000/auth/oic/callback'],
          },
        },
      };

      const result = await parseSingleSignOnRunConfiguration(testContext, ADMIN_USER, configuration, true);

      const minimalOpenIdConfiguration = result[0];

      expect(minimalOpenIdConfiguration.strategy).toBe('OpenIDConnectStrategy');
      expect(minimalOpenIdConfiguration.label).toBe('oic_minimal');
      expect(minimalOpenIdConfiguration.enabled).toBeTruthy();
      expect(minimalOpenIdConfiguration.configuration).toStrictEqual([
        { key: 'issuer', type: 'string', value: 'http://localhost:9999/realms/master' },
        { key: 'client_id', type: 'string', value: 'openctioid' },
        { key: 'client_secret', type: 'string', value: 'youShallNotPass' },
        { key: 'redirect_uris', type: 'array', value: '["http://localhost:4000/auth/oic/callback"]' },
      ]);
    });

    it('should OpenId with all types in configuration works', async () => {
      if (!MIGRATED_STRATEGY.some((strat) => strat === EnvStrategyType.STRATEGY_OPENID)) {
        return;
      }

      const configuration = {
        oic_all_types: {
          identifier: 'oic_all_types',
          strategy: 'OpenIDConnectStrategy',
          config: {
            issuer: 'http://localhost:9999/realms/master',
            client_id: 'openctioid',
            client_secret: 'youShallNotPass',
            redirect_uris: ['http://localhost:4000/auth/oic/callback'],
            label: 'My test oic with Types',
            entry_point: 'http://localhost:7777/realms/master/protocol/oic',
          },
        },
      };

      const result = await parseSingleSignOnRunConfiguration(testContext, ADMIN_USER, configuration, true);

      const allTypesOpenIdConfiguration = result[0];

      expect(allTypesOpenIdConfiguration.strategy).toBe('OpenIDConnectStrategy');
      expect(allTypesOpenIdConfiguration.label).toBe('My test oic with Types');
      expect(allTypesOpenIdConfiguration.enabled).toBeTruthy();
      expect(allTypesOpenIdConfiguration.configuration).toStrictEqual([
        { key: 'issuer', type: 'string', value: 'http://localhost:9999/realms/master' },
        { key: 'client_id', type: 'string', value: 'openctioid' },
        { key: 'client_secret', type: 'string', value: 'youShallNotPass' },
        { key: 'redirect_uris', type: 'array', value: '["http://localhost:4000/auth/oic/callback"]' },
        { key: 'entry_point', type: 'string', value: 'http://localhost:7777/realms/master/protocol/oic' },
      ]);
    });

    it('should OpenId with groups mapping in configuration works', async () => {
      if (!MIGRATED_STRATEGY.some((strat) => strat === EnvStrategyType.STRATEGY_OPENID)) {
        return;
      }
      const configuration = {
        oic_groups: {
          identifier: 'oic_groups',
          strategy: 'OpenIDConnectStrategy',
          config: {
            issuer: 'http://localhost:9999/realms/master',
            client_id: 'openctioid',
            client_secret: 'youShallNotPass',
            redirect_uris: ['http://localhost:4000/auth/oic/callback'],
            logout_remote: true,
            prevent_default_groups: false,
            groups_management: {
              groups_path: ['realm_access.roles'],
              groups_mapping: ['default-roles-master:Connectors'],
              read_userinfo: false,
              token_reference: 'token',
              groups_scope: 'groupsScope',
            },
          },
        },
      };

      const result = await parseSingleSignOnRunConfiguration(testContext, ADMIN_USER, configuration, true);
      const groupManagementOpenIdConfiguration = result[0];
      expect(groupManagementOpenIdConfiguration.strategy).toBe('OpenIDConnectStrategy');
      expect(groupManagementOpenIdConfiguration.label).toBe('oic_groups');
      expect(groupManagementOpenIdConfiguration.enabled).toBeTruthy();
      expect(groupManagementOpenIdConfiguration.configuration).toStrictEqual([
        { key: 'issuer', type: 'string', value: 'http://localhost:9999/realms/master' },
        { key: 'client_id', type: 'string', value: 'openctioid' },
        { key: 'client_secret', type: 'string', value: 'youShallNotPass' },
        { key: 'redirect_uris', type: 'array', value: '["http://localhost:4000/auth/oic/callback"]' },
        { key: 'logout_remote', type: 'boolean', value: 'true' },
        { key: 'prevent_default_groups', type: 'boolean', value: 'false' },
      ]);

      expect(groupManagementOpenIdConfiguration.groups_management).toStrictEqual({
        groups_mapping: ['default-roles-master:Connectors'],
        groups_path: ['realm_access.roles'],
        read_userinfo: false,
        token_reference: 'token',
        groups_scope: 'groupsScope',
      });
    });

    it('should OpenId with several OpenId config works', async () => {
      if (!MIGRATED_STRATEGY.some((strat) => strat === EnvStrategyType.STRATEGY_OPENID)) {
        return;
      }
      const configuration = {
        oic_1: {
          identifier: 'oic_1',
          strategy: 'OpenIDConnectStrategy',
          config: {
            issuer: 'http://localhost:9999/realms/master',
            client_id: 'openctioid',
            client_secret: 'youShallNotPass',
            redirect_uris: ['http://localhost:4000/auth/oic/callback'],
          },
        },
        oic_2: {
          identifier: 'oic_2',
          strategy: 'OpenIDConnectStrategy',
          config: {
            issuer: 'http://localhost:9999/realms/master',
            client_id: 'openctioid',
            client_secret: 'youShallNotPass',
            redirect_uris: ['http://localhost:4000/auth/oic/callback'],
          },
        },
      };

      const multiOicConfigurations = await parseSingleSignOnRunConfiguration(testContext, ADMIN_USER, configuration, true);

      expect(multiOicConfigurations[0].strategy).toBe('OpenIDConnectStrategy');
      expect(multiOicConfigurations[0].label).toBe('oic_1');
      expect(multiOicConfigurations[0].enabled).toBeTruthy();
      expect(multiOicConfigurations[0].configuration).toStrictEqual([
        { key: 'issuer', type: 'string', value: 'http://localhost:9999/realms/master' },
        { key: 'client_id', type: 'string', value: 'openctioid' },
        { key: 'client_secret', type: 'string', value: 'youShallNotPass' },
        { key: 'redirect_uris', type: 'array', value: '["http://localhost:4000/auth/oic/callback"]' },
      ]);
      expect(multiOicConfigurations[1].strategy).toBe('OpenIDConnectStrategy');
      expect(multiOicConfigurations[1].label).toBe('oic_2');
      expect(multiOicConfigurations[1].enabled).toBeTruthy();
      expect(multiOicConfigurations[1].configuration).toStrictEqual([
        { key: 'issuer', type: 'string', value: 'http://localhost:9999/realms/master' },
        { key: 'client_id', type: 'string', value: 'openctioid' },
        { key: 'client_secret', type: 'string', value: 'youShallNotPass' },
        { key: 'redirect_uris', type: 'array', value: '["http://localhost:4000/auth/oic/callback"]' },
      ]);
    });

    it('should OpenId with default values works', async () => {
      if (!MIGRATED_STRATEGY.some((strat) => strat === EnvStrategyType.STRATEGY_OPENID)) {
        return;
      }
      const configuration = {
        oic_default: {
          identifier: 'oic_default',
          strategy: 'OpenIDConnectStrategy',
          config: {
            label: 'My test OpenId with default values',
            issuer: 'http://localhost:9999/realms/master',
            client_id: 'openctioid',
            client_secret: 'youShallNotPass',
            redirect_uris: ['http://localhost:4000/auth/oic/callback'],
            groups_management: {
            },
            organizations_management: {
            },
          },
        },
      };

      const result = await parseSingleSignOnRunConfiguration(testContext, ADMIN_USER, configuration, true);
      const defaultValuesConfiguration = result[0];
      expect(defaultValuesConfiguration.strategy).toBe('OpenIDConnectStrategy');
      expect(defaultValuesConfiguration.label).toBe('My test OpenId with default values');
      expect(defaultValuesConfiguration.enabled).toBeTruthy();
      expect(defaultValuesConfiguration.configuration).toStrictEqual([
        { key: 'issuer', type: 'string', value: 'http://localhost:9999/realms/master' },
        { key: 'client_id', type: 'string', value: 'openctioid' },
        { key: 'client_secret', type: 'string', value: 'youShallNotPass' },
        { key: 'redirect_uris', type: 'array', value: '["http://localhost:4000/auth/oic/callback"]' },
      ]);

      expect(defaultValuesConfiguration.groups_management).toStrictEqual({
        groups_path: ['groups'],
        groups_mapping: [],
        read_userinfo: false,
        token_reference: 'access_token',
      });
      expect(defaultValuesConfiguration.organizations_management).toStrictEqual({
        organizations_path: ['organizations'],
        organizations_mapping: [],
        read_userinfo: false,
        token_reference: 'access_token',
      });
    });
  });
  describe('Dry run of LDAP migrations', () => {
    it('should LDAP minimal configuration works', async () => {
      if (!MIGRATED_STRATEGY.some((strat) => strat === EnvStrategyType.STRATEGY_LDAP)) {
        return;
      }
      const configuration = {
        ldap_minimal: {
          identifier: 'ldap_minimal',
          strategy: 'LdapStrategy',
          config: {
            url: 'ldap://51.178.68.23:390',
            bind_dn: 'CN=user1,DC=fr',
            bind_credentials: 'credentials',
            search_base: 'CN=user1',
            search_filter: '(cn={{username}})',
            mail_attribute: 'userPrincipalName',
          },
        },
      };

      const result = await parseSingleSignOnRunConfiguration(testContext, ADMIN_USER, configuration, true);

      const minimalLDAPConfiguration = result[0];

      expect(minimalLDAPConfiguration.strategy).toBe('LdapStrategy');
      expect(minimalLDAPConfiguration.label).toBe('ldap_minimal');
      expect(minimalLDAPConfiguration.enabled).toBeTruthy();
      expect(minimalLDAPConfiguration.configuration).toStrictEqual([
        { key: 'url', type: 'string', value: 'ldap://51.178.68.23:390' },
        { key: 'bindDN', type: 'string', value: 'CN=user1,DC=fr' },
        { key: 'bindCredentials', type: 'string', value: 'credentials' },
        { key: 'searchBase', type: 'string', value: 'CN=user1' },
        { key: 'searchFilter', type: 'string', value: '(cn={{username}})' },
        { key: 'mail_attribute', type: 'string', value: 'userPrincipalName' },
      ]);
    });

    it('should LDAP with groups mapping in configuration works', async () => {
      if (!MIGRATED_STRATEGY.some((strat) => strat === EnvStrategyType.STRATEGY_LDAP)) {
        return;
      }
      const configuration = {
        ldap_groups: {
          identifier: 'ldap_groups',
          strategy: 'LdapStrategy',
          config: {
            url: 'ldap://51.178.68.23:390',
            bind_dn: 'CN=user1,DC=fr',
            bind_credentials: 'credentials',
            search_base: 'CN=user1',
            search_filter: '(cn={{username}})',
            mail_attribute: 'userPrincipalName',
            groups_management: {
              groups_path: ['realm_access.roles'],
              groups_mapping: ['default-roles-master:Connectors'],
            },
          },
        },
      };

      const result = await parseSingleSignOnRunConfiguration(testContext, ADMIN_USER, configuration, true);
      const groupManagementLDAPConfiguration = result[0];
      expect(groupManagementLDAPConfiguration.strategy).toBe('LdapStrategy');
      expect(groupManagementLDAPConfiguration.label).toBe('ldap_groups');
      expect(groupManagementLDAPConfiguration.enabled).toBeTruthy();
      expect(groupManagementLDAPConfiguration.configuration).toStrictEqual([
        { key: 'url', type: 'string', value: 'ldap://51.178.68.23:390' },
        { key: 'bindDN', type: 'string', value: 'CN=user1,DC=fr' },
        { key: 'bindCredentials', type: 'string', value: 'credentials' },
        { key: 'searchBase', type: 'string', value: 'CN=user1' },
        { key: 'searchFilter', type: 'string', value: '(cn={{username}})' },
        { key: 'mail_attribute', type: 'string', value: 'userPrincipalName' },
      ]);

      expect(groupManagementLDAPConfiguration.groups_management).toStrictEqual({
        group_attribute: 'cn',
        groups_mapping: ['default-roles-master:Connectors'],
        groups_path: ['realm_access.roles'],
      });
    });

    it('should LDAP with several LDAP config works', async () => {
      if (!MIGRATED_STRATEGY.some((strat) => strat === EnvStrategyType.STRATEGY_LDAP)) {
        return;
      }
      const configuration = {
        ldap_1: {
          identifier: 'ldap_1',
          strategy: 'LdapStrategy',
          config: {
            url: 'ldap://51.178.68.23:390',
            bind_dn: 'CN=user1,DC=fr',
            bind_credentials: 'credentials',
            search_base: 'CN=user1',
            search_filter: '(cn={{username}})',
            mail_attribute: 'userPrincipalName',
          },
        },
        ldap_2: {
          identifier: 'ldap_2',
          strategy: 'LdapStrategy',
          config: {
            url: 'ldap://51.178.68.23:390',
            bind_dn: 'CN=user2,DC=fr',
            bind_credentials: 'credentials',
            search_base: 'CN=user2',
            search_filter: '(cn={{username}})',
            mail_attribute: 'userPrincipalName',
          },
        },
      };

      const multiOicConfigurations = await parseSingleSignOnRunConfiguration(testContext, ADMIN_USER, configuration, true);

      expect(multiOicConfigurations[0].strategy).toBe('LdapStrategy');
      expect(multiOicConfigurations[0].label).toBe('ldap_1');
      expect(multiOicConfigurations[0].enabled).toBeTruthy();
      expect(multiOicConfigurations[0].configuration).toStrictEqual([
        { key: 'url', type: 'string', value: 'ldap://51.178.68.23:390' },
        { key: 'bindDN', type: 'string', value: 'CN=user1,DC=fr' },
        { key: 'bindCredentials', type: 'string', value: 'credentials' },
        { key: 'searchBase', type: 'string', value: 'CN=user1' },
        { key: 'searchFilter', type: 'string', value: '(cn={{username}})' },
        { key: 'mail_attribute', type: 'string', value: 'userPrincipalName' },
      ]);
      expect(multiOicConfigurations[1].strategy).toBe('LdapStrategy');
      expect(multiOicConfigurations[1].label).toBe('ldap_2');
      expect(multiOicConfigurations[1].enabled).toBeTruthy();
      expect(multiOicConfigurations[1].configuration).toStrictEqual([
        { key: 'url', type: 'string', value: 'ldap://51.178.68.23:390' },
        { key: 'bindDN', type: 'string', value: 'CN=user2,DC=fr' },
        { key: 'bindCredentials', type: 'string', value: 'credentials' },
        { key: 'searchBase', type: 'string', value: 'CN=user2' },
        { key: 'searchFilter', type: 'string', value: '(cn={{username}})' },
        { key: 'mail_attribute', type: 'string', value: 'userPrincipalName' },
      ]);
    });

    it('should LDAP with default values works', async () => {
      if (!MIGRATED_STRATEGY.some((strat) => strat === EnvStrategyType.STRATEGY_LDAP)) {
        return;
      }
      const configuration = {
        ldap_default: {
          identifier: 'ldap_default',
          strategy: 'LdapStrategy',
          config: {
            url: 'ldap://51.178.68.23:390',
            bind_dn: 'CN=user1,DC=fr',
            bind_credentials: 'credentials',
            search_base: 'CN=user1',
            search_filter: '(cn={{username}})',
            mail_attribute: 'userPrincipalName',
            groups_management: {
            },
            organizations_management: {
            },
          },
        },
      };

      const result = await parseSingleSignOnRunConfiguration(testContext, ADMIN_USER, configuration, true);
      const defaultValuesConfiguration = result[0];
      expect(defaultValuesConfiguration.strategy).toBe('LdapStrategy');
      expect(defaultValuesConfiguration.label).toBe('ldap_default');
      expect(defaultValuesConfiguration.enabled).toBeTruthy();
      expect(defaultValuesConfiguration.configuration).toStrictEqual([
        { key: 'url', type: 'string', value: 'ldap://51.178.68.23:390' },
        { key: 'bindDN', type: 'string', value: 'CN=user1,DC=fr' },
        { key: 'bindCredentials', type: 'string', value: 'credentials' },
        { key: 'searchBase', type: 'string', value: 'CN=user1' },
        { key: 'searchFilter', type: 'string', value: '(cn={{username}})' },
        { key: 'mail_attribute', type: 'string', value: 'userPrincipalName' },
      ]);

      expect(defaultValuesConfiguration.groups_management).toStrictEqual({
        group_attribute: 'cn',
        groups_mapping: [],
      });
      expect(defaultValuesConfiguration.organizations_management).toStrictEqual({
        organizations_path: ['organizations'],
        organizations_mapping: [],
      });
    });
  });
  describe('Dry run of HEADER migrations', () => {
    it('should HEADER minimal configuration works', async () => {
      const configuration = {
        headers_minimal: {
          identifier: 'headers_minimal',
          strategy: 'HeaderStrategy',
          config: {
            header_email: 'X-MY-USER-EMAIL',
            header_name: 'X-MY-USER-NAME',
          },
        },
      };

      const result = await parseSingleSignOnRunConfiguration(testContext, ADMIN_USER, configuration, true);

      const minimalHEADERSConfiguration = result[0];

      expect(minimalHEADERSConfiguration.strategy).toBe('HeaderStrategy');
      expect(minimalHEADERSConfiguration.label).toBe('headers_minimal');
      expect(minimalHEADERSConfiguration.enabled).toBeTruthy();
      expect(minimalHEADERSConfiguration.configuration).toStrictEqual([
        { key: 'header_email', type: 'string', value: 'X-MY-USER-EMAIL' },
        { key: 'header_name', type: 'string', value: 'X-MY-USER-NAME' },
      ]);
    });

    it('should HEADER with groups mapping in configuration works', async () => {
      const configuration = {
        headers_groups: {
          identifier: 'headers_groups',
          strategy: 'HeaderStrategy',
          config: {
            header_email: 'X-MY-USER-EMAIL',
            header_name: 'X-MY-USER-NAME',
            header_firstname: 'X-MY-USER-FIRSTNAME',
            header_lastname: 'X-MY-USER-LASTNAME',
            headers_audit: ['X-MY-USER-AUDIT'],
            groups_management: {
              groups_mapping: ['default-roles-master:Connectors'],
              groups_splitter: '/',
              groups_header: 'header',
            },
          },
        },
      };

      const result = await parseSingleSignOnRunConfiguration(testContext, ADMIN_USER, configuration, true);
      const groupManagementHEADERConfiguration = result[0];
      expect(groupManagementHEADERConfiguration.strategy).toBe('HeaderStrategy');
      expect(groupManagementHEADERConfiguration.label).toBe('headers_groups');
      expect(groupManagementHEADERConfiguration.enabled).toBeTruthy();
      expect(groupManagementHEADERConfiguration.configuration).toStrictEqual([
        { key: 'header_email', type: 'string', value: 'X-MY-USER-EMAIL' },
        { key: 'header_name', type: 'string', value: 'X-MY-USER-NAME' },
        { key: 'header_firstname', type: 'string', value: 'X-MY-USER-FIRSTNAME' },
        { key: 'header_lastname', type: 'string', value: 'X-MY-USER-LASTNAME' },
        { key: 'headers_audit', type: 'array', value: '["X-MY-USER-AUDIT"]' },
      ]);

      expect(groupManagementHEADERConfiguration.groups_management).toStrictEqual({
        groups_mapping: ['default-roles-master:Connectors'],
        groups_splitter: '/',
        groups_header: 'header',
      });
    });

    it('should HEADER with several config works', async () => {
      const configuration = {
        headers_1: {
          identifier: 'headers_1',
          strategy: 'HeaderStrategy',
          config: {
            header_email: 'X-MY-USER-EMAIL1',
            header_name: 'X-MY-USER-NAME1',
            header_firstname: 'X-MY-USER-FIRSTNAME1',
            header_lastname: 'X-MY-USER-LASTNAME1',
            headers_audit: ['X-MY-USER-AUDIT1'],
            groups_management: {
              groups_header: 'X-MY-USER-GROUPS1',
            },
            organizations_management: {
              organizations_header: 'X-MY-USER-ORGANIZATIONS1',
            },
          },
        },
        headers_2: {
          identifier: 'headers_2',
          strategy: 'HeaderStrategy',
          config: {
            header_email: 'X-MY-USER-EMAIL2',
            header_name: 'X-MY-USER-NAME2',
            header_firstname: 'X-MY-USER-FIRSTNAME2',
            header_lastname: 'X-MY-USER-LASTNAME2',
            headers_audit: ['X-MY-USER-AUDIT2'],
            groups_management: {
              groups_header: 'X-MY-USER-GROUPS2',
            },
            organizations_management: {
              organizations_header: 'X-MY-USER-ORGANIZATIONS2',
            },
          },
        },
      };

      const multiOicConfigurations = await parseSingleSignOnRunConfiguration(testContext, ADMIN_USER, configuration, true);

      expect(multiOicConfigurations[0].strategy).toBe('HeaderStrategy');
      expect(multiOicConfigurations[0].label).toBe('headers_1');
      expect(multiOicConfigurations[0].enabled).toBeTruthy();
      expect(multiOicConfigurations[0].configuration).toStrictEqual([
        { key: 'header_email', type: 'string', value: 'X-MY-USER-EMAIL1' },
        { key: 'header_name', type: 'string', value: 'X-MY-USER-NAME1' },
        { key: 'header_firstname', type: 'string', value: 'X-MY-USER-FIRSTNAME1' },
        { key: 'header_lastname', type: 'string', value: 'X-MY-USER-LASTNAME1' },
        { key: 'headers_audit', type: 'array', value: '["X-MY-USER-AUDIT1"]' },
      ]);
      expect(multiOicConfigurations[1].strategy).toBe('HeaderStrategy');
      expect(multiOicConfigurations[1].label).toBe('headers_2');
      expect(multiOicConfigurations[1].enabled).toBeTruthy();
      expect(multiOicConfigurations[1].configuration).toStrictEqual([
        { key: 'header_email', type: 'string', value: 'X-MY-USER-EMAIL2' },
        { key: 'header_name', type: 'string', value: 'X-MY-USER-NAME2' },
        { key: 'header_firstname', type: 'string', value: 'X-MY-USER-FIRSTNAME2' },
        { key: 'header_lastname', type: 'string', value: 'X-MY-USER-LASTNAME2' },
        { key: 'headers_audit', type: 'array', value: '["X-MY-USER-AUDIT2"]' },
      ]);
    });

    it('should HEADER with default values works', async () => {
      const configuration = {
        headers_default: {
          identifier: 'headers_default',
          strategy: 'HeaderStrategy',
          config: {
            header_email: 'X-MY-USER-EMAIL',
            header_name: 'X-MY-USER-NAME',
            header_firstname: 'X-MY-USER-FIRSTNAME',
            header_lastname: 'X-MY-USER-LASTNAME',
            headers_audit: ['X-MY-USER-AUDIT'],
            groups_management: {
            },
            organizations_management: {
            },
          },
        },
      };

      const result = await parseSingleSignOnRunConfiguration(testContext, ADMIN_USER, configuration, true);
      const defaultValuesConfiguration = result[0];
      expect(defaultValuesConfiguration.strategy).toBe('HeaderStrategy');
      expect(defaultValuesConfiguration.label).toBe('headers_default');
      expect(defaultValuesConfiguration.enabled).toBeTruthy();
      expect(defaultValuesConfiguration.configuration).toStrictEqual([
        { key: 'header_email', type: 'string', value: 'X-MY-USER-EMAIL' },
        { key: 'header_name', type: 'string', value: 'X-MY-USER-NAME' },
        { key: 'header_firstname', type: 'string', value: 'X-MY-USER-FIRSTNAME' },
        { key: 'header_lastname', type: 'string', value: 'X-MY-USER-LASTNAME' },
        { key: 'headers_audit', type: 'array', value: '["X-MY-USER-AUDIT"]' },
      ]);

      expect(defaultValuesConfiguration.groups_management).toStrictEqual({
        groups_mapping: [],
        groups_splitter: ',',
        groups_header: '',
      });
      expect(defaultValuesConfiguration.organizations_management).toStrictEqual({
        organizations_mapping: [],
        organizations_splitter: ',',
        organizations_header: '',
      });
    });
  });
  describe('Dry run of CERT migrations', () => {
    it('should CERT minimal configuration works', async () => {
      const configuration = {
        cert_minimal: {
          identifier: 'cert_minimal',
          strategy: 'ClientCertStrategy',
          config: {

          },
        },
      };

      const result = await parseSingleSignOnRunConfiguration(testContext, ADMIN_USER, configuration, true);

      const minimalCERTConfiguration = result[0];

      expect(minimalCERTConfiguration.strategy).toBe('ClientCertStrategy');
      expect(minimalCERTConfiguration.label).toBe('cert_minimal');
      expect(minimalCERTConfiguration.enabled).toBeTruthy();
      expect(minimalCERTConfiguration.configuration).toStrictEqual([

      ]);
    });

    it('should CERT with several CERT config works', async () => {
      const configuration = {
        cert_1: {
          identifier: 'cert_1',
          strategy: 'ClientCertStrategy',
          config: {

          },
        },
        cert_2: {
          identifier: 'cert_2',
          strategy: 'ClientCertStrategy',
          config: {

          },
        },
      };

      const multiOicConfigurations = await parseSingleSignOnRunConfiguration(testContext, ADMIN_USER, configuration, true);

      expect(multiOicConfigurations[0].strategy).toBe('ClientCertStrategy');
      expect(multiOicConfigurations[0].label).toBe('cert_1');
      expect(multiOicConfigurations[0].enabled).toBeTruthy();
      expect(multiOicConfigurations[0].configuration).toStrictEqual([

      ]);
      expect(multiOicConfigurations[1].strategy).toBe('ClientCertStrategy');
      expect(multiOicConfigurations[1].label).toBe('cert_2');
      expect(multiOicConfigurations[1].enabled).toBeTruthy();
      expect(multiOicConfigurations[1].configuration).toStrictEqual([

      ]);
    });
  });
  describe('Actual run of migrations', () => {
    it('should SAML configuration works', async () => {
      const configuration = {
        samltestmigration: {
          identifier: 'samltestmigration',
          strategy: 'SamlStrategy',
          config: {
            disabled: true,
            label: 'Login with SAML',
            issuer: 'openctisaml_default',
            entry_point: 'http://localhost:8888/realms/master/protocol/saml',
            saml_callback_url: 'http://localhost:3000/auth/saml/callback',
            cert: 'totallyFakeCertGroups',
            organizations_default: ['OpenCTI'],
          },
        },
      };

      const result = await parseSingleSignOnRunConfiguration(testContext, ADMIN_USER, configuration, false);
      const samlStrategy = result.find((sso) => sso.identifier === 'samltestmigration');
      expect(samlStrategy).toBeDefined();
      expect(samlStrategy?.strategy).toBe('SamlStrategy');
      expect(samlStrategy?.enabled).toBe(false);
      expect(samlStrategy?.name).toMatch(/Login with SAML*/);
      expect(samlStrategy?.configuration).toStrictEqual([
        { key: 'issuer', type: 'string', value: 'openctisaml_default' },
        { key: 'entryPoint', type: 'string', value: 'http://localhost:8888/realms/master/protocol/saml' },
        { key: 'callbackUrl', type: 'string', value: 'http://localhost:3000/auth/saml/callback' },
        { key: 'idpCert', type: 'string', value: 'totallyFakeCertGroups' },
        { key: 'organizations_default', type: 'array', value: '["OpenCTI"]' },
      ]);
      expect(samlStrategy?.enabled).toBeFalsy();
      if (samlStrategy) {
        await deleteSingleSignOn(testContext, ADMIN_USER, samlStrategy?.id);
      }
    });
  });
});
