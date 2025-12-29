import { describe, expect, it } from 'vitest';
import { parseSingleSignOnRunConfiguration } from '../../../src/modules/singleSignOn/singleSignOn-migration';
import { ADMIN_USER, testContext } from '../../utils/testQuery';
import { deleteSingleSignOn, findSingleSignOnById } from '../../../src/modules/singleSignOn/singleSignOn-domain';

describe('Migration of SSO environment test coverage', () => {
  describe('Dry run of migrations', () => {
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

    it('should SAML configuration works', async () => {
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
        saml_groups: {
          identifier: 'saml_groups',
          strategy: 'SamlStrategy',
          config: {
            label: 'My test SAML',
            issuer: 'openctisaml',
            entry_point: 'http://localhost:9999/realms/master/protocol/saml',
            saml_callback_url: 'http://localhost:4000/auth/saml/callback',
            cert: 'totallyFakeCert',
            logout_remote: true,
            want_assertions_signed: false,
            want_authn_response_signed: false,
            audience: false,
            auto_create_group: true,
            prevent_default_groups: false,
            groups_management: {
              groups_attributes: ['samlgroup'],
              groups_path: ['groups'],
              groups_mapping: ['group1:Administrators'],
            },
          },
        },
      };

      const result = await parseSingleSignOnRunConfiguration(testContext, ADMIN_USER, configuration, true);

      const minimalSamlConfiguration = result[0];
      const groupManagementSAMLConfiguration = result[1];

      expect(minimalSamlConfiguration.strategy).toBe('SamlStrategy');
      expect(minimalSamlConfiguration.name).toMatch(/saml_minimal-*/);
      expect(minimalSamlConfiguration.enabled).toBeTruthy();
      expect(minimalSamlConfiguration.configuration).toStrictEqual([
        { key: 'issuer', type: 'string', value: 'openctisaml' },
        { key: 'entry_point', type: 'string', value: 'http://localhost:9999/realms/master/protocol/saml' },
        { key: 'saml_callback_url', type: 'string', value: 'http://localhost:4000/auth/saml/callback' },
        { key: 'cert', type: 'string', value: 'totallyFakeCert' },
      ]);

      expect(groupManagementSAMLConfiguration.strategy).toBe('SamlStrategy');
      expect(groupManagementSAMLConfiguration.name).toMatch(/My test SAML-*/);
      expect(groupManagementSAMLConfiguration.enabled).toBeTruthy();
      /*
      expect(minimalSamlConfiguration.groups_management).toStrictEqual([
        { key: 'issuer', type: 'string', value: 'openctisaml' },
        { key: 'entry_point', type: 'string', value: 'http://localhost:9999/realms/master/protocol/saml' },
        { key: 'saml_callback_url', type: 'string', value: 'http://localhost:4000/auth/saml/callback' },
        { key: 'cert', type: 'string', value: 'totallyFakeCert' },
      ]);
      expect(minimalSamlConfiguration.configuration).toStrictEqual([
        { key: 'issuer', type: 'string', value: 'openctisaml' },
        { key: 'entry_point', type: 'string', value: 'http://localhost:9999/realms/master/protocol/saml' },
        { key: 'saml_callback_url', type: 'string', value: 'http://localhost:4000/auth/saml/callback' },
        { key: 'cert', type: 'string', value: 'totallyFakeCert' },
      ]);

      expect(result.length).toBe(2);
      */
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
