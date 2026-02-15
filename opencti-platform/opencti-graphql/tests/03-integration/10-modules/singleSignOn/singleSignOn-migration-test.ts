import { describe, expect, it } from 'vitest';
import { parseSingleSignOnRunConfiguration } from '../../../../src/modules/singleSignOn/singleSignOn-migration';
import { ADMIN_USER, testContext } from '../../../utils/testQuery';
import { deleteSingleSignOn } from '../../../../src/modules/singleSignOn/singleSignOn-domain';
import { EnvStrategyType, MIGRATED_STRATEGY } from '../../../../src/modules/singleSignOn/providers-configuration';

describe('Migration of SSO environment test coverage', () => {
  describe('Dry run of SAML migrations', () => {
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
            decryption_pvk: '-----BEGIN PRIVATE KEY-----\\nMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM\\n/h+/h+/h+/h+/h+/h+/h+/h+/h+/h+/h+/h+/h+/h+/h+/h+/h+/h+/h+/h+/h+A\\nnMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM\\nnMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM\\nnMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM\\nnMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM\\nnMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM\\nnMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM\\nnMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM\\nnMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM\\nMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM\\nnMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM\\nGLQ9wsHH5tQkNr581fConN+uq1iWNxtEz8mOc+Xa2BSuAhl3nX++t5BWs7zeBQP9\\njjfMi8aOQuv7/7lgCAY9oX7OnjF0Zk42AW2oJMC/h/OUvU9wTsyN7lOsyvCLSHoQ\\n77lV3ZvL2Uj6mB+FsjcrT/mD3wKBgQDJiTUGC0LjAJXnw6ncnbm3uxXwENwV4Slp\\narnhMJo7pokw3tHUbbDmmKmMXxtpDsJkHioCLqcL72cuZWPqCCKC4HmH1s+hdUov\\nZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZz\\nZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZz\\nZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZz\\nZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZz\\nZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZz\\nZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZz\\nZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZz\\nZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZz\\nZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZz\\nQQQQQQQQQQQQQQQQQQQQQQQQ\\n-----END PRIVATE KEY-----',
            disable_requested_authn_context: true,
            audience: 'MyAudience',
            account_attribute: 'MyAccount',
            pi: 3.14159,
            auto_create_group: false,
            firstname_attribute: 'theFirstname',
            lastname_attribute: 'theLastName',
            mail_attribute: 'TheMail',
            private_key: 'MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM',
            signature_algorithm: 'sha256',
            want_authn_response_signed: false,
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
        { key: 'decryptionPvk', type: 'secret', value: '-----BEGIN PRIVATE KEY-----\\nMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM\\n/h+/h+/h+/h+/h+/h+/h+/h+/h+/h+/h+/h+/h+/h+/h+/h+/h+/h+/h+/h+/h+A\\nnMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM\\nnMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM\\nnMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM\\nnMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM\\nnMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM\\nnMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM\\nnMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM\\nnMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM\\nMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM\\nnMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM\\nGLQ9wsHH5tQkNr581fConN+uq1iWNxtEz8mOc+Xa2BSuAhl3nX++t5BWs7zeBQP9\\njjfMi8aOQuv7/7lgCAY9oX7OnjF0Zk42AW2oJMC/h/OUvU9wTsyN7lOsyvCLSHoQ\\n77lV3ZvL2Uj6mB+FsjcrT/mD3wKBgQDJiTUGC0LjAJXnw6ncnbm3uxXwENwV4Slp\\narnhMJo7pokw3tHUbbDmmKmMXxtpDsJkHioCLqcL72cuZWPqCCKC4HmH1s+hdUov\\nZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZz\\nZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZz\\nZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZz\\nZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZz\\nZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZz\\nZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZz\\nZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZz\\nZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZz\\nZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZzZz\\nQQQQQQQQQQQQQQQQQQQQQQQQ\\n-----END PRIVATE KEY-----' },
        { key: 'disableRequestedAuthnContext', type: 'boolean', value: 'true' },
        { key: 'audience', type: 'string', value: 'MyAudience' },
        { key: 'account_attribute', type: 'string', value: 'MyAccount' },
        { key: 'pi', type: 'number', value: '3.14159' }, // couldn't find a saml float attribute but better to know if it works in theory
        { key: 'auto_create_group', type: 'boolean', value: 'false' },
        { key: 'firstname_attribute', type: 'string', value: 'theFirstname' },
        { key: 'lastname_attribute', type: 'string', value: 'theLastName' },
        { key: 'mail_attribute', type: 'string', value: 'TheMail' },
        { key: 'privateKey', type: 'secret', value: 'MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM' },
        { key: 'signatureAlgorithm', type: 'string', value: 'sha256' },
        { key: 'wantAuthnResponseSigned', type: 'boolean', value: 'false' },
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

    it('should SAML with organization mapping in configuration works', async () => {
      const configuration = {
        saml_org: {
          identifier: 'saml_org',
          strategy: 'SamlStrategy',
          config: {
            label: 'My test SAML with Orgs',
            issuer: 'openctisaml_orgs',
            entry_point: 'http://localhost:8888/realms/master/protocol/saml',
            saml_callback_url: 'http://localhost:3000/auth/saml_org/callback',
            cert: 'totallyFakeCertGroups',
            organizations_management: {
              organizations_path: ['theOrg'],
              organizations_mapping: ['orgA:OCTIA', 'orgB:OCTIB'],
            },
          },
        },
      };

      const result = await parseSingleSignOnRunConfiguration(testContext, ADMIN_USER, configuration, true);

      const orgMappingSAMLConfiguration = result[0];
      expect(orgMappingSAMLConfiguration.strategy).toBe('SamlStrategy');
      expect(orgMappingSAMLConfiguration.name).toMatch(/My test SAML with Orgs-*/);
      expect(orgMappingSAMLConfiguration.label).toBe('My test SAML with Orgs');
      expect(orgMappingSAMLConfiguration.enabled).toBeTruthy();
      expect(orgMappingSAMLConfiguration.configuration).toStrictEqual([
        { key: 'issuer', type: 'string', value: 'openctisaml_orgs' },
        { key: 'entryPoint', type: 'string', value: 'http://localhost:8888/realms/master/protocol/saml' },
        { key: 'callbackUrl', type: 'string', value: 'http://localhost:3000/auth/saml_org/callback' },
        { key: 'idpCert', type: 'string', value: 'totallyFakeCertGroups' },
      ]);

      expect(orgMappingSAMLConfiguration.organizations_management).toStrictEqual({
        organizations_path: ['theOrg'],
        organizations_mapping: ['orgA:OCTIA', 'orgB:OCTIB'],
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
        { key: 'client_secret', type: 'secret', value: 'youShallNotPass' },
        { key: 'redirect_uri', type: 'string', value: 'http://localhost:4000/auth/oic/callback' },
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
            default_scopes: ['myopenid', 'myemail', 'myprofile'],
            logout_remote: false,
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
        { key: 'client_secret', type: 'secret', value: 'youShallNotPass' },
        { key: 'redirect_uri', type: 'string', value: 'http://localhost:4000/auth/oic/callback' },
        { key: 'entry_point', type: 'string', value: 'http://localhost:7777/realms/master/protocol/oic' },
        { key: 'default_scopes', type: 'array', value: '["myopenid","myemail","myprofile"]' },
        { key: 'logout_remote', type: 'boolean', value: 'false' },
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
        { key: 'client_secret', type: 'secret', value: 'youShallNotPass' },
        { key: 'redirect_uri', type: 'string', value: 'http://localhost:4000/auth/oic/callback' },
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

    it('should OpenId with organization mapping in configuration works', async () => {
      if (!MIGRATED_STRATEGY.some((strat) => strat === EnvStrategyType.STRATEGY_OPENID)) {
        return;
      }
      const configuration = {
        oic_orgs: {
          identifier: 'oic_orgs',
          strategy: 'OpenIDConnectStrategy',
          config: {
            issuer: 'http://localhost:9999/realms/master',
            client_id: 'oic_orgs',
            client_secret: 'youShallNotPass',
            redirect_uris: ['http://localhost:4000/auth/oic_orgs/callback'],
            logout_remote: true,
            prevent_default_groups: false,
            organizations_management: {
              organizations_path: [
                'orgs',
              ],
              organizations_mapping: [
                '/Filigran org:Filigran',
              ],
              read_userinfo: false,
              token_reference: 'access_token2',
            },
          },
        },
      };

      const result = await parseSingleSignOnRunConfiguration(testContext, ADMIN_USER, configuration, true);
      const orgsOpenIdConfiguration = result[0];
      expect(orgsOpenIdConfiguration.strategy).toBe('OpenIDConnectStrategy');
      expect(orgsOpenIdConfiguration.label).toBe('oic_orgs');
      expect(orgsOpenIdConfiguration.enabled).toBeTruthy();
      expect(orgsOpenIdConfiguration.configuration).toStrictEqual([
        { key: 'issuer', type: 'string', value: 'http://localhost:9999/realms/master' },
        { key: 'client_id', type: 'string', value: 'oic_orgs' },
        { key: 'client_secret', type: 'secret', value: 'youShallNotPass' },
        { key: 'redirect_uri', type: 'string', value: 'http://localhost:4000/auth/oic_orgs/callback' },
        { key: 'logout_remote', type: 'boolean', value: 'true' },
        { key: 'prevent_default_groups', type: 'boolean', value: 'false' },
      ]);

      expect(orgsOpenIdConfiguration.organizations_management).toStrictEqual({
        organizations_mapping: ['/Filigran org:Filigran'],
        organizations_path: ['orgs'],
        read_userinfo: false,
        token_reference: 'access_token2',
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
        { key: 'client_secret', type: 'secret', value: 'youShallNotPass' },
        { key: 'redirect_uri', type: 'string', value: 'http://localhost:4000/auth/oic/callback' },
      ]);
      expect(multiOicConfigurations[1].strategy).toBe('OpenIDConnectStrategy');
      expect(multiOicConfigurations[1].label).toBe('oic_2');
      expect(multiOicConfigurations[1].enabled).toBeTruthy();
      expect(multiOicConfigurations[1].configuration).toStrictEqual([
        { key: 'issuer', type: 'string', value: 'http://localhost:9999/realms/master' },
        { key: 'client_id', type: 'string', value: 'openctioid' },
        { key: 'client_secret', type: 'secret', value: 'youShallNotPass' },
        { key: 'redirect_uri', type: 'string', value: 'http://localhost:4000/auth/oic/callback' },
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
        { key: 'client_secret', type: 'secret', value: 'youShallNotPass' },
        { key: 'redirect_uri', type: 'string', value: 'http://localhost:4000/auth/oic/callback' },
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

    it('should OpenId with cyberark as credentials provider works', async () => {
      const configuration = {
        oic_cyberark: {
          identifier: 'oic_cyberark',
          strategy: 'OpenIDConnectStrategy',
          credentials_provider: {
            selector: 'cyberark',
            cyberark: {
              uri: 'http://localhost:8090/AIMWebService/api/Accounts',
              field_targets: ['client_secret'],
              app_id: 'cyberark',
              safe: 'safe',
              object: 'secret',
            },
            https_cert: {
              reject_unauthorized: false,
              ca: '/opt/local/opencti/myca.pem',
              crt: '/opt/local/opencti/mycert.pem',
              key: '/opt/local/opencti/mykey.pk',
            },
          },
          config: {
            label: 'My OpenId with CyberArk',
            issuer: 'http://localhost:9999/realms/master',
            client_id: 'openctioid',
            redirect_uris: ['http://localhost:4000/auth/oic/callback'],
          },
        },
      };

      const result = await parseSingleSignOnRunConfiguration(testContext, ADMIN_USER, configuration, true);
      const cyberArkConfig = result[0];

      expect(cyberArkConfig.strategy).toBe('OpenIDConnectStrategy');
      expect(cyberArkConfig.label).toBe('My OpenId with CyberArk');
      expect(cyberArkConfig.enabled).toBeTruthy();
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
        { key: 'bindCredentials', type: 'secret', value: 'credentials' },
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
        { key: 'bindCredentials', type: 'secret', value: 'credentials' },
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
        { key: 'bindCredentials', type: 'secret', value: 'credentials' },
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
        { key: 'bindCredentials', type: 'secret', value: 'credentials' },
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
        { key: 'bindCredentials', type: 'secret', value: 'credentials' },
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
