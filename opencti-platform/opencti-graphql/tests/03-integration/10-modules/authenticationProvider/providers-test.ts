import { describe, it, vi, expect, beforeAll, afterAll } from 'vitest';
import { initializeAuthenticationProviders } from '../../../../src/modules/authenticationProvider/providers';
import { ADMIN_USER, testContext } from '../../../utils/testQuery';
import type { BasicStoreSettings } from '../../../../src/types/settings';
import * as mockProviderEnv from '../../../../src/modules/authenticationProvider/providers-configuration';
import { getSettings, getSettingsFromDatabase } from '../../../../src/domain/settings';
import { buildAvailableProviders, updateLocalAuth } from '../../../../src/domain/setting-auth';
import { type ProviderConfiguration, PROVIDERS } from '../../../../src/modules/authenticationProvider/providers-configuration';
import type { LocalAuthConfigInput } from '../../../../src/generated/graphql';

const clearEnvProviderArray = () => {
  const len = PROVIDERS.length;
  for (let i = 0; i < len; i++) {
    PROVIDERS.pop();
  }
};

describe('Provider coverage', () => {
  const PROVIDER_SAVE: ProviderConfiguration[] = [];
  beforeAll(async () => {
    const len = PROVIDERS.length;
    for (let i = 0; i < len; i++) {
      PROVIDER_SAVE.push(PROVIDERS[i]);
    }
  });

  afterAll(async () => {
    clearEnvProviderArray();
    const len = PROVIDER_SAVE.length;
    for (let i = 0; i < len; i++) {
      PROVIDERS.push(PROVIDER_SAVE[i]);
    }
  });

  describe('initializeAuthenticationProviders coverage', () => {
    it('should force env & local disabled along with a strategy be correct', async () => {
    // GIVEN a force env, and a configuration with a local disabled and an OpenID configured
      clearEnvProviderArray();

      vi.spyOn(mockProviderEnv, 'isAuthenticationForcedFromEnv').mockReturnValue(true);
      vi.spyOn(mockProviderEnv, 'getProvidersFromEnvironment').mockReturnValue({
        local: {
          strategy: 'LocalStrategy',
          config: {
            disabled: true,
          },
        }, oick: {
          identifier: 'oick',
          strategy: 'OpenIDConnectStrategy',
          enabled: true,
          config: {
            issuer: 'http://localhost:9999/realms/master',
            client_id: 'openctioid',
            client_secret: 'xxxxxxxxxxxxx',
            redirect_uris: ['http://localhost:4000/auth/oick/callback'],
          },
        },
      });

      // WHEN initializing providers
      await initializeAuthenticationProviders(testContext);

      const finalSettings = await getSettings(testContext) as unknown as BasicStoreSettings;
      const settingsProviders = await buildAvailableProviders(finalSettings);

      // THEN
      // Should have only the OpenID, and no local since local is disabled in env
      expect(settingsProviders).toStrictEqual([
        {
          logout_remote: undefined,
          name: 'oick',
          provider: 'oick',
          strategy: 'OpenIDConnectStrategy',
          type: 'SSO',
        },
      ]);
    });

    it('should force env & local disabled with no strategy still register local', async () => {
    // GIVEN a force env, and a configuration with only a local disabled
      clearEnvProviderArray();
      vi.spyOn(mockProviderEnv, 'isAuthenticationForcedFromEnv').mockReturnValue(true);
      vi.spyOn(mockProviderEnv, 'getProvidersFromEnvironment').mockReturnValue({
        local: {
          strategy: 'LocalStrategy',
          config: {
            disabled: true,
          },
        },
      });

      // WHEN initializing providers
      await initializeAuthenticationProviders(testContext);

      // THEN
      // Should have only the OpenID, and no local since local is disabled in env
      const finalSettings = await getSettings(testContext) as unknown as BasicStoreSettings;
      const settingsProviders = await buildAvailableProviders(finalSettings);

      expect(settingsProviders).toStrictEqual([
        {
          name: 'local',
          provider: 'local',
          strategy: 'LocalStrategy',
          type: 'FORM',
        },
      ]);
    });
  });

  describe('setting-auth file test coverage', () => {
    it('should local auth enabled only work fine', async () => {
      const settingsMock: Partial<BasicStoreSettings> = {
        local_auth: {
          enabled: true,
          button_label_override: 'testLocal',
        },
        cert_auth: {
          enabled: false,
          description: '',
          button_label_override: '',
          user_info_mapping: {
            email_expr: '',
            name_expr: '',
          },
          groups_mapping: {
            default_groups: [],
            groups_expr: [],
            groups_mapping: [],
            auto_create_groups: false,
            prevent_default_groups: false,
          },
          organizations_mapping: {
            default_organizations: [],
            organizations_expr: [],
            organizations_mapping: [],
            auto_create_organizations: false,
          },
        },
        headers_auth: {
          enabled: false,
          description: '',
          button_label_override: '',
          user_info_mapping: {
            email_expr: '',
            name_expr: '',
          },
          groups_mapping: {
            default_groups: [],
            groups_expr: [],
            groups_mapping: [],
            auto_create_groups: false,
            prevent_default_groups: false,
          },
          organizations_mapping: {
            default_organizations: [],
            organizations_expr: [],
            organizations_mapping: [],
            auto_create_organizations: false,
          },
          headers_audit: [],
        },
      };
      const availableProviders = await buildAvailableProviders(settingsMock as BasicStoreSettings);
      expect(availableProviders).toStrictEqual([{
        name: 'testLocal',
        provider: 'local',
        strategy: 'LocalStrategy',
        type: 'FORM',
      }]);
    });

    it('should cert auth enabled only work fine', async () => {
      const settingsMock: Partial<BasicStoreSettings> = {
        local_auth: {
          enabled: false,
          button_label_override: 'testLocal',
        },
        cert_auth: {
          enabled: true,
          description: 'My cert auth for tests',
          button_label_override: 'myCert',
          user_info_mapping: {
            email_expr: 'mèl',
            name_expr: 'nom',
          },
          groups_mapping: {
            default_groups: [],
            groups_expr: [],
            groups_mapping: [],
            auto_create_groups: false,
            prevent_default_groups: false,
          },
          organizations_mapping: {
            default_organizations: [],
            organizations_expr: [],
            organizations_mapping: [],
            auto_create_organizations: false,
          },
        },
        headers_auth: {
          enabled: false,
          description: '',
          button_label_override: '',
          user_info_mapping: {
            email_expr: '',
            name_expr: '',
          },
          groups_mapping: {
            default_groups: [],
            groups_expr: [],
            groups_mapping: [],
            auto_create_groups: false,
            prevent_default_groups: false,
          },
          organizations_mapping: {
            default_organizations: [],
            organizations_expr: [],
            organizations_mapping: [],
            auto_create_organizations: false,
          },
          headers_audit: [],
        },
      };
      const availableProviders = await buildAvailableProviders(settingsMock as BasicStoreSettings);
      expect(availableProviders).toStrictEqual([{
        name: 'myCert',
        provider: 'cert',
        strategy: 'ClientCertStrategy',
        type: 'SSO',
      }]);
    });

    it('should header auth enabled only work fine', async () => {
      const settingsMock: Partial<BasicStoreSettings> = {
        local_auth: {
          enabled: false,
          button_label_override: 'testLocal',
        },
        cert_auth: {
          enabled: false,
          description: 'My cert auth for tests',
          button_label_override: 'myCert',
          user_info_mapping: {
            email_expr: 'mèl',
            name_expr: 'nom',
          },
          groups_mapping: {
            default_groups: [],
            groups_expr: [],
            groups_mapping: [],
            auto_create_groups: false,
            prevent_default_groups: false,
          },
          organizations_mapping: {
            default_organizations: [],
            organizations_expr: [],
            organizations_mapping: [],
            auto_create_organizations: false,
          },
        },
        headers_auth: {
          enabled: true,
          description: 'My header auth',
          button_label_override: 'Header',
          user_info_mapping: {
            email_expr: 'mail',
            name_expr: 'name',
          },
          groups_mapping: {
            default_groups: [],
            groups_expr: [],
            groups_mapping: [],
            auto_create_groups: false,
            prevent_default_groups: false,
          },
          organizations_mapping: {
            default_organizations: [],
            organizations_expr: [],
            organizations_mapping: [],
            auto_create_organizations: false,
          },
          headers_audit: [],
        },
      };
      const availableProviders = await buildAvailableProviders(settingsMock as BasicStoreSettings);
      expect(availableProviders).toStrictEqual([{
        name: 'Header',
        provider: 'headers',
        strategy: 'HeaderStrategy',
        type: 'SSO',
      }]);
    });

    it('should update password policy work', async () => {
      const settings = await getSettingsFromDatabase(testContext) as unknown as BasicStoreSettings;
      const localUpdateInput: LocalAuthConfigInput = {
        enabled: true,
        password_policy_max_length: 1,
        password_policy_min_length: 2,
        password_policy_min_lowercase: 3,
        password_policy_min_numbers: 4,
        password_policy_min_symbols: 5,
        password_policy_min_uppercase: 6,
        password_policy_min_words: 7,
      };
      const result = await updateLocalAuth(testContext, ADMIN_USER, settings.id, localUpdateInput);

      expect(result.local_auth.enabled).toBeTruthy();
      expect(result.password_policy_max_length).toBe(1);
    });
  });
});
