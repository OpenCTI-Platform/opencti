import { describe, it, vi, expect, beforeAll, afterAll, beforeEach, afterEach } from 'vitest';
import { initializeAuthenticationProviders } from '../../../../src/modules/authenticationProvider/providers';
import { ADMIN_USER, testContext, USER_EDITOR } from '../../../utils/testQuery';
import type { BasicStoreSettings } from '../../../../src/types/settings';
import * as mockProviderEnv from '../../../../src/modules/authenticationProvider/providers-configuration';
import { getSettings, getSettingsFromDatabase } from '../../../../src/domain/settings';
import { buildAvailableProviders, updateCertAuth, updateHeaderAuth, updateLocalAuth } from '../../../../src/domain/setting-auth';
import { type ProviderConfiguration, PROVIDERS } from '../../../../src/modules/authenticationProvider/providers-configuration';
import type { CertAuthConfigInput, HeadersAuthConfigInput, LocalAuthConfigInput, UserLoginInput } from '../../../../src/generated/graphql';
import { findAllAuthenticationProvider } from '../../../../src/modules/authenticationProvider/authenticationProvider-domain';
import { SYSTEM_USER } from '../../../../src/utils/access';
import { elDeleteElements, elIndexElements } from '../../../../src/database/engine';
import { patchAttribute } from '../../../../src/database/middleware';
import { ENTITY_TYPE_SETTINGS } from '../../../../src/schema/internalObject';
import type { BasicStoreEntityAuthenticationProvider } from '../../../../src/modules/authenticationProvider/authenticationProvider-types';
import { sessionLogin } from '../../../../src/domain/user';
import type { AuthContext } from '../../../../src/types/user';
import type Express from 'express';

const clearDbProvider = async () => {
  const authenticators = await findAllAuthenticationProvider(testContext, SYSTEM_USER);
  await elDeleteElements(testContext, SYSTEM_USER, authenticators, { forceDelete: true, forceRefresh: true });
};
const clearEnvProviderArray = () => {
  const len = PROVIDERS.length;
  for (let i = 0; i < len; i++) {
    PROVIDERS.pop();
  }
};

const setLocalAuthToEnabled = async (enabled: boolean) => {
  const settings = await getSettingsFromDatabase(testContext) as unknown as BasicStoreSettings;
  const localUpdateInput: LocalAuthConfigInput = {
    enabled,
    password_policy_max_length: 0,
    password_policy_min_length: 0,
    password_policy_min_lowercase: 0,
    password_policy_min_numbers: 0,
    password_policy_min_symbols: 0,
    password_policy_min_uppercase: 0,
    password_policy_min_words: 0,
  };
  const result = await updateLocalAuth(testContext, ADMIN_USER, settings.id, localUpdateInput);
  expect(result.local_auth.enabled).toBe(enabled);
};

describe('Provider coverage', () => {
  const PROVIDER_SAVE: ProviderConfiguration[] = [];
  let savedDbProviders: BasicStoreEntityAuthenticationProvider[] = [];
  let savedSettings: BasicStoreSettings;

  beforeAll(async () => {
    // Snapshot in-memory PROVIDERS
    const len = PROVIDERS.length;
    for (let i = 0; i < len; i++) {
      PROVIDER_SAVE.push(PROVIDERS[i]);
    }
    // Snapshot DB authentication provider entities
    savedDbProviders = await findAllAuthenticationProvider(testContext, SYSTEM_USER);
    // Snapshot settings auth/password fields
    savedSettings = await getSettingsFromDatabase(testContext) as unknown as BasicStoreSettings;
  });

  afterAll(async () => {
    // Restore in-memory PROVIDERS
    clearEnvProviderArray();
    const len = PROVIDER_SAVE.length;
    for (let i = 0; i < len; i++) {
      PROVIDERS.push(PROVIDER_SAVE[i]);
    }

    // Restore settings auth/password fields
    const settingsPatch: Record<string, any> = {
      local_auth: savedSettings.local_auth,
      cert_auth: savedSettings.cert_auth,
      headers_auth: savedSettings.headers_auth,
      password_policy_min_length: (savedSettings as any).password_policy_min_length,
      password_policy_max_length: (savedSettings as any).password_policy_max_length,
      password_policy_min_symbols: (savedSettings as any).password_policy_min_symbols,
      password_policy_min_numbers: (savedSettings as any).password_policy_min_numbers,
      password_policy_min_words: (savedSettings as any).password_policy_min_words,
      password_policy_min_lowercase: (savedSettings as any).password_policy_min_lowercase,
      password_policy_min_uppercase: (savedSettings as any).password_policy_min_uppercase,
    };
    await patchAttribute(testContext, ADMIN_USER, savedSettings.id, ENTITY_TYPE_SETTINGS, settingsPatch);

    // Restore DB authentication provider entities:
    // delete whatever providers exist now, then re-index the originals
    const currentProviders = await findAllAuthenticationProvider(testContext, SYSTEM_USER);
    if (currentProviders.length > 0) {
      await elDeleteElements(testContext, SYSTEM_USER, currentProviders, { forceDelete: true, forceRefresh: true });
    }
    if (savedDbProviders.length > 0) {
      await elIndexElements(testContext, SYSTEM_USER, undefined, savedDbProviders);
    }
  });

  describe('initializeAuthenticationProviders coverage', () => {
    beforeEach(() => {
      vi.clearAllMocks();
    });

    afterEach(() => {
      vi.restoreAllMocks();
    });

    it('should force env & local disabled along with a strategy be correct', async () => {
    // GIVEN a force env, and a configuration with a local disabled and an SAML configured
      clearEnvProviderArray();

      vi.spyOn(mockProviderEnv, 'isAuthenticationForcedFromEnv').mockReturnValue(true);
      vi.spyOn(mockProviderEnv, 'getProvidersFromEnvironment').mockReturnValue({
        local: {
          strategy: 'LocalStrategy',
          config: {
            disabled: true,
          },
        }, saml_p_test: {
          identifier: 'saml_p_test',
          strategy: 'SamlStrategy',
          config: {
            issuer: 'saml_p_test',
            label: 'saml_p_test',
            entry_point: 'http://localhost:9999/realms/master/protocol/saml_p_test',
            saml_callback_url: 'http://localhost:4000/auth/saml_p_test/callback',
            cert: 'xxxxxxxxxxxxxxxxxxxxxxxx',
            logout_remote: false,
          },
        },
      });

      // WHEN initializing providers
      await initializeAuthenticationProviders(testContext);

      const finalSettings = await getSettings(testContext) as unknown as BasicStoreSettings;
      const settingsProviders = await buildAvailableProviders(finalSettings);

      // THEN
      // Should have only the SAML, and no local since local is disabled in env
      expect(settingsProviders).toStrictEqual([
        {
          logout_remote: false,
          name: 'saml_p_test',
          provider: 'saml_p_test',
          strategy: 'SamlStrategy',
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
      // Should have only the local since there is no other strategy
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

    it('should no force env and with no strategy still register local', async () => {
      // GIVEN an empty configuration in DB
      await clearDbProvider();
      vi.spyOn(mockProviderEnv, 'isAuthenticationForcedFromEnv').mockReturnValue(false);

      // WHEN initializing providers
      await initializeAuthenticationProviders(testContext);

      // THEN
      // Should have only the local
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
      expect(result.password_policy_min_length).toBe(2);
      expect(result.password_policy_min_lowercase).toBe(3);
      expect(result.password_policy_min_numbers).toBe(4);
      expect(result.password_policy_min_symbols).toBe(5);
      expect(result.password_policy_min_uppercase).toBe(6);
      expect(result.password_policy_min_words).toBe(7);
    });

    it('should update cert work', async () => {
      const settings = await getSettingsFromDatabase(testContext) as unknown as BasicStoreSettings;
      const localUpdateInput: CertAuthConfigInput = {
        button_label_override: 'MyCert',
        description: 'Cert auth for tests',
        groups_mapping: {
          auto_create_groups: false,
          default_groups: ['TestGroup'],
          groups_expr: ['test.group'],
          groups_mapping: [{ provider: 'Admin', platform: 'Administrator' }],
          prevent_default_groups: false,
        },
        organizations_mapping: {
          auto_create_organizations: false,
          default_organizations: [],
          organizations_expr: ['test.org'],
          organizations_mapping: [{ provider: 'Filigran', platform: 'Filigran' }],
        },
        user_info_mapping: {
          email_expr: 'user.email',
          name_expr: 'user.name',
        },
        enabled: false,
      };
      const result = await updateCertAuth(testContext, ADMIN_USER, settings.id, localUpdateInput);

      expect(result.cert_auth).toStrictEqual({
        button_label_override: 'MyCert',
        description: 'Cert auth for tests',
        enabled: false,
        groups_mapping: {
          auto_create_groups: false,
          default_groups: [
            'TestGroup',
          ],
          groups_expr: [
            'test.group',
          ],
          groups_mapping: [
            {
              platform: 'Administrator',
              provider: 'Admin',
            },
          ],
          prevent_default_groups: false,
        },
        organizations_mapping: {
          auto_create_organizations: false,
          default_organizations: [],
          organizations_expr: [
            'test.org',
          ],
          organizations_mapping: [
            {
              platform: 'Filigran',
              provider: 'Filigran',
            },
          ],
        },
        user_info_mapping: {
          email_expr: 'user.email',
          name_expr: 'user.name',
        },
      });
    });

    it('should update header work', async () => {
      const settings = await getSettingsFromDatabase(testContext) as unknown as BasicStoreSettings;
      const localUpdateInput: HeadersAuthConfigInput = {
        button_label_override: 'MyHeader',
        description: 'Header auth for tests',
        groups_mapping: {
          auto_create_groups: false,
          default_groups: ['HeaderTestGroup'],
          groups_expr: ['header.group'],
          groups_mapping: [{ provider: 'Admin', platform: 'Administrator' }],
          prevent_default_groups: false,
        },
        organizations_mapping: {
          auto_create_organizations: false,
          default_organizations: [],
          organizations_expr: ['header.org'],
          organizations_mapping: [{ provider: 'Filigran', platform: 'Filigran' }],
        },
        user_info_mapping: {
          email_expr: 'header.email',
          name_expr: 'header.name',
        },
        enabled: false,
      };
      const result = await updateHeaderAuth(testContext, ADMIN_USER, settings.id, localUpdateInput);

      expect(result.headers_auth).toStrictEqual({
        button_label_override: 'MyHeader',
        description: 'Header auth for tests',
        enabled: false,
        groups_mapping: {
          auto_create_groups: false,
          default_groups: [
            'HeaderTestGroup',
          ],
          groups_expr: [
            'header.group',
          ],
          groups_mapping: [
            {
              platform: 'Administrator',
              provider: 'Admin',
            },
          ],
          prevent_default_groups: false,
        },
        organizations_mapping: {
          auto_create_organizations: false,
          default_organizations: [],
          organizations_expr: [
            'header.org',
          ],
          organizations_mapping: [
            {
              platform: 'Filigran',
              provider: 'Filigran',
            },
          ],
        },
        user_info_mapping: {
          email_expr: 'header.email',
          name_expr: 'header.name',
        },
      });
    });
  });

  // Even if it's on user domain we put the test here to benefit from providers & settings reset.
  describe('sessionLogin test coverage', () => {
    beforeEach(() => {
      vi.clearAllMocks();
    });

    afterEach(() => {
      vi.restoreAllMocks();
    });

    const getMockAuthContextWithRequest = () => {
      const request: Partial<Express.Request> = {
        headers: { 'x-forwarded-for': '127.0.0.1' },
        header: (_: string) => undefined,
        session: {
          // eslint-disable-next-line @typescript-eslint/ban-ts-comment
          // @ts-ignore see user#sessionAuthenticateUser there is a session.save() there
          save: () => {},
        },
      };

      const reqContext: AuthContext = {
        otp_mandatory: false,
        req: request as Express.Request,
        source: '',
        tracing: undefined,
        user: undefined,
        user_inside_platform_organization: false,
      };
      return reqContext;
    };

    it('should admin from configuration work with force_env + local disabled', async () => {
      const reqContext: AuthContext = getMockAuthContextWithRequest();

      // GIVEN using force env + local disabled
      await setLocalAuthToEnabled(false);
      vi.spyOn(mockProviderEnv, 'isAuthenticationForcedFromEnv').mockReturnValue(true);
      vi.spyOn(mockProviderEnv, 'getProvidersFromEnvironment').mockReturnValue({
        local: {
          strategy: 'LocalStrategy',
          config: {
            disabled: true,
          },
        },
      });

      // THEN admin from config should still work
      const userInput: UserLoginInput = { email: 'admin@opencti.io', password: 'admin' }; // from test.json
      await sessionLogin(reqContext, userInput);

      // THEN any other user should not
      const userInputEditor: UserLoginInput = { email: USER_EDITOR.email, password: USER_EDITOR.password }; // from testQueryHelper
      await expect(async () => {
        await sessionLogin(reqContext, userInputEditor);
      }).rejects.toThrowError('Bad login or password');
    });

    it('should all local users work with force_env + local enabled', async () => {
      const reqContext: AuthContext = getMockAuthContextWithRequest();

      // GIVEN using force env + local enabled
      await setLocalAuthToEnabled(true);
      vi.spyOn(mockProviderEnv, 'isAuthenticationForcedFromEnv').mockReturnValue(true);
      vi.spyOn(mockProviderEnv, 'getProvidersFromEnvironment').mockReturnValue({
        local: {
          strategy: 'LocalStrategy',
          config: {
            disabled: false,
          },
        },
      });

      // THEN admin from config should still work
      const userInput: UserLoginInput = { email: 'admin@opencti.io', password: 'admin' }; // from test.json
      await sessionLogin(reqContext, userInput);

      // THEN any other user should also
      const userInputEditor: UserLoginInput = { email: USER_EDITOR.email, password: USER_EDITOR.password }; // from testQueryHelper
      await sessionLogin(reqContext, userInputEditor);
    });

    it('should admin from configuration work with database auth + local disabled', async () => {
      const reqContext: AuthContext = getMockAuthContextWithRequest();

      // GIVEN local disabled in database
      await setLocalAuthToEnabled(false);
      vi.spyOn(mockProviderEnv, 'isAuthenticationForcedFromEnv').mockReturnValue(false);

      // THEN admin from config should still work
      const userInput: UserLoginInput = { email: 'admin@opencti.io', password: 'admin' }; // from test.json
      await sessionLogin(reqContext, userInput);

      // THEN any other user should not
      const userInputEditor: UserLoginInput = { email: USER_EDITOR.email, password: USER_EDITOR.password }; // from testQueryHelper
      await expect(async () => {
        await sessionLogin(reqContext, userInputEditor);
      }).rejects.toThrowError('Bad login or password');
    });

    it('should all local users work database auth + local enabled', async () => {
      const reqContext: AuthContext = getMockAuthContextWithRequest();

      // GIVEN local enabled in database
      await setLocalAuthToEnabled(true);
      vi.spyOn(mockProviderEnv, 'isAuthenticationForcedFromEnv').mockReturnValue(false);

      // THEN admin from config should still work
      const userInput: UserLoginInput = { email: 'admin@opencti.io', password: 'admin' }; // from test.json
      await sessionLogin(reqContext, userInput);

      // THEN any other user should also
      const userInputEditor: UserLoginInput = { email: USER_EDITOR.email, password: USER_EDITOR.password }; // from testQueryHelper
      await sessionLogin(reqContext, userInputEditor);
    });

    it('should all local users work database auth + local disabled + local forced in env', async () => {
      const reqContext: AuthContext = getMockAuthContextWithRequest();

      // GIVEN local disabled in database, but local force from env
      await setLocalAuthToEnabled(false);
      vi.spyOn(mockProviderEnv, 'isAuthenticationForcedFromEnv').mockReturnValue(false);
      vi.spyOn(mockProviderEnv, 'isLocalAuthForcedEnabledFromEnv').mockReturnValue(true);

      // THEN admin from config should still work
      const userInput: UserLoginInput = { email: 'admin@opencti.io', password: 'admin' }; // from test.json
      await sessionLogin(reqContext, userInput);

      // THEN any other user should also
      const userInputEditor: UserLoginInput = { email: USER_EDITOR.email, password: USER_EDITOR.password }; // from testQueryHelper
      await sessionLogin(reqContext, userInputEditor);
    });

    it('should all local users work with force_env + local disabled + force local in env', async () => {
      const reqContext: AuthContext = getMockAuthContextWithRequest();

      // GIVEN local disabled in env, but local force from env also
      await setLocalAuthToEnabled(false);
      vi.spyOn(mockProviderEnv, 'isLocalAuthForcedEnabledFromEnv').mockReturnValue(true);
      vi.spyOn(mockProviderEnv, 'isAuthenticationForcedFromEnv').mockReturnValue(true);
      vi.spyOn(mockProviderEnv, 'getProvidersFromEnvironment').mockReturnValue({
        local: {
          strategy: 'LocalStrategy',
          config: {
            disabled: true,
          },
        },
      });

      // THEN admin from config should still work
      const userInput: UserLoginInput = { email: 'admin@opencti.io', password: 'admin' }; // from test.json
      await sessionLogin(reqContext, userInput);

      // THEN any other user should also
      const userInputEditor: UserLoginInput = { email: USER_EDITOR.email, password: USER_EDITOR.password }; // from testQueryHelper
      await sessionLogin(reqContext, userInputEditor);
    });
  });
});
