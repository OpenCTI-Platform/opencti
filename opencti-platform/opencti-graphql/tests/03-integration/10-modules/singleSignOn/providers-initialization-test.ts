import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { ADMIN_USER, testContext } from '../../../utils/testQuery';
import { initializeEnvAuthenticationProviders } from '../../../../src/modules/singleSignOn/providers-initialization';
import * as providerConfig from '../../../../src/modules/singleSignOn/providers-configuration';
import * as providerInit from '../../../../src/modules/singleSignOn/providers-initialization';
import { type ProviderConfiguration, PROVIDERS } from '../../../../src/modules/singleSignOn/providers-configuration';
import conf, { booleanConf, logApp } from '../../../../src/config/conf';
import * as enterpriseEdition from '../../../../src/enterprise-edition/ee';
import { clearProvider, clearSsoDatabase } from './singleSignOn-test-utils';
import { initializeAuthenticationProviders } from '../../../../src/modules/singleSignOn/singleSignOn-init';
import { waitInSec } from '../../../../src/database/utils';
import { fullEntitiesList } from '../../../../src/database/middleware-loader';
import { ENTITY_TYPE_SINGLE_SIGN_ON } from '../../../../src/modules/singleSignOn/singleSignOn-types';
import { findById as findUserById } from '../../../../src/domain/user';
import { v4 as uuid } from 'uuid';
import { initializeAdminUser } from '../../../../src/modules/singleSignOn/providers-initialization';
import type { AuthUser } from '../../../../src/types/user';
import { OPENCTI_ADMIN_UUID } from '../../../../src/schema/general';
import { SYSTEM_USER } from '../../../../src/utils/access';

describe('Providers initialization coverage', () => {
  const PROVIDERS_SAVE: ProviderConfiguration[] = [];

  beforeAll(async () => {
    // Copy existing configuration and reset it for tests purpose.
    for (let i = 0; i < PROVIDERS.length; i++) {
      PROVIDERS_SAVE.push(PROVIDERS[i]);
    }
    expect(PROVIDERS_SAVE).toStrictEqual(PROVIDERS);
  });

  afterAll(async () => {
    // Reinstall initial configuration
    await waitInSec(1);
    await clearProvider();
    for (let i = 0; i < PROVIDERS_SAVE.length; i++) {
      PROVIDERS.push(PROVIDERS_SAVE[i]);
    }
    expect(PROVIDERS).toStrictEqual(PROVIDERS_SAVE);
  });

  describe('New platform startup coverage', () => {
    beforeEach(async () => {
      // we are testing platform initialization, so need to start from scratch on all tests
      await clearProvider();
      expect(PROVIDERS).toStrictEqual([]);

      await clearSsoDatabase();
    });

    const advancedEnvConfig = {
      local: {
        strategy: 'LocalStrategy',
      },
      saml: {
        identifier: 'saml2',
        strategy: 'SamlStrategy',
        config: {
          issuer: 'openctisaml',
          label: 'SAML groups 1',
          entry_point: 'https://myidp.invalid/realms/master/protocol/saml',
          saml_callback_url: 'http://opencti.mydomain.com/auth/saml2/callback',
          cert: 'xxxxxxxxxxxxxxxx',
        },
      },
      ldap: {
        identifier: 'ldap',
        strategy: 'LdapStrategy',
        config: {
          url: 'ldap://myidp:389',
          bind_dn: 'dc=mokapi,dc=io',
          search_base: 'ou=people,dc=mokapi,dc=io',
        },
      },
    };

    it('[EE & forceEnv = true & editionLocked = false] should force env avoid any call to database register in passport', async () => {
      // GIVEN lots of provider in env
      vi.spyOn(enterpriseEdition, 'isEnterpriseEdition').mockResolvedValue(true);
      vi.spyOn(providerConfig, 'isAuthenticationForcedFromEnv').mockReturnValue(true);
      vi.spyOn(providerConfig, 'isAuthenticationEditionLocked').mockReturnValue(false);
      vi.spyOn(providerConfig, 'getProvidersFromEnvironment').mockReturnValue(advancedEnvConfig);

      const registerAuthSpy = vi.spyOn(providerInit, 'registerAuthenticationProvider');
      const unregisterAuthSpy = vi.spyOn(providerInit, 'unregisterAuthenticationProvider');

      // WHEN initialization is run on startup
      await initializeAuthenticationProviders(testContext);

      // THEN no new authentication is registered on passport
      expect(registerAuthSpy, 'Register should not be called at all with force env = true').not.toHaveBeenCalled();
      expect(unregisterAuthSpy, 'Unregister should not be called at all with force env = true').not.toHaveBeenCalled();
      expect(PROVIDERS.length).toBe(3);
    });

    it('[EE & forceEnv = true & editionLocked = true] should force env avoid any call to database register in passport', async () => {
      vi.spyOn(enterpriseEdition, 'isEnterpriseEdition').mockResolvedValue(true);
      vi.spyOn(providerConfig, 'isAuthenticationForcedFromEnv').mockReturnValue(true);
      vi.spyOn(providerConfig, 'isAuthenticationEditionLocked').mockReturnValue(true);
      vi.spyOn(providerConfig, 'getProvidersFromEnvironment').mockReturnValue(advancedEnvConfig);

      const registerAuthSpy = vi.spyOn(providerInit, 'registerAuthenticationProvider');
      const unregisterAuthSpy = vi.spyOn(providerInit, 'unregisterAuthenticationProvider');

      // WHEN initialization is run on startup
      await initializeAuthenticationProviders(testContext);

      // THEN no new authentication is registered on passport
      expect(registerAuthSpy, 'Register should not be called at all with force env = true').not.toHaveBeenCalled();
      expect(unregisterAuthSpy, 'Unregister should not be called at all with force env = true').not.toHaveBeenCalled();
      expect(PROVIDERS.length).toBe(3);
    });

    it('[CE & forceEnv = false & editionLocked = true] should community edition not register SSO, only local', async () => {
      // GIVEN lots of provider in env
      vi.spyOn(providerConfig, 'isAuthenticationForcedFromEnv').mockReturnValue(false);
      vi.spyOn(providerConfig, 'isAuthenticationEditionLocked').mockReturnValue(true);
      vi.spyOn(providerConfig, 'getProvidersFromEnvironment').mockReturnValue(advancedEnvConfig);
      vi.spyOn(enterpriseEdition, 'isEnterpriseEdition').mockResolvedValue(false);

      const registerAuthSpy = vi.spyOn(providerInit, 'registerAuthenticationProvider');
      const unregisterAuthSpy = vi.spyOn(providerInit, 'unregisterAuthenticationProvider');

      // WHEN initialization is run on startup
      await initializeAuthenticationProviders(testContext);

      // THEN only local authentication is registered in passport
      expect(registerAuthSpy, 'Register should be called only once for local').toHaveBeenCalledOnce();
      expect(unregisterAuthSpy, 'Unregister should not be called at all with force env = true').not.toHaveBeenCalled();
      expect(PROVIDERS).toStrictEqual([{
        name: 'local',
        type: 'FORM',
        strategy: 'LocalStrategy',
        provider: 'local',
      }]); // local only
    });

    it('[CE & forceEnv = true & editionLocked = true] should community edition and force env not register SSO, only local the old way', async () => {
      // GIVEN lots of provider in env
      vi.spyOn(providerConfig, 'isAuthenticationForcedFromEnv').mockReturnValue(true);
      vi.spyOn(providerConfig, 'getProvidersFromEnvironment').mockReturnValue(advancedEnvConfig);
      vi.spyOn(enterpriseEdition, 'isEnterpriseEdition').mockResolvedValue(false);

      const registerAuthSpy = vi.spyOn(providerInit, 'registerAuthenticationProvider');
      const unregisterAuthSpy = vi.spyOn(providerInit, 'unregisterAuthenticationProvider');

      // WHEN initialization is run on startup
      await initializeAuthenticationProviders(testContext);

      // THEN only local authentication is registered in passport
      expect(registerAuthSpy, 'Register should be called only once for local - CE not impacted by force anv').toHaveBeenCalledOnce();
      expect(unregisterAuthSpy, 'Unregister should not be called at all with CE').not.toHaveBeenCalled();
      expect(PROVIDERS).toStrictEqual([{
        name: 'local',
        type: 'FORM',
        strategy: 'LocalStrategy',
        provider: 'local',
      }]); // local only

      // AND THEN nothing is stored in database
      const ssoInDb = await fullEntitiesList(testContext, ADMIN_USER, [ENTITY_TYPE_SINGLE_SIGN_ON]);
      expect(ssoInDb).toStrictEqual([]);
    });
  });

  describe('Providers from environment coverage', () => {
    const deprecatedProviders = [
      { identifier: 'google',
        strategyLogName: 'GOOGLE',
        configuration: {
          google: {
            strategy: 'GoogleStrategy',
            config: {
              client_id: 'xxxxxxxxxxx',
              client_secret: 'yyyyyyyyyyyyyy',
              callback_url: 'https://opencti.mydomain.com/auth/google/callback',
              logout_remote: false,
            },
          },
        },
      },
      { identifier: 'facebook',
        strategyLogName: 'FACEBOOK',
        configuration: {
          facebook: {
            strategy: 'FacebookStrategy',
            config: {
              client_id: 'xxxxxxxxxxx',
              client_secret: 'yyyyyyyyyyyyyy',
              callback_url: 'https://opencti.mydomain.com/auth/facebook/callback',
              logout_remote: false,
            },
          },
        },
      },
      { identifier: 'github',
        strategyLogName: 'GITHUB',
        configuration: {
          github: {
            strategy: 'GithubStrategy',
            config: {
              client_id: 'xxxxxxxxxxx',
              client_secret: 'yyyyyyyyyyyyyy',
              callback_url: 'https://opencti.mydomain.com/auth/github/callback',
              logout_remote: false,
            },
          },
        },
      },
    ];

    it.each(deprecatedProviders)('should read deprecated strategy from env and warn', async (useCase) => {
      vi.spyOn(providerConfig, 'getProvidersFromEnvironment').mockReturnValue(useCase.configuration);
      vi.spyOn(providerConfig, 'isAuthenticationForcedFromEnv').mockReturnValue(false);
      vi.spyOn(enterpriseEdition, 'isEnterpriseEdition').mockResolvedValue(true);

      const logAppWarnSpy = vi.spyOn(logApp, 'warn');
      await initializeEnvAuthenticationProviders(testContext, ADMIN_USER);

      // Provider must be registered
      expect(PROVIDERS.some((strategyProv) => strategyProv.provider === useCase.identifier)).toBeTruthy();

      // And warn should be send
      expect(logAppWarnSpy, 'No exception should be throw, but an warn message about deprecation should be present')
        .toHaveBeenCalledWith(
          `[ENV-PROVIDER][${useCase.strategyLogName}] DEPRECATED Strategy found in configuration providerRef:${useCase.identifier}, please consider using OpenID`,
        );
    });
    const envProviders = {
      oic: {
        identifier: 'oic',
        strategy: 'OpenIDConnectStrategy',
        config: {
          client_id: 'xxxxxxxxxxx',
          client_secret: 'yyyyyyyyyyyyyy',
          callback_url: 'https://opencti.mydomain.com/auth/oic/callback',
          logout_remote: false,
        },
      },
      saml: {
        identifier: 'saml2',
        strategy: 'SamlStrategy',
        config: {
          issuer: 'openctisaml',
          label: 'SAML groups 1',
          entry_point: 'https://myidp/realms/master/protocol/saml',
          saml_callback_url: 'http://opencti.mydomain.com/auth/saml2/callback',
          cert: 'xxxxxxxxxxxxxxxx',
        },
      },
      ldap: {
        identifier: 'ldap',
        strategy: 'LdapStrategy',
        config: {
          url: 'ldap://myidp:389',
          bind_dn: 'dc=mokapi,dc=io',
          search_base: 'ou=people,dc=mokapi,dc=io',
        },
      },
    };
    const convertedProviders = [
    /* TODO
    { identifier: 'local',
      strategyLogName: 'LOCAL',
      strategyId: 'LocalStrategy',
      configuration: {
        local: {
          strategy: 'LocalStrategy',
        },
      },
    }, */
      { identifier: 'oic',
        strategyLogName: 'OPENID',
        strategyId: 'OpenIDConnectStrategy',
        configuration: {
          oic: {
            strategy: 'OpenIDConnectStrategy',
            config: {
              client_id: 'xxxxxxxxxxx',
              client_secret: 'yyyyyyyyyyyyyy',
              callback_url: 'https://opencti.mydomain.com/auth/oic/callback',
              logout_remote: false,
            },
          },
        },
      },
      { identifier: 'saml2',
        strategyLogName: 'SAML',
        strategyId: 'SamlStrategy',
        configuration: {
          saml: {
            identifier: 'saml2',
            strategy: 'SamlStrategy',
            config: {
              issuer: 'openctisaml',
              label: 'SAML groups 1',
              entry_point: 'https://myidp/realms/master/protocol/saml',
              saml_callback_url: 'http://opencti.mydomain.com/auth/saml2/callback',
              cert: 'xxxxxxxxxxxxxxxx',
            },
          },
        },
      },
      { identifier: 'ldap',
        strategyLogName: 'LDAP',
        strategyId: 'LdapStrategy',
        configuration: {
          ldap: {
            identifier: 'ldap',
            strategy: 'LdapStrategy',
            config: {
              url: 'ldap://myidp:389',
              bind_dn: 'dc=mokapi,dc=io',
              search_base: 'ou=people,dc=mokapi,dc=io',
            },
          },
        },
      },
    ];
    it('should not init converted strategy from env', async () => {
      vi.spyOn(providerConfig, 'getProvidersFromEnvironment').mockReturnValue(envProviders);
      vi.spyOn(providerConfig, 'isAuthenticationProviderMigrated').mockReturnValue(false);
      vi.spyOn(providerConfig, 'isAuthenticationForcedFromEnv').mockReturnValue(false);
      vi.spyOn(enterpriseEdition, 'isEnterpriseEdition').mockResolvedValue(true);

      const logAppInfoSpy = vi.spyOn(logApp, 'info');
      await initializeEnvAuthenticationProviders(testContext, ADMIN_USER);
      for (let index = 0; index < convertedProviders.length; index += 1) {
        const useCase = convertedProviders[index];
        // Provider must not be registered
        expect(PROVIDERS.some((strategyProv) => strategyProv.provider === useCase.identifier)).toBeFalsy();

        // And info should be in log that a provider is in env
        expect(logAppInfoSpy, 'Provider should be see, but not added on env step.')
          .toHaveBeenCalledWith(
            `[ENV-PROVIDER][${useCase.strategyLogName}] ${useCase.strategyId} found in configuration providerRef:${useCase.identifier}`,
          );

        expect(logAppInfoSpy, 'Provider should be mark as should be converted')
          .toHaveBeenCalledWith(
            `[ENV-PROVIDER][${useCase.strategyLogName}] ${useCase.identifier} is about to be converted to database configuration.`,
          );
      }
    });

    it('should disabled provider not be registered', async () => {
      const configuration = {
        ldapBis: {
          identifier: 'ldapBis',
          strategy: 'LdapStrategy',
          config: {
            disabled: true,
            url: 'ldap://myidp:389',
            bind_dn: 'dc=mokapi,dc=io',
            search_base: 'ou=people,dc=mokapi,dc=io',
          },
        },
      };

      vi.spyOn(providerConfig, 'getProvidersFromEnvironment').mockReturnValue(configuration);

      const logAppInfoSpy = vi.spyOn(logApp, 'info');
      await initializeEnvAuthenticationProviders(testContext, ADMIN_USER);

      // Provider must not be registered
      expect(PROVIDERS.some((strategyProv) => strategyProv.provider === 'ldapBis')).toBeFalsy();

      expect(logAppInfoSpy, 'No logs').not.toHaveBeenCalledWith(
        '[ENV-PROVIDER][LDAP] LdapStrategy is about to be converted to database configuration.',
      );
    });
  });

  describe('initializeAdminUser configurations verifications', () => {
    let adminToken: string;
    let adminEmail: string;
    let adminPassword: string;
    let adminExternallyManaged: boolean;

    beforeAll(async () => {
      // Copy existing configuration and reset it for tests purpose.
      adminEmail = conf.get('app:admin:email');
      adminPassword = conf.get('app:admin:password');
      adminToken = conf.get('app:admin:token');
      adminExternallyManaged = booleanConf('app:admin:externally_managed', false);
    });

    afterAll(async () => {
      // Copy existing configuration and reset it for tests purpose.
      // Reinstall initial configuration
      vi.spyOn(providerConfig, 'getConfigurationAdminPassword').mockReturnValue(adminPassword);
      vi.spyOn(providerConfig, 'getConfigurationAdminToken').mockReturnValue(adminToken);
      vi.spyOn(providerConfig, 'getConfigurationAdminEmail').mockReturnValue(adminEmail);
      vi.spyOn(providerConfig, 'isAdminExternallyManaged').mockReturnValue(adminExternallyManaged);
      await initializeAdminUser(testContext);

      const existingAdmin = await findUserById(testContext, SYSTEM_USER, OPENCTI_ADMIN_UUID) as AuthUser;
      expect(existingAdmin.user_email).toBe(adminEmail);
    });

    it('should well configured admin be initialized', async () => {
      // GIVEN configuration
      const newToken = uuid();
      vi.spyOn(providerConfig, 'getConfigurationAdminPassword').mockReturnValue('IDiscoveredUniverseMatter');
      vi.spyOn(providerConfig, 'getConfigurationAdminToken').mockReturnValue(newToken);
      vi.spyOn(providerConfig, 'getConfigurationAdminEmail').mockReturnValue('cecilia.payne@filigran.io');
      vi.spyOn(providerConfig, 'isAdminExternallyManaged').mockReturnValue(false);

      await initializeAdminUser(testContext);

      const existingAdmin = await findUserById(testContext, SYSTEM_USER, OPENCTI_ADMIN_UUID) as AuthUser;
      expect(existingAdmin.user_email).toBe('cecilia.payne@filigran.io');
    });

    it('should password env with digit only works', async () => {
      // GIVEN configuration
      const newToken = uuid();
      vi.spyOn(providerConfig, 'getConfigurationAdminPassword').mockReturnValue(1111);
      vi.spyOn(providerConfig, 'getConfigurationAdminToken').mockReturnValue(newToken);
      vi.spyOn(providerConfig, 'getConfigurationAdminEmail').mockReturnValue('cecilia.payne@filigran.io');
      vi.spyOn(providerConfig, 'isAdminExternallyManaged').mockReturnValue(false);

      await initializeAdminUser(testContext);
      // expect no exception, exception are failing tests so nothing to check more.
    });

    // There is a "too many concurrent call on the same entities" edition issues on this one (externally managed = true means delete admin user)
    it.skip('should externally managed admin prevent admin creation', async () => {
      // GIVEN configuration
      vi.spyOn(providerConfig, 'getConfigurationAdminPassword').mockReturnValue('FirstBlackFemaleEngineerAtNasa');
      vi.spyOn(providerConfig, 'getConfigurationAdminToken').mockReturnValue(adminToken);
      vi.spyOn(providerConfig, 'getConfigurationAdminEmail').mockReturnValue('mary.jackson@filigran.io');
      vi.spyOn(providerConfig, 'isAdminExternallyManaged').mockReturnValue(true);

      await initializeAdminUser(testContext);

      await waitInSec(1); // tests are too fast, delete user and create the same again need some pause

      const existingAdmin = await findUserById(testContext, SYSTEM_USER, OPENCTI_ADMIN_UUID) as AuthUser;
      expect(existingAdmin).toBeUndefined();
    });

    it('should default password be refused', async () => {
      // GIVEN configuration
      vi.spyOn(providerConfig, 'getConfigurationAdminPassword').mockReturnValue('ChangeMe');
      vi.spyOn(providerConfig, 'getConfigurationAdminToken').mockReturnValue(adminToken);
      vi.spyOn(providerConfig, 'getConfigurationAdminEmail').mockReturnValue('mary.jackson@filigran.io');
      vi.spyOn(providerConfig, 'isAdminExternallyManaged').mockReturnValue(false);

      await expect(async () => {
        await initializeAdminUser(testContext);
      }).rejects.toThrowError('You need to configure the environment vars');
    });

    it('should invalid email be refused', async () => {
      // GIVEN configuration
      vi.spyOn(providerConfig, 'getConfigurationAdminPassword').mockReturnValue('changeMe');
      vi.spyOn(providerConfig, 'getConfigurationAdminToken').mockReturnValue(adminToken);
      vi.spyOn(providerConfig, 'getConfigurationAdminEmail').mockReturnValue('mary.jacksonATfiligran.io');
      vi.spyOn(providerConfig, 'isAdminExternallyManaged').mockReturnValue(false);

      await expect(async () => {
        await initializeAdminUser(testContext);
      }).rejects.toThrowError('Email must be a valid email address');
    });

    it('should invalid token be refused', async () => {
      // GIVEN configuration
      vi.spyOn(providerConfig, 'getConfigurationAdminPassword').mockReturnValue('FirstBlackFemaleEngineerAtNasa');
      vi.spyOn(providerConfig, 'getConfigurationAdminToken').mockReturnValue('1234-1324-13424');
      vi.spyOn(providerConfig, 'getConfigurationAdminEmail').mockReturnValue('mary.jackson@filigran.io');
      vi.spyOn(providerConfig, 'isAdminExternallyManaged').mockReturnValue(false);

      await expect(async () => {
        await initializeAdminUser(testContext);
      }).rejects.toThrowError('Token must be a valid UUID');
    });
  });
});
