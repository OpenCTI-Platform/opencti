import { describe, expect, it, vi } from 'vitest';
import { ADMIN_USER, testContext } from '../../../utils/testQuery';
import { initializeEnvAuthenticationProviders } from '../../../../src/modules/singleSignOn/providers-initialization';
import * as providerConfig from '../../../../src/modules/singleSignOn/providers-configuration';
import { PROVIDERS } from '../../../../src/modules/singleSignOn/providers-configuration';
import { logApp } from '../../../../src/config/conf';

describe.skip('Providers from environment coverage', () => {
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
  it.each(convertedProviders)('should not init converted strategy from env', async (useCase) => {
    vi.spyOn(providerConfig, 'getProvidersFromEnvironment').mockReturnValue(useCase.configuration);
    vi.spyOn(providerConfig, 'isAuthenticationProviderMigrated').mockReturnValue(false);

    const logAppInfoSpy = vi.spyOn(logApp, 'info');
    await initializeEnvAuthenticationProviders(testContext, ADMIN_USER);

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
