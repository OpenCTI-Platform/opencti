import { describe, it, vi, expect } from 'vitest';
import { initializeAuthenticationProviders } from '../../../../src/modules/authenticationProvider/providers';
import { testContext } from '../../../utils/testQuery';
import type { BasicStoreSettings } from '../../../../src/types/settings';
import * as mockProviderEnv from '../../../../src/modules/authenticationProvider/providers-configuration';
import { getSettings } from '../../../../src/domain/settings';
import { buildAvailableProviders } from '../../../../src/domain/setting-auth';
import { PROVIDERS } from '../../../../src/modules/authenticationProvider/providers-configuration';

describe('initializeAuthenticationProviders coverage', () => {
  const clearEnvProviderArray = () => {
    const len = PROVIDERS.length;
    for (let i = 0; i < len; i++) {
      PROVIDERS.pop();
    }
  };

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
