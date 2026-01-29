import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { registerLocalStrategy } from '../../../../src/modules/singleSignOn/singleSignOn-providers';
import { ADMIN_USER, testContext } from '../../../utils/testQuery';
import { type ProviderConfiguration, PROVIDERS } from '../../../../src/modules/singleSignOn/providers-configuration';
import * as providerConfig from '../../../../src/modules/singleSignOn/providers-configuration';
import { clearProvider } from './singleSignOn-test-utils';
import { initEnterpriseAuthenticationProviders } from '../../../../src/modules/singleSignOn/singleSignOn-init';
import { waitInSec } from '../../../../src/database/utils';

describe('Single sign on Provider coverage tests', () => {
  describe('initialization coverage', () => {
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

    it('should an empty configuration works', async () => {
      // GIVEN no SSO configuration at all - only local is register
      vi.spyOn(providerConfig, 'isAuthenticationForcedFromEnv').mockReturnValue(false);
      await clearProvider();

      // WHEN initialization is done
      await initEnterpriseAuthenticationProviders(testContext, ADMIN_USER);

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
});
