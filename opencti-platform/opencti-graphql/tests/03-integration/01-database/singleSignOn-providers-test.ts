import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { findAllSingleSignOn } from '../../../src/modules/singleSignOn/singleSignOn-domain';
import { ADMIN_USER, testContext } from '../../utils/testQuery';
import { addLocalStrategy, initAuthenticationProviders } from '../../../src/modules/singleSignOn/singleSignOn-providers';
import { type ProviderConfiguration, PROVIDERS } from '../../../src/config/providers-configuration';

describe('Single sign on Domain coverage tests', () => {
  describe('initialization coverage', () => {
    const clearProvider = async () => {
      for (let i = 0; i < PROVIDERS.length; i++) {
        PROVIDERS.pop();
      }
      expect(PROVIDERS).toStrictEqual([]);
    };

    let PROVIDERS_SAVE: ProviderConfiguration[];
    beforeAll(async () => {
      // Copy existing configuration and reset it for tests purpose.
      PROVIDERS_SAVE = [...PROVIDERS];
    });

    afterAll(async () => {
      // Reinstall initial configuration
      await clearProvider();
      for (let i = 0; i < PROVIDERS_SAVE.length; i++) {
        PROVIDERS.push(PROVIDERS_SAVE[i]);
      }
      expect(PROVIDERS).toStrictEqual(PROVIDERS_SAVE);
    });

    it('should an empty configuration works', async () => {
      // GIVEN no SSO configuration at all
      await clearProvider();
      const ssoConfig = await findAllSingleSignOn(testContext, ADMIN_USER);
      expect(ssoConfig.length, 'This test assume that no configuration is setup yet').toBe(0);
      expect(PROVIDERS).toStrictEqual([]);

      // WHEN initialization is done
      await initAuthenticationProviders(testContext, ADMIN_USER);
      console.log('PROVIDERS:', PROVIDERS);

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
      await addLocalStrategy('localFirst');
      console.log('PROVIDERS:', PROVIDERS);
      await addLocalStrategy('localSecond');

      // THEN only last local strategy is configured and enabled
      expect(PROVIDERS).toStrictEqual([
        {
          name: 'localSecond',
          type: 'FORM',
          strategy: 'LocalStrategy',
          provider: 'local',
        },
      ]);
    });
  });
});
