import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { initAuthenticationProviders, registerLocalStrategy } from '../../../../src/modules/singleSignOn/singleSignOn-providers';
import { ADMIN_USER, testContext } from '../../../utils/testQuery';
import { type ProviderConfiguration, PROVIDERS } from '../../../../src/modules/singleSignOn/providers-configuration';

describe.skip('Single sign on Provider coverage tests', () => {
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
      expect(PROVIDERS).toStrictEqual([]);

      // WHEN initialization is done
      await initAuthenticationProviders(testContext, ADMIN_USER);

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
