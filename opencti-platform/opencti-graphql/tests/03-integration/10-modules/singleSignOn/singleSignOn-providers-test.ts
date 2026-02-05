import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { registerLocalStrategy } from '../../../../src/modules/singleSignOn/singleSignOn-providers';
import { ADMIN_USER, testContext } from '../../../utils/testQuery';
import * as providerConfig from '../../../../src/modules/singleSignOn/providers-configuration';
import { isAuthenticationActivatedByIdentifier, type ProviderConfiguration, PROVIDERS } from '../../../../src/modules/singleSignOn/providers-configuration';
import { clearProvider } from './singleSignOn-test-utils';
import { initEnterpriseAuthenticationProviders } from '../../../../src/modules/singleSignOn/singleSignOn-init';
import { waitInSec } from '../../../../src/database/utils';
import { deleteSingleSignOn, internalAddSingleSignOn } from '../../../../src/modules/singleSignOn/singleSignOn-domain';
import { type SingleSignOnAddInput, StrategyType } from '../../../../src/generated/graphql';

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

    it('should existing SSO in database be loaded', async () => {
      // GIVEN no SSO configuration at all - only local is register
      vi.spyOn(providerConfig, 'isAuthenticationForcedFromEnv').mockReturnValue(false);
      await clearProvider();

      const newSAMLInput: SingleSignOnAddInput = {
        strategy: StrategyType.SamlStrategy,
        name: 'Test SAML existing SSO',
        identifier: 'saml',
        enabled: true,
        configuration: [
          { key: 'issuer', type: 'string', value: 'openctisaml_default' },
          { key: 'entryPoint', type: 'string', value: 'http://localhost:8888/realms/master/protocol/saml' },
          { key: 'callbackUrl', type: 'string', value: 'http://localhost:3000/auth/saml/callback' },
          { key: 'idpCert', type: 'string', value: 'totallyFakeCertGroups' },
        ],
      };
      const saml1 = await internalAddSingleSignOn(testContext, ADMIN_USER, newSAMLInput, true);

      const newSAMLDisabledInput: SingleSignOnAddInput = {
        strategy: StrategyType.SamlStrategy,
        name: 'Test SAML2 existing SSO',
        identifier: 'saml2',
        enabled: false,
        configuration: [
          { key: 'issuer', type: 'string', value: 'saml2' },
          { key: 'entryPoint', type: 'string', value: 'http://localhost:8888/realms/master/protocol/saml' },
          { key: 'callbackUrl', type: 'string', value: 'http://localhost:3000/auth/saml2/callback' },
          { key: 'idpCert', type: 'string', value: 'saml2Cert' },
        ],
      };
      const saml2 = await internalAddSingleSignOn(testContext, ADMIN_USER, newSAMLDisabledInput, true);

      // WHEN initialization is done
      await initEnterpriseAuthenticationProviders(testContext, ADMIN_USER);

      // THEN the first SAML is configured, but not the second one
      // Local is created on platform startup
      expect(isAuthenticationActivatedByIdentifier('local')).toBeTruthy();
      expect(isAuthenticationActivatedByIdentifier('saml')).toBeTruthy();
      expect(isAuthenticationActivatedByIdentifier('saml2')).toBeFalsy();

      // Cleanup
      await deleteSingleSignOn(testContext, ADMIN_USER, saml1.id);
      await deleteSingleSignOn(testContext, ADMIN_USER, saml2.id);
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
