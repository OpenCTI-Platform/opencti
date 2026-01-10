import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { ADMIN_USER, testContext } from '../../utils/testQuery';
import { registerLocalStrategy, buildSAMLOptions, initAuthenticationProviders } from '../../../src/modules/singleSignOn/singleSignOn-providers';
import { type ProviderConfiguration, PROVIDERS } from '../../../src/config/providers-configuration';
import type { BasicStoreEntitySingleSignOn } from '../../../src/modules/singleSignOn/singleSignOn-types';
import { StrategyType } from '../../../src/generated/graphql';

describe('Single sign on Provider coverage tests', () => {
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
      await registerLocalStrategy('localFirst');
      console.log('PROVIDERS:', PROVIDERS);
      await registerLocalStrategy('localSecond');

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

  describe('configuration computation coverage', () => {
    it('should build correct options for SAML', async () => {
      const samlEntity: Partial<BasicStoreEntitySingleSignOn> = {
        strategy: StrategyType.SamlStrategy,
        configuration: [
          {
            key: 'issuer',
            value: 'openctisaml',
            type: 'string',
          },
          {
            key: 'entryPoint',
            value: 'http://localhost:9999/realms/master/protocol/saml',
            type: 'string',
          },
          {
            key: 'callbackUrl',
            value: 'http://localhost:4000/auth/saml/callback',
            type: 'string',
          },
          {
            key: 'idpCert',
            value: 'MIICmzCxxxxuJ1ZY=',
            type: 'string',
          },
          {
            key: 'wantAuthnResponseSigned',
            value: 'false',
            type: 'boolean',
          },
          {
            key: 'acceptedClockSkewMs',
            value: '3',
            type: 'number',
          },
        ],
      };

      const result = await buildSAMLOptions(samlEntity as BasicStoreEntitySingleSignOn);
      expect(result).toStrictEqual({
        issuer: 'openctisaml',
        entryPoint: 'http://localhost:9999/realms/master/protocol/saml',
        callbackUrl: 'http://localhost:4000/auth/saml/callback',
        idpCert: 'MIICmzCxxxxuJ1ZY=',
        wantAuthnResponseSigned: false,
        acceptedClockSkewMs: 3,
      });
    });
  });
});
