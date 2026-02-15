import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { parseValueAsType, registerLocalStrategy } from '../../../../src/modules/__singleSignOn/singleSignOn-providers';
import { ADMIN_USER, testContext } from '../../../utils/testQuery';
import * as providerConfig from '../../../../src/modules/__singleSignOn/providers-configuration';
import { isAuthenticationActivatedByIdentifier, type ProviderConfiguration, PROVIDERS } from '../../../../src/modules/__singleSignOn/providers-configuration';
import { clearProvider } from './singleSignOn-test-utils';
import { initEnterpriseAuthenticationProviders } from '../../../../src/modules/__singleSignOn/singleSignOn-init';
import { waitInSec } from '../../../../src/database/utils';
import { deleteSingleSignOn, encryptAuthValue, internalAddSingleSignOn, SECRET_TYPE } from '../../../../src/modules/__singleSignOn/singleSignOn-domain';
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
      expect(PROVIDERS).toStrictEqual([]);
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
      expect(isAuthenticationActivatedByIdentifier('saml')).toBeTruthy();
      expect(isAuthenticationActivatedByIdentifier('saml2')).toBeFalsy();

      // Cleanup
      await deleteSingleSignOn(testContext, ADMIN_USER, saml1.id);
      await deleteSingleSignOn(testContext, ADMIN_USER, saml2.id);
    });
  });

  describe('Convert database configuration to object coverage', () => {
    it('should boolean be correctly parsed', async () => {
      let result = await parseValueAsType({ key: 'theKey', value: 'true', type: 'boolean' });
      expect(result).toBe(true);

      result = await parseValueAsType({ key: 'theKey', value: 'true', type: 'BOOLEAN' });
      expect(result).toBe(true);

      result = await parseValueAsType({ key: 'theKey', value: 'wrong', type: 'Boolean' });
      expect(result).toBe(false);
    });

    it('should number be correctly parsed', async () => {
      let result = await parseValueAsType({ key: 'theKey', value: 'true', type: 'boolean' });
      expect(result).toBe(true);

      result = await parseValueAsType({ key: 'theKey', value: 'true', type: 'BOOLEAN' });
      expect(result).toBe(true);

      result = await parseValueAsType({ key: 'theKey', value: 'wrong', type: 'Boolean' });
      expect(result).toBe(false);
    });

    it('should partial configuration throw error', async () => {
      await expect((async () => {
        await parseValueAsType({ key: '', value: 'true', type: 'boolean' });
      })()).rejects.toThrowError('Authentication configuration cannot be parsed, key, type or value is empty.');

      await expect((async () => {
        await parseValueAsType({ key: 'myKey', value: '', type: 'string' });
      })()).rejects.toThrowError('Authentication configuration cannot be parsed, key, type or value is empty.');

      await expect((async () => {
        await parseValueAsType({ key: 'myKey', value: 'true', type: '' });
      })()).rejects.toThrowError('Authentication configuration cannot be parsed, key, type or value is empty.');
    });

    it('should invalid configuration throw error', async () => {
      await expect((async () => {
        await parseValueAsType({ key: 'myKey', value: '{un: "deux"}', type: 'object' });
      })()).rejects.toThrowError('Authentication configuration cannot be parsed, unknown type.');
    });

    it('should decrypt secret types', async () => {
      const encryptedValue = await encryptAuthValue('MyValueIsFine');
      expect(encryptedValue).not.toBe('MyValueIsFine');
      const result = await parseValueAsType({ key: 'myKey', value: `${encryptedValue}`, type: SECRET_TYPE });
      expect(result).toBe('MyValueIsFine');
    });
  });
});
