import { afterAll, describe, expect, it, vi } from 'vitest';

import { logApp } from '../../../../src/config/conf';
import { addSingleSignOn, deleteSingleSignOn, fieldPatchSingleSignOn, findAllSingleSignOn, findSingleSignOnById } from '../../../../src/modules/singleSignOn/singleSignOn-domain';
import { ADMIN_USER, testContext } from '../../../utils/testQuery';
import { StrategyType, type SingleSignOnAddInput, type EditInput } from '../../../../src/generated/graphql';
import { PROVIDERS } from '../../../../src/modules/singleSignOn/providers-configuration';
import type { BasicStoreEntitySingleSignOn, StixSingleSignOn, StoreEntitySingleSignOn } from '../../../../src/modules/singleSignOn/singleSignOn-types';
import convertSingleSignOnToStix from '../../../../src/modules/singleSignOn/singleSignOn-converter';
import { onAuthenticationMessageAdd, onAuthenticationMessageDelete, onAuthenticationMessageEdit } from '../../../../src/modules/singleSignOn/singleSignOn-listener';

describe.skip('Single sign on Domain coverage tests', () => {
  describe('SAML coverage tests', () => {
    afterAll(async () => {
      const allSso = await findAllSingleSignOn(testContext, ADMIN_USER);
      for (let i = 0; i < allSso.length; i++) {
        if (allSso[i].identifier?.startsWith('samlTest')) {
          await deleteSingleSignOn(testContext, ADMIN_USER, allSso[i].id);
        }
      }
    });

    let minimalSsoEntity: BasicStoreEntitySingleSignOn;
    it('should add new minimal SAML provider', async () => {
      const input: SingleSignOnAddInput = {
        name: 'Saml for test domain',
        strategy: StrategyType.SamlStrategy,
        identifier: 'samlTestDomain',
        enabled: true,
        label: 'Nice SAML button',
        configuration: [
          { key: 'callbackUrl', value: 'http://myopencti/auth/samlTestDomain/callback', type: 'string' },
          { key: 'idpCert', value: '21341234', type: 'string' },
          { key: 'issuer', value: 'issuer', type: 'string' },
        ],
      };
      const samlEntity = await addSingleSignOn(testContext, ADMIN_USER, input);
      minimalSsoEntity = samlEntity;
      expect(samlEntity.identifier).toBe('samlTestDomain');
      expect(samlEntity.enabled).toBe(true);
      expect(samlEntity.label).toBe('Nice SAML button');

      // Here there is a pub/sub on redis, let's just call the same method than listener
      await onAuthenticationMessageAdd({ instance: samlEntity });
      expect(PROVIDERS.some((strategyProv) => strategyProv.provider === 'samlTestDomain')).toBeTruthy();
    });

    it('should convert to stix', async () => {
      const stixSso: StixSingleSignOn = convertSingleSignOnToStix(minimalSsoEntity as StoreEntitySingleSignOn);
      expect(stixSso.identifier).toBe('samlTestDomain');
      expect(stixSso.id).toMatch(/singlesignon-+/);
      expect(stixSso.label).toBe('Nice SAML button');
    });

    it('should disable minimal Saml works', async () => {
      const input: EditInput[] = [{ key: 'label', value: ['Nice SAML button V2'] }];
      await fieldPatchSingleSignOn(testContext, ADMIN_USER, minimalSsoEntity.id, input);
      const entity = await findSingleSignOnById(testContext, ADMIN_USER, minimalSsoEntity.id);

      // Here there is a pub/sub on redis, let's just call the same method than listener
      await onAuthenticationMessageEdit({ instance: entity });

      expect(entity.label).toBe('Nice SAML button V2');
      expect(PROVIDERS.some((strategyProv) => strategyProv.provider === 'samlTestDomain')).toBeTruthy();
    });

    it('should delete minimal Saml works', async () => {
      await deleteSingleSignOn(testContext, ADMIN_USER, minimalSsoEntity.id);

      // Here there is a pub/sub on redis, let's just call the same method than listener
      await onAuthenticationMessageDelete({ instance: minimalSsoEntity });

      expect(PROVIDERS.some((strategyProv) => strategyProv.provider === 'samlTestDomain')).toBeFalsy();
    });

    it('should not add new SAML provider if no config is given', async () => {
      const logAppErrorSpy = vi.spyOn(logApp, 'error');

      // For example callbackUrl is mandatory for SAML
      const input: SingleSignOnAddInput = {
        name: 'Saml for test domain callback url missing',
        strategy: StrategyType.SamlStrategy,
        identifier: 'samlTestNotOk',
        enabled: true,
        label: 'Nice SAML button',
      };
      const samlEntity = await addSingleSignOn(testContext, ADMIN_USER, input);

      // Here there is a pub/sub on redis, let's just call the same method as listener
      await onAuthenticationMessageAdd({ instance: samlEntity });

      expect(PROVIDERS.some((strategyProv) => strategyProv.provider === 'samlTestNotOk')).toBeFalsy();
      expect(logAppErrorSpy, 'No exception should be throw, but an error message should be present')
        .toHaveBeenCalledWith(
          `[Auth][Not provided]Error when initializing an authentication provider (id: ${samlEntity.id}, identifier: samlTestNotOk), cause: SSO configuration is empty`,
          expect.anything(),
        );
    });

    it('should not add new SAML provider if mandatory callbackUrl config is not given', async () => {
      const logAppErrorSpy = vi.spyOn(logApp, 'error');
      // For example callbackUrl is mandatory for SAML
      const input: SingleSignOnAddInput = {
        name: 'Saml for test domain callback url missing',
        strategy: StrategyType.SamlStrategy,
        identifier: 'samlTestNotOk2',
        enabled: true,
        label: 'Nice SAML button',
        configuration: [{ key: 'idpCert', value: 'mszfrhazmfghqzefh', type: 'string' }],
      };
      const samlEntity = await addSingleSignOn(testContext, ADMIN_USER, input);

      // Here there is a pub/sub on redis, let's just call the same method as listener
      await onAuthenticationMessageAdd({ instance: samlEntity });

      expect(PROVIDERS.some((strategyProv) => strategyProv.provider === 'samlTestNotOk2')).toBeFalsy();
      expect(logAppErrorSpy, 'No exception should be throw, but an error message should be present')
        .toHaveBeenCalledWith(
          `[Auth][Not provided]Error when initializing an authentication provider (id: ${samlEntity.id}, identifier: samlTestNotOk2), cause: callbackUrl is mandatory for SAML`,
          expect.anything(),
        );
    });

    it('should not add new SAML provider if mandatory idpCert config is not given', async () => {
      const logAppErrorSpy = vi.spyOn(logApp, 'error');
      const input: SingleSignOnAddInput = {
        name: 'Saml for test domain idpCert url missing',
        strategy: StrategyType.SamlStrategy,
        identifier: 'samlTestNotOk4',
        enabled: true,
        label: 'Nice SAML button',
        configuration: [{ key: 'callbackUrl', value: 'http://opencti/saml', type: 'string' }],
      };
      const samlEntity = await addSingleSignOn(testContext, ADMIN_USER, input);

      // Here there is a pub/sub on redis, let's just call the same method as listener
      await onAuthenticationMessageAdd({ instance: samlEntity });

      expect(PROVIDERS.some((strategyProv) => strategyProv.provider === 'samlTestNotOk4')).toBeFalsy();
      expect(logAppErrorSpy, 'No exception should be throw, but an error message should be present')
        .toHaveBeenCalledWith(
          `[Auth][Not provided]Error when initializing an authentication provider (id: ${samlEntity.id}, identifier: samlTestNotOk4), cause: idpCert is mandatory for SAML`,
          expect.anything(),
        );
    });

    it('should not add new SAML provider if mandatory issuer config is not given', async () => {
      const logAppErrorSpy = vi.spyOn(logApp, 'error');
      const input: SingleSignOnAddInput = {
        name: 'Saml for test domain issuer missing',
        strategy: StrategyType.SamlStrategy,
        identifier: 'samlTestNotOk5',
        enabled: true,
        label: 'Nice SAML button',
        configuration: [
          { key: 'idpCert', value: 'mszfrhazmfghqzefh', type: 'string' },
          { key: 'callbackUrl', value: 'http://opencti/saml', type: 'string' }],
      };
      const samlEntity = await addSingleSignOn(testContext, ADMIN_USER, input);

      // Here there is a pub/sub on redis, let's just call the same method as listener
      await onAuthenticationMessageAdd({ instance: samlEntity });

      expect(PROVIDERS.some((strategyProv) => strategyProv.provider === 'samlTestNotOk5')).toBeFalsy();
      expect(logAppErrorSpy, 'No exception should be throw, but an error message should be present')
        .toHaveBeenCalledWith(
          `[Auth][Not provided]Error when initializing an authentication provider (id: ${samlEntity.id}, identifier: samlTestNotOk5), cause: issuer is mandatory for SAML`,
          expect.anything(),
        );
    });
  });
  describe('OpenID coverage tests', () => {
    afterAll(async () => {
      const allSso = await findAllSingleSignOn(testContext, ADMIN_USER);
      for (let i = 0; i < allSso.length; i++) {
        if (allSso[i].identifier?.startsWith('openidTest')) {
          await deleteSingleSignOn(testContext, ADMIN_USER, allSso[i].id);
        }
      }
    });

    it('should add new minimal OpenID provider', async () => {
      const input: SingleSignOnAddInput = {
        name: 'OpenID for test domain',
        strategy: StrategyType.OpenIdConnectStrategy,
        identifier: 'openidTestDomain',
        enabled: false,
        label: 'Nice OIC button',
        configuration: [
          { key: 'redirect_uris', value: '["http://fake.invalid"]', type: 'array' },
          { key: 'client_secret', value: 'graceHopper', type: 'string' },
          { key: 'client_id', value: 'myoicclient', type: 'string' },
          { key: 'issuer', value: 'issuer', type: 'string' },
        ],
      };
      const oicEntity = await addSingleSignOn(testContext, ADMIN_USER, input);

      expect(oicEntity.identifier).toBe('openidTestDomain');
      expect(oicEntity.enabled).toBe(false);
      expect(oicEntity.label).toBe('Nice OIC button');
    });

    it('should missing redirect_uris throw error', async () => {
      const logAppErrorSpy = vi.spyOn(logApp, 'error');
      const input: SingleSignOnAddInput = {
        name: 'OpenID for test domain no redirect_uris',
        strategy: StrategyType.OpenIdConnectStrategy,
        identifier: 'openidTestKo1',
        enabled: true,
        label: 'Nice OIC button',
        configuration: [
          { key: 'client_secret', value: 'graceHopper', type: 'string' },
          { key: 'client_id', value: 'myoicclient', type: 'string' },
          { key: 'issuer', value: 'issuer', type: 'string' },
        ],
      };
      const oicEntity = await addSingleSignOn(testContext, ADMIN_USER, input);
      expect(oicEntity.identifier).toBe('openidTestKo1');
      expect(oicEntity.enabled).toBe(true);
      expect(oicEntity.label).toBe('Nice OIC button');

      // Here there is a pub/sub on redis, let's just call the same method as listener
      await onAuthenticationMessageAdd({ instance: oicEntity });
      expect(PROVIDERS.some((strategyProv) => strategyProv.provider === 'openidTestKo1')).toBeFalsy();

      expect(logAppErrorSpy, 'No exception should be throw, but an error message should be present')
        .toHaveBeenCalledWith(
          `[Auth][Not provided]Error when initializing an authentication provider (id: ${oicEntity.id}, identifier: openidTestKo1), cause: redirect_uris is mandatory for OpenID`,
          expect.anything(),
        );
    });

    it('should missing client_id throw error', async () => {
      const logAppErrorSpy = vi.spyOn(logApp, 'error');
      const input: SingleSignOnAddInput = {
        name: 'OpenID for test domain no client_id',
        strategy: StrategyType.OpenIdConnectStrategy,
        identifier: 'openidTestKo2',
        enabled: true,
        label: 'Nice OIC button',
        configuration: [
          { key: 'redirect_uris', value: '["http://fake.invalid"]', type: 'array' },
          { key: 'client_secret', value: 'graceHopper', type: 'string' },
          { key: 'issuer', value: 'issuer', type: 'string' },
        ],
      };
      const oicEntity = await addSingleSignOn(testContext, ADMIN_USER, input);
      expect(oicEntity.identifier).toBe('openidTestKo2');
      expect(oicEntity.enabled).toBe(true);
      expect(oicEntity.label).toBe('Nice OIC button');

      // Here there is a pub/sub on redis, let's just call the same method as listener
      await onAuthenticationMessageAdd({ instance: oicEntity });
      expect(PROVIDERS.some((strategyProv) => strategyProv.provider === 'openidTestKo2')).toBeFalsy();

      expect(logAppErrorSpy, 'No exception should be throw, but an error message should be present')
        .toHaveBeenCalledWith(
          `[Auth][Not provided]Error when initializing an authentication provider (id: ${oicEntity.id}, identifier: openidTestKo2), cause: client_id is mandatory for OpenID`,
          expect.anything(),
        );
    });

    it('should missing issuer throw error', async () => {
      const logAppErrorSpy = vi.spyOn(logApp, 'error');
      const input: SingleSignOnAddInput = {
        name: 'OpenID for test domain no issuer',
        strategy: StrategyType.OpenIdConnectStrategy,
        identifier: 'openidTestKo3',
        enabled: true,
        label: 'Nice OIC button',
        configuration: [
          { key: 'redirect_uris', value: '["http://fake.invalid"]', type: 'array' },
          { key: 'client_secret', value: 'graceHopper', type: 'string' },
          { key: 'client_id', value: 'myoicclient', type: 'string' },
        ],
      };
      const oicEntity = await addSingleSignOn(testContext, ADMIN_USER, input);
      expect(oicEntity.identifier).toBe('openidTestKo3');
      expect(oicEntity.enabled).toBe(true);
      expect(oicEntity.label).toBe('Nice OIC button');

      // Here there is a pub/sub on redis, let's just call the same method as listener
      await onAuthenticationMessageAdd({ instance: oicEntity });
      expect(PROVIDERS.some((strategyProv) => strategyProv.provider === 'openidTestKo1')).toBeFalsy();

      expect(logAppErrorSpy, 'No exception should be throw, but an error message should be present')
        .toHaveBeenCalledWith(
          `[Auth][Not provided]Error when initializing an authentication provider (id: ${oicEntity.id}, identifier: openidTestKo3), cause: issuer is mandatory for OpenID`,
          expect.anything(),
        );
    });

    it('should missing client_secret throw error', async () => {
      const logAppErrorSpy = vi.spyOn(logApp, 'error');
      const input: SingleSignOnAddInput = {
        name: 'OpenID for test domain no client_secret',
        strategy: StrategyType.OpenIdConnectStrategy,
        identifier: 'openidTestKo4',
        enabled: true,
        label: 'Nice OIC button',
        configuration: [
          { key: 'redirect_uris', value: '["http://fake.invalid"]', type: 'array' },
          { key: 'client_id', value: 'myoicclient', type: 'string' },
          { key: 'issuer', value: 'issuer', type: 'string' },
        ],
      };
      const oicEntity = await addSingleSignOn(testContext, ADMIN_USER, input);
      expect(oicEntity.identifier).toBe('openidTestKo4');
      expect(oicEntity.enabled).toBe(true);
      expect(oicEntity.label).toBe('Nice OIC button');

      // Here there is a pub/sub on redis, let's just call the same method as listener
      await onAuthenticationMessageAdd({ instance: oicEntity });
      expect(PROVIDERS.some((strategyProv) => strategyProv.provider === 'openidTestKo4')).toBeFalsy();

      expect(logAppErrorSpy, 'No exception should be throw, but an error message should be present')
        .toHaveBeenCalledWith(
          `[Auth][Not provided]Error when initializing an authentication provider (id: ${oicEntity.id}, identifier: openidTestKo4), cause: client_secret is mandatory for OpenID`,
          expect.anything(),
        );
    });
  });

  describe('LDAP coverage tests', () => {
    afterAll(async () => {
      const allSso = await findAllSingleSignOn(testContext, ADMIN_USER);
      for (let i = 0; i < allSso.length; i++) {
        if (allSso[i].identifier?.startsWith('ldapTest')) {
          await deleteSingleSignOn(testContext, ADMIN_USER, allSso[i].id);
        }
      }
    });

    it('should add new minimal OpenID provider', async () => {
      const input: SingleSignOnAddInput = {
        name: 'LDAP for test domain',
        strategy: StrategyType.LdapStrategy,
        identifier: 'ldapTest1',
        enabled: true,
        configuration: [
          { key: 'url', type: 'string', value: 'ldap://localhost:389' },
          { key: 'bindDN', type: 'string', value: 'cn=admin,dc=example,dc=org' },
          { key: 'bindCredentials', type: 'string', value: 'youShallNotPass' },
          { key: 'searchBase', type: 'string', value: 'dc=example,dc=org' },
          { key: 'searchFilter', type: 'string', value: 'mail={{username}}' },
        ],
      };
      const ldapEntity = await addSingleSignOn(testContext, ADMIN_USER, input);

      expect(ldapEntity.identifier).toBe('ldapTest1');
      expect(ldapEntity.enabled).toBe(true);

      // Here there is a pub/sub on redis, let's just call the same method as listener
      await onAuthenticationMessageAdd({ instance: ldapEntity });
      expect(PROVIDERS.some((strategyProv) => strategyProv.provider === 'ldapTest1')).toBeTruthy();
    });
  });
});
