import { afterAll, describe, expect, it, vi } from 'vitest';

import { logApp } from '../../../../src/config/conf';
import {
  addSingleSignOn,
  deleteSingleSignOn,
  editSingleSignOn,
  findAllAuthenticationProvider,
  findAuthenticationProviderById,
  SECRET_TYPE,
} from '../../../../src/modules/authenticationProvider/authenticationProvider-domain';
import { ADMIN_USER, testContext } from '../../../utils/testQuery';
import { AuthenticationProviderType, type SingleSignOnAddInput } from '../../../../src/generated/graphql';
import { PROVIDERS } from '../../../../src/modules/authenticationProvider/providers-configuration';
import type { BasicStoreEntityAuthenticationProvider, ConfigEntry, StixAuthenticationProvider, StoreEntityAuthenticationProvider } from '../../../../src/modules/authenticationProvider/authenticationProvider-types';
import convertAuthenticationProviderToStix from '../../../../src/modules/authenticationProvider/authenticationProvider-converter';
import { onAuthenticationMessageAdd, onAuthenticationMessageDelete, onAuthenticationMessageEdit } from '../../../../src/modules/authenticationProvider/authenticationProvider-listener';
import * as providerConfig from '../../../../src/modules/authenticationProvider/providers-configuration';
import { getFakeAuthUser } from '../../../utils/domainQueryHelper';

describe('Single sign on Domain coverage tests', () => {
  describe('SAML coverage tests', () => {
    afterAll(async () => {
      const allSso = await findAllAuthenticationProvider(testContext, ADMIN_USER);
      for (let i = 0; i < allSso.length; i++) {
        if (allSso[i].identifier?.startsWith('samlTest')) {
          await deleteSingleSignOn(testContext, ADMIN_USER, allSso[i].id);
        }
      }
    });

    let minimalSsoEntity: BasicStoreEntityAuthenticationProvider;
    it('should add new minimal SAML provider', async () => {
      const input: SingleSignOnAddInput = {
        name: 'Saml for test domain',
        strategy: AuthenticationProviderType.Saml,
        identifier: 'samlTestDomain',
        enabled: true,
        label: 'Nice SAML button',
        configuration: [
          { key: 'callbackUrl', value: 'http://myopencti/auth/samlTestDomain/callback', type: 'string' },
          { key: 'idpCert', value: '21341234', type: 'string' },
          { key: 'issuer', value: 'https://issuer.example.net', type: 'string' },
          { key: 'privateKey', value: 'myPrivateKey', type: 'string' },
          { key: 'custom_value_that_is_secret', value: 'theCustomValue', type: SECRET_TYPE },
        ],
      };
      const samlEntity = await addSingleSignOn(testContext, ADMIN_USER, input);
      minimalSsoEntity = samlEntity;
      expect(samlEntity.identifier).toBe('samlTestDomain');
      expect(samlEntity.enabled).toBe(true);
      expect(samlEntity.label).toBe('Nice SAML button');

      const callbackUrl = samlEntity.configuration?.find((config) => config.key === 'callbackUrl') as ConfigEntry;
      expect(callbackUrl.value).toBe('http://myopencti/auth/samlTestDomain/callback');

      // Here there is a pub/sub on redis, let's just call the same method than listener
      await onAuthenticationMessageAdd({ instance: samlEntity });
      const cacheConfig = PROVIDERS.find((strategyProv) => strategyProv.provider === 'samlTestDomain');
      expect(cacheConfig?.logout_remote).toBeFalsy();
      expect(PROVIDERS.some((strategyProv) => strategyProv.provider === 'samlTestDomain')).toBeTruthy();
    });

    it('should logout_remote be in SAML provider', async () => {
      const input: SingleSignOnAddInput = {
        name: 'Saml for test domain',
        strategy: AuthenticationProviderType.Saml,
        identifier: 'samlTestDomainLogout',
        enabled: true,
        label: 'Nice SAML button',
        configuration: [
          { key: 'callbackUrl', value: 'http://myopencti/auth/samlTestDomainLogout/callback', type: 'string' },
          { key: 'idpCert', value: '21341234', type: 'string' },
          { key: 'issuer', value: 'https://issuer.example.net', type: 'string' },
          { key: 'logout_remote', value: 'true', type: 'boolean' },
        ],
      };
      const samlEntity = await addSingleSignOn(testContext, ADMIN_USER, input);
      expect(samlEntity.identifier).toBe('samlTestDomainLogout');
      expect(samlEntity.enabled).toBe(true);
      expect(samlEntity.label).toBe('Nice SAML button');

      // Here there is a pub/sub on redis, let's just call the same method than listener
      await onAuthenticationMessageAdd({ instance: samlEntity });
      const cacheConfig = PROVIDERS.find((strategyProv) => strategyProv.provider === 'samlTestDomainLogout');
      expect(cacheConfig?.logout_remote).toBeTruthy();
    });

    it('should convert to stix', async () => {
      const stixSso: StixAuthenticationProvider = convertAuthenticationProviderToStix(minimalSsoEntity as StoreEntityAuthenticationProvider);
      expect(stixSso.identifier).toBe('samlTestDomain');
      expect(stixSso.id).toMatch(/singlesignon-+/);
      expect(stixSso.label).toBe('Nice SAML button');
    });

    it('should disabled minimal Saml works', async () => {
      await editSingleSignOn(testContext, ADMIN_USER, minimalSsoEntity.id, { label: 'Nice SAML button V2' });
      const entity = await findAuthenticationProviderById(testContext, ADMIN_USER, minimalSsoEntity.id);

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
        strategy: AuthenticationProviderType.Saml,
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
          `[Auth][Not provided]Error when initializing an authentication provider (id: ${samlEntity.id}, identifier: samlTestNotOk), cause: idpCert is mandatory for SAML.`,
          expect.anything(),
        );
    });

    it('should not add new SAML provider if mandatory callbackUrl config is not given', async () => {
      const logAppErrorSpy = vi.spyOn(logApp, 'error');
      // For example callbackUrl is mandatory for SAML
      const input: SingleSignOnAddInput = {
        name: 'Saml for test domain callback url missing',
        strategy: AuthenticationProviderType.Saml,
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
          `[Auth][Not provided]Error when initializing an authentication provider (id: ${samlEntity.id}, identifier: samlTestNotOk2), cause: callbackUrl is mandatory for SAML.`,
          expect.anything(),
        );
    });

    it('should not add new SAML provider if mandatory idpCert config is not given', async () => {
      const logAppErrorSpy = vi.spyOn(logApp, 'error');
      const input: SingleSignOnAddInput = {
        name: 'Saml for test domain idpCert url missing',
        strategy: AuthenticationProviderType.Saml,
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
          `[Auth][Not provided]Error when initializing an authentication provider (id: ${samlEntity.id}, identifier: samlTestNotOk4), cause: idpCert is mandatory for SAML.`,
          expect.anything(),
        );
    });

    it('should not add new SAML provider if mandatory issuer config is not given', async () => {
      const logAppErrorSpy = vi.spyOn(logApp, 'error');
      const input: SingleSignOnAddInput = {
        name: 'Saml for test domain issuer missing',
        strategy: AuthenticationProviderType.Saml,
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
          `[Auth][Not provided]Error when initializing an authentication provider (id: ${samlEntity.id}, identifier: samlTestNotOk5), cause: issuer is mandatory for SAML.`,
          expect.anything(),
        );
    });
  });
  describe('OpenID coverage tests', () => {
    afterAll(async () => {
      const allSso = await findAllAuthenticationProvider(testContext, ADMIN_USER);
      for (let i = 0; i < allSso.length; i++) {
        if (allSso[i].identifier?.startsWith('openidTest')) {
          await deleteSingleSignOn(testContext, ADMIN_USER, allSso[i].id);
        }
      }
    });

    it('should add new minimal OpenID provider', async () => {
      const input: SingleSignOnAddInput = {
        name: 'OpenID for test domain',
        strategy: AuthenticationProviderType.Oidc,
        identifier: 'openidTestDomain',
        enabled: false,
        label: 'Nice OIC button',
        configuration: [
          { key: 'redirect_uri', value: 'http://fake.invalid', type: 'string' },
          { key: 'client_secret', value: 'graceHopper', type: 'string' },
          { key: 'client_id', value: 'myoicclient', type: 'string' },
          { key: 'issuer', value: 'https://issuer.example.net', type: 'string' },
        ],
      };
      const oicEntity = await addSingleSignOn(testContext, ADMIN_USER, input);

      expect(oicEntity.identifier).toBe('openidTestDomain');
      expect(oicEntity.enabled).toBe(false);
      expect(oicEntity.label).toBe('Nice OIC button');

      const client_id: ConfigEntry = oicEntity.configuration?.find((config) => config.key === 'client_id') as ConfigEntry;
      expect(client_id.value).toBe('myoicclient');
    });

    it('should missing redirect_uri throw error', async () => {
      const logAppErrorSpy = vi.spyOn(logApp, 'error');
      const input: SingleSignOnAddInput = {
        name: 'OpenID for test domain no redirect_uri',
        strategy: AuthenticationProviderType.Oidc,
        identifier: 'openidTestKo1',
        enabled: true,
        label: 'Nice OIC button',
        configuration: [
          { key: 'client_secret', value: 'graceHopper', type: 'string' },
          { key: 'client_id', value: 'myoicclient', type: 'string' },
          { key: 'issuer', value: 'https://issuer.example.net', type: 'string' },
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
          `[Auth][Not provided]Error when initializing an authentication provider (id: ${oicEntity.id}, identifier: openidTestKo1), cause: redirect_uri is mandatory for OpenID.`,
          expect.anything(),
        );
    });

    it('should missing client_id throw error', async () => {
      const logAppErrorSpy = vi.spyOn(logApp, 'error');
      const input: SingleSignOnAddInput = {
        name: 'OpenID for test domain no client_id',
        strategy: AuthenticationProviderType.Oidc,
        identifier: 'openidTestKo2',
        enabled: true,
        label: 'Nice OIC button',
        configuration: [
          { key: 'redirect_uri', value: 'http://fake.invalid', type: 'string' },
          { key: 'client_secret', value: 'graceHopper', type: 'string' },
          { key: 'issuer', value: 'https://issuer.example.net', type: 'string' },
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
          `[Auth][Not provided]Error when initializing an authentication provider (id: ${oicEntity.id}, identifier: openidTestKo2), cause: client_id is mandatory for OpenID.`,
          expect.anything(),
        );
    });

    it('should missing issuer throw error', async () => {
      const logAppErrorSpy = vi.spyOn(logApp, 'error');
      const input: SingleSignOnAddInput = {
        name: 'OpenID for test domain no issuer',
        strategy: AuthenticationProviderType.Oidc,
        identifier: 'openidTestKo3',
        enabled: true,
        label: 'Nice OIC button',
        configuration: [
          { key: 'redirect_uri', value: 'http://fake.invalid', type: 'string' },
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
          `[Auth][Not provided]Error when initializing an authentication provider (id: ${oicEntity.id}, identifier: openidTestKo3), cause: issuer is mandatory for OpenID.`,
          expect.anything(),
        );
    });

    it('should missing client_secret throw error', async () => {
      const logAppErrorSpy = vi.spyOn(logApp, 'error');
      const input: SingleSignOnAddInput = {
        name: 'OpenID for test domain no client_secret',
        strategy: AuthenticationProviderType.Oidc,
        identifier: 'openidTestKo4',
        enabled: true,
        label: 'Nice OIC button',
        configuration: [
          { key: 'redirect_uri', value: 'http://fake.invalid', type: 'string' },
          { key: 'client_id', value: 'myoicclient', type: 'string' },
          { key: 'issuer', value: 'https://issuer.example.net', type: 'string' },
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
          `[Auth][Not provided]Error when initializing an authentication provider (id: ${oicEntity.id}, identifier: openidTestKo4), cause: client_secret is mandatory for OpenID.`,
          expect.anything(),
        );
    });
  });
  describe('LDAP coverage tests', () => {
    afterAll(async () => {
      const allSso = await findAllAuthenticationProvider(testContext, ADMIN_USER);
      for (let i = 0; i < allSso.length; i++) {
        if (allSso[i].identifier?.startsWith('ldapTest')) {
          await deleteSingleSignOn(testContext, ADMIN_USER, allSso[i].id);
        }
      }
    });

    it('should add new minimal LDAP provider', async () => {
      const input: SingleSignOnAddInput = {
        name: 'LDAP for test domain',
        strategy: AuthenticationProviderType.Ldap,
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
      const configUrl = ldapEntity.configuration?.find((config) => config.key === 'url') as ConfigEntry;
      expect(configUrl.value).toBe('ldap://localhost:389');

      // Here there is a pub/sub on redis, let's just call the same method as listener
      await onAuthenticationMessageAdd({ instance: ldapEntity });
      expect(PROVIDERS.some((strategyProv) => strategyProv.provider === 'ldapTest1')).toBeTruthy();
    });
  });

  describe('Edition locked coverage tests', () => {
    let ssoCreate: BasicStoreEntityAuthenticationProvider;
    vi.spyOn(providerConfig, 'isAuthenticationEditionLocked').mockReturnValue(true);
    const mockDummyUser = getFakeAuthUser('NotAdmin');

    it('should not admin be refused to add SSO', async () => {
      const input: SingleSignOnAddInput = {
        name: 'LDAP for test NotAdmin',
        strategy: AuthenticationProviderType.Ldap,
        identifier: 'ldapTestNotAdmin',
        enabled: true,
        configuration: [
          { key: 'url', type: 'string', value: 'ldap://localhost:389' },
          { key: 'bindDN', type: 'string', value: 'cn=admin,dc=example,dc=org' },
          { key: 'bindCredentials', type: 'string', value: 'youShallNotPass' },
          { key: 'searchBase', type: 'string', value: 'dc=example,dc=org' },
          { key: 'searchFilter', type: 'string', value: 'mail={{username}}' },
        ],
      };

      // Any user should be refused
      await expect(async () => {
        await addSingleSignOn(testContext, mockDummyUser, input);
      }).rejects.toThrowError('Authentication edition is locked by environment variable');

      // But config admin can still do
      ssoCreate = await addSingleSignOn(testContext, ADMIN_USER, input);
      expect(ssoCreate.identifier).toBe('ldapTestNotAdmin');
    });

    it('should not admin be refused to fieldPatch SSO', async () => {
      // Any user should be refused
      await expect(async () => {
        await editSingleSignOn(testContext, mockDummyUser, ssoCreate.id, { label: 'hacked' });
      }).rejects.toThrowError('Authentication edition is locked by environment variable');

      // But config admin can still do
      const patched = await editSingleSignOn(testContext, ADMIN_USER, ssoCreate.id, { label: 'notHacked' });
      expect(patched.label).toBe('notHacked');
      // expect no error
    });

    it('should not admin be refused to delete SSO', async () => {
      // Any user should be refused
      await expect(async () => {
        await deleteSingleSignOn(testContext, mockDummyUser, ssoCreate.id);
      }).rejects.toThrowError('Authentication edition is locked by environment variable');

      // But config admin can still do
      await deleteSingleSignOn(testContext, ADMIN_USER, ssoCreate.id);
      // expect no error
    });
  });
});
