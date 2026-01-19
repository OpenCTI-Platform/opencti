import { describe, expect, it, vi } from 'vitest';
import { addSingleSignOn, deleteSingleSignOn, findAllSingleSignOn } from '../../../src/modules/singleSignOn/singleSignOn-domain';
import { ADMIN_USER, testContext } from '../../utils/testQuery';
import { type SingleSignOnAddInput, StrategyType } from '../../../src/generated/graphql';
import { PROVIDERS } from '../../../src/config/providers-configuration';
import { convertStoreToStix_2_1 } from '../../../src/database/stix-2-1-converter';
import type { StixSingleSignOn, StoreEntitySingleSignOn } from '../../../src/modules/singleSignOn/singleSignOn-types';
import { v4 as uuid } from 'uuid';
import { logApp } from '../../../src/config/conf';
import { registerStrategy } from '../../../src/modules/singleSignOn/singleSignOn-providers';

describe('Single sign on Domain coverage tests', () => {
  describe('SAML coverage tests', () => {
    let createdSamlId: string;
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
      createdSamlId = samlEntity.id;

      expect(samlEntity.identifier).toBe('samlTestDomain');
      expect(samlEntity.enabled).toBe(true);
      expect(samlEntity.label).toBe('Nice SAML button');

      // Here there is a pub/sub on redis, let's just call the same method than listener
      await registerStrategy(samlEntity);
      expect(PROVIDERS.some((strategyProv) => strategyProv.provider === 'samlTestDomain')).toBeTruthy();
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

      // Here there is a pub/sub on redis, let's just call the same method than listener
      await registerStrategy(samlEntity);

      expect(PROVIDERS.some((strategyProv) => strategyProv.provider === 'samlTestNotOk')).toBeFalsy();
      expect(logAppErrorSpy, 'No exception should be throw, but an error message should be present')
        .toHaveBeenCalledWith(
          '[Auth][Not provided]Error when initializing an authentication provider samlTestNotOk, cause: SSO configuration is empty',
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

      // Here there is a pub/sub on redis, let's just call the same method than listener
      await registerStrategy(samlEntity);

      expect(PROVIDERS.some((strategyProv) => strategyProv.provider === 'samlTestNotOk2')).toBeFalsy();
      expect(logAppErrorSpy, 'No exception should be throw, but an error message should be present')
        .toHaveBeenCalledWith(
          '[Auth][Not provided]Error when initializing an authentication provider samlTestNotOk2, cause: callbackUrl is mandatory for SAML',
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

      // Here there is a pub/sub on redis, let's just call the same method than listener
      await registerStrategy(samlEntity);

      expect(PROVIDERS.some((strategyProv) => strategyProv.provider === 'samlTestNotOk4')).toBeFalsy();
      expect(logAppErrorSpy, 'No exception should be throw, but an error message should be present')
        .toHaveBeenCalledWith(
          '[Auth][Not provided]Error when initializing an authentication provider samlTestNotOk4, cause: idpCert is mandatory for SAML',
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

      // Here there is a pub/sub on redis, let's just call the same method than listener
      await registerStrategy(samlEntity);

      expect(PROVIDERS.some((strategyProv) => strategyProv.provider === 'samlTestNotOk5')).toBeFalsy();
      expect(logAppErrorSpy, 'No exception should be throw, but an error message should be present')
        .toHaveBeenCalledWith(
          '[Auth][Not provided]Error when initializing an authentication provider samlTestNotOk5, cause: issuer is mandatory for SAML',
          expect.anything(),
        );
    });

    it('should remove SAML provider created', async () => {
      await deleteSingleSignOn(testContext, ADMIN_USER, createdSamlId);

      const allSso = await findAllSingleSignOn(testContext, ADMIN_USER);
      for (let i = 0; i < allSso.length; i++) {
        if (allSso[i].identifier !== 'samlTestNotOk') {
          await deleteSingleSignOn(testContext, ADMIN_USER, allSso[i].id);
        }
      }
    });
  });
  describe('OpenID coverage tests', () => {
    let createdOpenIdId: string;

    it('should add new minimal OpenID provider', async () => {
      const input: SingleSignOnAddInput = {
        name: 'OpenID for test domain',
        strategy: StrategyType.OpenIdConnectStrategy,
        identifier: 'oicTestDomain',
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
      createdOpenIdId = oicEntity.id;

      expect(oicEntity.identifier).toBe('oicTestDomain');
      expect(oicEntity.enabled).toBe(false);
      expect(oicEntity.label).toBe('Nice OIC button');
    });

    it('should remove OpenID provider created', async () => {
      await deleteSingleSignOn(testContext, ADMIN_USER, createdOpenIdId);
    });
  });

  describe('stix coverage tests', () => {
    it.todo('should convert to 2.1 stix', async () => {
      const id = uuid();

      const ssoEntity: Partial<StoreEntitySingleSignOn> = {
        identifier: 'stixIdentifier',
        id,
        label: 'stix sso button',
      };

      const stixSso: StixSingleSignOn = convertStoreToStix_2_1(ssoEntity as StoreEntitySingleSignOn) as StixSingleSignOn;
      expect(stixSso.identifier).toBe('stixIdentifier');
      expect(stixSso.id).toBe(id);
      expect(stixSso.label).toBe('stix sso button');
    });
  });
});
