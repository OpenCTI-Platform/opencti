import { describe, expect, it } from 'vitest';
import { addSingleSignOn, deleteSingleSignOn, findAllSingleSignOn } from '../../../src/modules/singleSignOn/singleSignOn-domain';
import { ADMIN_USER, testContext } from '../../utils/testQuery';
import { type SingleSignOnAddInput, StrategyType } from '../../../src/generated/graphql';
import { PROVIDERS } from '../../../src/config/providers-configuration';
import { convertStoreToStix_2_1 } from '../../../src/database/stix-2-1-converter';
import type { BasicStoreEntitySingleSignOn, StixSingleSignOn, StoreEntitySingleSignOn } from '../../../src/modules/singleSignOn/singleSignOn-types';
import { v4 as uuid } from 'uuid';

describe('Single sign on Domain coverage tests', () => {
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

    expect(PROVIDERS.some((strategyProv) => strategyProv.provider === 'samlTestDomain')).toBeTruthy();
  });

  it('should not add new SAML provider if no config is given', async () => {
    // For example callbackUrl is mandatory for SAML
    const input: SingleSignOnAddInput = {
      name: 'Saml for test domain callback url missing',
      strategy: StrategyType.SamlStrategy,
      identifier: 'samlTestNotOk',
      enabled: true,
      label: 'Nice SAML button',
    };
    await expect(() => addSingleSignOn(testContext, ADMIN_USER, input))
      .rejects.toThrowError('SSO configuration is empty');

    expect(PROVIDERS.some((strategyProv) => strategyProv.provider === 'samlTestNotOk')).toBeFalsy();
  });

  it('should not add new SAML provider if mandatory callbackUrl config is not given', async () => {
    // For example callbackUrl is mandatory for SAML
    const input: SingleSignOnAddInput = {
      name: 'Saml for test domain callback url missing',
      strategy: StrategyType.SamlStrategy,
      identifier: 'samlTestNotOk',
      enabled: true,
      label: 'Nice SAML button',
      configuration: [{ key: 'idpCert', value: 'mszfrhazmfghqzefh', type: 'string' }],
    };
    await expect(() => addSingleSignOn(testContext, ADMIN_USER, input))
      .rejects.toThrowError('callbackUrl is mandatory for SAML');

    expect(PROVIDERS.some((strategyProv) => strategyProv.provider === 'samlTestNotOk')).toBeFalsy();
  });

  it('should not add new SAML provider if mandatory callbackUrl config is not given', async () => {
    const input: SingleSignOnAddInput = {
      name: 'Saml for test domain callbackUrl missing',
      strategy: StrategyType.SamlStrategy,
      identifier: 'samlTestNotOk',
      enabled: true,
      label: 'Nice SAML button',
      configuration: [{ key: 'idpCert', value: 'mszfrhazmfghqzefh', type: 'string' }],
    };
    await expect(() => addSingleSignOn(testContext, ADMIN_USER, input))
      .rejects.toThrowError('callbackUrl is mandatory for SAML');

    expect(PROVIDERS.some((strategyProv) => strategyProv.provider === 'samlTestNotOk')).toBeFalsy();
  });

  it('should not add new SAML provider if mandatory idpCert config is not given', async () => {
    const input: SingleSignOnAddInput = {
      name: 'Saml for test domain idpCert url missing',
      strategy: StrategyType.SamlStrategy,
      identifier: 'samlTestNotOk',
      enabled: true,
      label: 'Nice SAML button',
      configuration: [{ key: 'callbackUrl', value: 'http://opencti/saml', type: 'string' }],
    };
    await expect(() => addSingleSignOn(testContext, ADMIN_USER, input))
      .rejects.toThrowError('idpCert is mandatory for SAML');

    expect(PROVIDERS.some((strategyProv) => strategyProv.provider === 'samlTestNotOk')).toBeFalsy();
  });

  it('should not add new SAML provider if mandatory issuer config is not given', async () => {
    const input: SingleSignOnAddInput = {
      name: 'Saml for test domain issuer missing',
      strategy: StrategyType.SamlStrategy,
      identifier: 'samlTestNotOk',
      enabled: true,
      label: 'Nice SAML button',
      configuration: [
        { key: 'idpCert', value: 'mszfrhazmfghqzefh', type: 'string' },
        { key: 'callbackUrl', value: 'http://opencti/saml', type: 'string' }],
    };
    await expect(() => addSingleSignOn(testContext, ADMIN_USER, input))
      .rejects.toThrowError('issuer is mandatory for SAML');

    expect(PROVIDERS.some((strategyProv) => strategyProv.provider === 'samlTestNotOk')).toBeFalsy();
  });

  it('should remove SAML provider created', async () => {
    await deleteSingleSignOn(testContext, ADMIN_USER, createdSamlId);

    const allSso = await findAllSingleSignOn(testContext, ADMIN_USER);
    for (let i = 0; i < allSso.length; i++) {
      if (allSso[i].identifier === 'samlTestNotOk') {
        await deleteSingleSignOn(testContext, ADMIN_USER, allSso[i].id);
      }
    }
  });

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
