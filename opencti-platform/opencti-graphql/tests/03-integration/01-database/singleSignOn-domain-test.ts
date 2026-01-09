import { describe, expect, it } from 'vitest';
import { addSingleSignOn } from '../../../src/modules/singleSignOn/singleSignOn-domain';
import { ADMIN_USER, testContext } from '../../utils/testQuery';
import { type SingleSignOnAddInput, StrategyType } from '../../../src/generated/graphql';
import { PROVIDERS } from '../../../src/config/providers-configuration';

describe('Single sign on Domain coverage tests', () => {
  let createdSamlId;

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
});
