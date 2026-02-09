import { describe, it, expect } from 'vitest';
import { ConfigTypeArray, getAdvancedConfigFromData, getConfigFromData } from '@components/settings/sso_definitions/utils/getConfigAndAdvancedConfigFromData';

describe('Function: getAdvancedConfigFromData', () => {
  it('should SAML advanced config works', () => {
    const inputConfig: ConfigTypeArray = [
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
      {
        key: 'privateKey',
        value: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
        type: 'encrypted',
      },
      {
        key: 'myCustomSecret',
        value: 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
        type: 'encrypted',
      },
    ];

    const resultAdvanced = getAdvancedConfigFromData(inputConfig, 'SamlStrategy');
    const resultPredefined = getConfigFromData(inputConfig, 'SamlStrategy');

    // Everything should be filter out except acceptedClockSkewMs & myCustomSecret
    expect(resultAdvanced).toStrictEqual([{
      key: 'acceptedClockSkewMs',
      type: 'number',
      value: '3',
    },
    {
      key: 'myCustomSecret',
      value: '******',
      type: 'secret',
    }]);

    expect(resultPredefined).toStrictEqual([
      {
        key: 'issuer',
        type: 'string',
        value: 'openctisaml',
      },
      {
        key: 'entryPoint',
        type: 'string',
        value: 'http://localhost:9999/realms/master/protocol/saml',
      },
      {
        key: 'callbackUrl',
        type: 'string',
        value: 'http://localhost:4000/auth/saml/callback',
      },
      {
        key: 'idpCert',
        type: 'string',
        value: 'MIICmzCxxxxuJ1ZY=',
      },
      {
        key: 'wantAuthnResponseSigned',
        type: 'boolean',
        value: 'false',
      },
      {
        key: 'privateKey',
        type: 'encrypted',
        value: 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
      },
    ]);

    // All data should be there
    expect(resultPredefined.length + resultAdvanced.length).toBe(inputConfig.length);
  });

  it('should empty config be fine', () => {
    const result = getAdvancedConfigFromData([], 'SamlStrategy');
    expect(result).toStrictEqual([]);
  });

  it('should wrong strategy be ok', () => {
    const result = getAdvancedConfigFromData([], 'PirouetteStrategy');
    expect(result).toStrictEqual([]);
  });
});
