import { describe, expect, it } from 'vitest';
import { maskEncryptedConfigurationKeys } from '../../../../src/modules/authenticationProvider/authenticationProvider-domain';
import type { BasicStoreEntityAuthenticationProvider } from '../../../../src/modules/authenticationProvider/authenticationProvider-types';

describe('excludeEncryptedConfigurationKeys tests', () => {
  it('should not return encrypted values', async () => {
    const sso = {
      name: 'name',
      configuration: [
        { key: 'privateKey', value: 'issuer', type: 'secret' },
        { key: 'issuer', value: 'issuer', type: 'string' },
        { key: 'newKey', value: 'newKey', type: 'string' },
      ],
    } as BasicStoreEntityAuthenticationProvider;
    const configuration = maskEncryptedConfigurationKeys(sso);
    expect(configuration).not.toContainEqual({ key: 'privateKey' });
    expect(configuration).toStrictEqual([
      { key: 'privateKey', value: '******', type: 'secret' },
      { key: 'issuer', value: 'issuer', type: 'string' },
      { key: 'newKey', value: 'newKey', type: 'string' },
    ]);
  });
});
