import { describe, expect, it } from 'vitest';
import { excludeEncryptedConfigurationKeys } from '../../../../src/modules/singleSignOn/singleSignOn-domain';
import type { BasicStoreEntitySingleSignOn } from '../../../../src/modules/singleSignOn/singleSignOn-types';

describe('excludeEncryptedConfigurationKeys tests', () => {
  it('should not return encrypted values', async () => {
    const sso = {
      name: 'name',
      configuration: [
        { key: 'privateKey', value: 'issuer', type: 'encrypted' },
        { key: 'issuer', value: 'issuer', type: 'string' },
        { key: 'newKey', value: 'newKey', type: 'string' },
      ],
    } as BasicStoreEntitySingleSignOn;
    const configuration = excludeEncryptedConfigurationKeys(sso);
    expect(configuration).not.toContainEqual({ key: 'privateKey' });
    expect(configuration).toStrictEqual([
      { key: 'issuer', value: 'issuer', type: 'string' },
      { key: 'newKey', value: 'newKey', type: 'string' },
    ]);
  });
});
