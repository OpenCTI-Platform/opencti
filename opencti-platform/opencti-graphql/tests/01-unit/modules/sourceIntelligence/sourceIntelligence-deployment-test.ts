import { describe, expect, it } from 'vitest';
import { requiredSettingsOfContract } from '../../../../src/modules/sourceIntelligence/sourceIntelligence-deployment';
import type { CatalogContract } from '../../../../src/modules/catalog/catalog-types';

const schema = (properties: Record<string, unknown>, required: string[]) => ({ type: 'object', properties, required }) as unknown as CatalogContract['config_schema'];

describe('Source intelligence one-click deployment settings', () => {
  it('should ask for the required settings without a default value, a secret masked', () => {
    const settings = requiredSettingsOfContract(schema({
      MISP_URL: { type: 'string', title: 'MISP URL', description: 'Address of the MISP instance' },
      MISP_KEY: { type: 'string', format: 'password', description: 'API key of a MISP user' },
      MISP_SSL_VERIFY: { type: ['boolean', 'null'], title: 'Verify the certificate' },
      MISP_INTERVAL: { type: 'integer', default: 5 },
      MISP_OPTIONAL: { type: 'string' },
    }, ['MISP_URL', 'MISP_KEY', 'MISP_SSL_VERIFY', 'MISP_INTERVAL']));

    expect(settings).toEqual([
      { key: 'MISP_URL', label: 'MISP URL', description: 'Address of the MISP instance', type: 'string', secret: false },
      { key: 'MISP_KEY', label: 'MISP_KEY', description: 'API key of a MISP user', type: 'string', secret: true },
      { key: 'MISP_SSL_VERIFY', label: 'Verify the certificate', description: null, type: 'boolean', secret: false },
    ]);
  });

  it('should leave out what the deployment provides, the runtime variables and the deprecated settings', () => {
    const settings = requiredSettingsOfContract(schema({
      CONNECTOR_NAME: { type: 'string' },
      CONNECTOR_ID: { type: 'string' },
      OPENCTI_URL: { type: 'string' },
      OPENCTI_TOKEN: { type: 'string', format: 'password' },
      LEGACY_KEY: { type: 'string', deprecated: true },
      UNDECLARED: undefined,
    }, ['CONNECTOR_NAME', 'CONNECTOR_ID', 'OPENCTI_URL', 'OPENCTI_TOKEN', 'LEGACY_KEY', 'UNDECLARED']));

    expect(settings).toEqual([]);
  });

  it('should ask for nothing when the contract has no schema', () => {
    expect(requiredSettingsOfContract(null)).toEqual([]);
    expect(requiredSettingsOfContract(undefined)).toEqual([]);
  });
});
