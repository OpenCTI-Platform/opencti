import { describe, expect, it } from 'vitest';
import { deploymentConfiguration, requiredSettingsOfContract } from '../../../../src/modules/sourceIntelligence/sourceIntelligence-deployment';
import { computeConnectorTargetContract } from '../../../../src/modules/catalog/catalog-domain';
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

  it('should name the connector in the deployed configuration, so that a contract requiring the name without a default validates', () => {
    const contract = {
      slug: 'misp',
      title: 'MISP',
      config_schema: schema({ CONNECTOR_NAME: { type: 'string' }, MISP_URL: { type: 'string' } }, ['CONNECTOR_NAME', 'MISP_URL']),
    };
    const settings = [{ key: 'MISP_URL', value: 'https://misp.example' }];
    expect(requiredSettingsOfContract(contract.config_schema).map(({ key }) => key)).toEqual(['MISP_URL']);
    expect(() => computeConnectorTargetContract(settings, contract, 'public-key')).toThrow(/Missing required field: "CONNECTOR_NAME"/);

    const configuration = deploymentConfiguration(settings, 'MISP');
    expect(configuration).toEqual([{ key: 'MISP_URL', value: 'https://misp.example' }, { key: 'CONNECTOR_NAME', value: 'MISP' }]);
    expect(computeConnectorTargetContract(configuration, contract, 'public-key')).toEqual(expect.arrayContaining([
      expect.objectContaining({ key: 'CONNECTOR_NAME', value: 'MISP' }),
      expect.objectContaining({ key: 'MISP_URL', value: 'https://misp.example' }),
    ]));
  });

  it('should store an integer setting sent in decimal notation as sent, up to the largest integer the dialog accepts', () => {
    const contract = {
      slug: 'misp',
      title: 'MISP',
      config_schema: schema({ CONNECTOR_NAME: { type: 'string' }, MISP_INTERVAL: { type: 'integer' } }, ['CONNECTOR_NAME', 'MISP_INTERVAL']),
    };
    [String(Number.MAX_SAFE_INTEGER), String(Number.MIN_SAFE_INTEGER), '1000'].forEach((value) => {
      const configuration = deploymentConfiguration([{ key: 'MISP_INTERVAL', value }], 'MISP');
      expect(computeConnectorTargetContract(configuration, contract, 'public-key')).toEqual(expect.arrayContaining([{ key: 'MISP_INTERVAL', value }]));
    });
  });

  it('should keep the name of the deployment over a name given with the settings', () => {
    expect(deploymentConfiguration([{ key: 'CONNECTOR_NAME', value: 'Other' }, { key: 'MISP_KEY', value: 'secret' }], 'MISP')).toEqual([
      { key: 'MISP_KEY', value: 'secret' },
      { key: 'CONNECTOR_NAME', value: 'MISP' },
    ]);
  });
});
