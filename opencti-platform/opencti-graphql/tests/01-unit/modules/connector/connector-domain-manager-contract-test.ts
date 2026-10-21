import { describe, expect, it, vi } from 'vitest';
import { logApp } from '../../../../src/config/conf';
import { FunctionalError } from '../../../../src/config/errors';
import {
  computeConnectorImage,
  computeManagerConnectorContract,
  computeManagerConnectorExcerpt,
  computeManagerConnectorImage,
} from '../../../../src/modules/connector/connector-domain';

const connectorWithContract = () => ({
  id: 'connector-1',
  internal_id: 'connector-1',
  manager_contract: {
    catalog_id: 'catalog-1',
    contract_id: 'ipinfo-1.2.3',
    content_hash: 'hash-1',
    title: 'IPinfo',
    slug: 'ipinfo',
    description: 'desc',
    short_description: 'short',
    logo_uri: '/storage/view/catalog-logos/logo.png',
    use_cases: [],
    verified: true,
    last_verified_date: '2024-01-01',
    playbook_supported: false,
    max_confidence_level: 50,
    support_version: '6.7.0',
    subscription_link: null,
    source_code: '',
    manager_supported: true,
    contract_version: '1.2.3',
    image: 'opencti/connector-ipinfo',
    connector_type: 'EXTERNAL_IMPORT',
    config_schema: {
      $schema: 'https://json-schema.org/draft/2020-12/schema',
      $id: 'schema-id',
      type: 'object',
      properties: {},
      required: [],
      additionalProperties: true,
    },
    license_type: null,
    solution_categories: [],
    contact: null,
  },
});

describe('repository manager contract helpers', () => {
  it('should return null contract and excerpt when manager contract is absent', async () => {
    const connector = { id: 'connector-1', internal_id: 'connector-1' };
    await expect(computeManagerConnectorContract({} as any, {} as any, connector as any)).resolves.toBeNull();
    await expect(computeManagerConnectorExcerpt({} as any, {} as any, connector as any)).resolves.toBeNull();
  });

  it('should compute manager contract JSON from embedded contract snapshot', async () => {
    const contract = await computeManagerConnectorContract({} as any, {} as any, connectorWithContract() as any);
    expect(contract).not.toBeNull();
    const parsed = JSON.parse(contract!);
    expect(parsed.slug).toBe('ipinfo');
    expect(parsed.container_image).toBe('opencti/connector-ipinfo');
    expect(parsed.container_version).toBe('1.2.3');
  });

  it('should compute manager contract excerpt from embedded contract snapshot', async () => {
    const excerpt = await computeManagerConnectorExcerpt({} as any, {} as any, connectorWithContract() as any);
    expect(excerpt).toEqual({
      title: 'IPinfo',
      slug: 'ipinfo',
      logo: '/storage/view/catalog-logos/logo.png',
    });
  });

  it('should compute manager connector image from embedded contract snapshot', async () => {
    const image = await computeManagerConnectorImage(connectorWithContract() as any);
    expect(image).toBe('opencti/connector-ipinfo:1.2.3');
  });

  it('should throw FunctionalError when a managed connector has no contract snapshot', async () => {
    const connector = { id: 'connector-1', internal_id: 'connector-1', catalog_id: 'ipinfo' };
    await expect(computeManagerConnectorImage(connector as any)).rejects.toThrowError(FunctionalError('Missing manager contract snapshot').message);
  });

  it('should throw FunctionalError on invalid contract snapshot', async () => {
    const connector = connectorWithContract();
    delete (connector.manager_contract as any).image;
    await expect(computeManagerConnectorImage(connector as any)).rejects.toThrowError(FunctionalError('Invalid manager contract snapshot').message);
  });
});

describe('connectors lists image', () => {
  it('should return a null image for a connector that is not managed', async () => {
    const connector = { id: 'connector-1', internal_id: 'connector-1' };
    await expect(computeConnectorImage(connector as any)).resolves.toBeNull();
  });

  it('should return a null image and log an error for a managed connector without contract snapshot', async () => {
    const logError = vi.spyOn(logApp, 'error').mockImplementation(() => {});
    const connector = { id: 'connector-1', internal_id: 'connector-1', catalog_id: 'ipinfo' };
    await expect(computeConnectorImage(connector as any)).resolves.toBeNull();
    expect(logError).toHaveBeenCalledWith('[OPENCTI-MODULE] Managed connector without contract snapshot', {
      module: 'connector',
      connectorId: 'connector-1',
      catalogId: 'ipinfo',
    });
    logError.mockRestore();
  });

  it('should compute the image of a managed connector from its contract snapshot', async () => {
    const connector = { ...connectorWithContract(), catalog_id: 'catalog-1' };
    await expect(computeConnectorImage(connector as any)).resolves.toBe('opencti/connector-ipinfo:1.2.3');
  });
});
