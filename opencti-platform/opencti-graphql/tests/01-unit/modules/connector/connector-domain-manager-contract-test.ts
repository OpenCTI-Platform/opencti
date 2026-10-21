import { describe, expect, it, vi } from 'vitest';
import { logApp } from '../../../../src/config/conf';
import { FunctionalError } from '../../../../src/config/errors';
import type { AuthContext, AuthUser } from '../../../../src/types/user';
import type { BasicStoreEntityConnector } from '../../../../src/modules/connector/connector-types';

const { mockRedisGetConnectorLogs, mockRedisGetConnectorHealthMetrics } = vi.hoisted(() => ({
  mockRedisGetConnectorLogs: vi.fn(),
  mockRedisGetConnectorHealthMetrics: vi.fn(),
}));

vi.mock('../../../../src/modules/connector/connector-redis', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/modules/connector/connector-redis')>()),
  redisGetConnectorLogs: mockRedisGetConnectorLogs,
  redisGetConnectorHealthMetrics: mockRedisGetConnectorHealthMetrics,
}));

import {
  computeConnectorContractConfiguration,
  computeConnectorContractHash,
  computeConnectorContractImage,
  computeConnectorCurrentStatus,
  computeConnectorHealthMetrics,
  computeConnectorLogs,
  computeConnectorRequestedStatus,
  computeConnectorUptime,
  computeManagedConnectorContractConfiguration,
  computeManagedConnectorContractHash,
  computeManagedConnectorContractImage,
  computeManagedConnectorCurrentStatus,
  computeManagedConnectorHealthMetrics,
  computeManagedConnectorLogs,
  computeManagedConnectorRequestedStatus,
  computeManagedConnectorUptime,
  computeManagerConnectorContract,
  computeManagerConnectorExcerpt,
  computeManagerConnectorImage,
} from '../../../../src/modules/connector/connector-domain';

const context = {} as AuthContext;
const user = { id: 'user-1' } as AuthUser;

// Only the fields read by the tested functions
const asConnector = (fields: Partial<BasicStoreEntityConnector>) => fields as BasicStoreEntityConnector;

const connectorWithContract = () => asConnector({
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
    solution_categories: [],
  },
});

describe('repository manager contract helpers', () => {
  it('should return null contract and excerpt when manager contract is absent', async () => {
    const connector = asConnector({ id: 'connector-1', internal_id: 'connector-1' });
    await expect(computeManagerConnectorContract(context, user, connector)).resolves.toBeNull();
    await expect(computeManagerConnectorExcerpt(context, user, connector)).resolves.toBeNull();
  });

  it('should compute manager contract JSON from embedded contract snapshot', async () => {
    const contract = await computeManagerConnectorContract(context, user, connectorWithContract());
    expect(contract).not.toBeNull();
    const parsed = JSON.parse(contract!);
    expect(parsed.slug).toBe('ipinfo');
    expect(parsed.container_image).toBe('opencti/connector-ipinfo');
    expect(parsed.container_version).toBe('1.2.3');
  });

  it('should compute manager contract excerpt from embedded contract snapshot', async () => {
    const excerpt = await computeManagerConnectorExcerpt(context, user, connectorWithContract());
    expect(excerpt).toEqual({
      title: 'IPinfo',
      slug: 'ipinfo',
      logo: '/storage/view/catalog-logos/logo.png',
    });
  });

  it('should compute manager connector image from embedded contract snapshot', async () => {
    const image = await computeManagerConnectorImage(connectorWithContract());
    expect(image).toBe('opencti/connector-ipinfo:1.2.3');
  });

  it('should throw FunctionalError when a managed connector has no contract snapshot', async () => {
    const connector = asConnector({ id: 'connector-1', internal_id: 'connector-1', catalog_id: 'ipinfo' });
    await expect(computeManagerConnectorImage(connector)).rejects.toThrowError(FunctionalError('Missing manager contract snapshot').message);
  });

  it('should throw FunctionalError on invalid contract snapshot', async () => {
    const { manager_contract, ...connectorFields } = connectorWithContract();
    const connector = asConnector({ ...connectorFields, manager_contract: manager_contract && { ...manager_contract, image: '' } });
    await expect(computeManagerConnectorImage(connector)).rejects.toThrowError(FunctionalError('Invalid manager contract snapshot').message);
  });
});

describe('manager fields', () => {
  const notManagedConnector = asConnector({ id: 'connector-1', internal_id: 'connector-1', manager_current_status: 'started', manager_requested_status: 'started' });
  const managedConnector = asConnector({ ...connectorWithContract(), catalog_id: 'catalog-1', manager_current_status: 'started', manager_requested_status: 'stopped' });

  it.each([
    ['manager_current_status', computeConnectorCurrentStatus, computeManagedConnectorCurrentStatus],
    ['manager_requested_status', computeConnectorRequestedStatus, computeManagedConnectorRequestedStatus],
    ['manager_contract_image', computeConnectorContractImage, computeManagedConnectorContractImage],
    ['manager_contract_configuration', (cn: BasicStoreEntityConnector) => computeConnectorContractConfiguration(context, user, cn), (cn: BasicStoreEntityConnector) => computeManagedConnectorContractConfiguration(context, user, cn)],
    ['manager_contract_hash', (cn: BasicStoreEntityConnector) => computeConnectorContractHash(context, user, cn), (cn: BasicStoreEntityConnector) => computeManagedConnectorContractHash(context, user, cn)],
    ['manager_connector_logs', computeConnectorLogs, computeManagedConnectorLogs],
    ['manager_health_metrics', (cn: BasicStoreEntityConnector) => computeConnectorHealthMetrics(context, user, cn), (cn: BasicStoreEntityConnector) => computeManagedConnectorHealthMetrics(context, user, cn)],
    ['manager_connector_uptime', (cn: BasicStoreEntityConnector) => computeConnectorUptime(context, user, cn), (cn: BasicStoreEntityConnector) => computeManagedConnectorUptime(context, user, cn)],
  ])('should resolve %s to null on Connector and throw on ManagedConnector for a connector that is not managed', async (_field, onConnector, onManagedConnector) => {
    await expect(onConnector(notManagedConnector)).resolves.toBeNull();
    await expect(onManagedConnector(notManagedConnector)).rejects.toThrowError(FunctionalError('Connector is not managed').message);
    expect(mockRedisGetConnectorLogs).not.toHaveBeenCalled();
    expect(mockRedisGetConnectorHealthMetrics).not.toHaveBeenCalled();
  });

  it('should resolve the statuses of a managed connector on both types', async () => {
    await expect(computeConnectorCurrentStatus(managedConnector)).resolves.toBe('started');
    await expect(computeManagedConnectorCurrentStatus(managedConnector)).resolves.toBe('started');
    await expect(computeConnectorRequestedStatus(managedConnector)).resolves.toBe('stopped');
    await expect(computeManagedConnectorRequestedStatus(managedConnector)).resolves.toBe('stopped');
  });

  it('should throw on ManagedConnector for a managed connector without requested status', async () => {
    const connector = asConnector({ id: 'connector-1', internal_id: 'connector-1', catalog_id: 'catalog-1' });
    await expect(computeConnectorRequestedStatus(connector)).resolves.toBeUndefined();
    await expect(computeManagedConnectorRequestedStatus(connector)).rejects.toThrowError(FunctionalError('Missing manager requested status').message);
  });

  it('should resolve the logs and health of a managed connector on both types', async () => {
    mockRedisGetConnectorLogs.mockResolvedValue(['log line']);
    mockRedisGetConnectorHealthMetrics.mockResolvedValue({ restart_count: 0, started_at: 'not-a-date' });
    await expect(computeConnectorLogs(managedConnector)).resolves.toEqual(['log line']);
    await expect(computeManagedConnectorLogs(managedConnector)).resolves.toEqual(['log line']);
    expect(mockRedisGetConnectorLogs).toHaveBeenCalledWith('connector-1');
    await expect(computeConnectorHealthMetrics(context, user, managedConnector)).resolves.toEqual({ restart_count: 0, started_at: 'not-a-date' });
    await expect(computeManagedConnectorHealthMetrics(context, user, managedConnector)).resolves.toEqual({ restart_count: 0, started_at: 'not-a-date' });
    await expect(computeConnectorUptime(context, user, managedConnector)).resolves.toBeNull();
    await expect(computeManagedConnectorUptime(context, user, managedConnector)).resolves.toBeNull();
  });

  it('should compute the image of a managed connector from its contract snapshot on both types', async () => {
    await expect(computeConnectorContractImage(managedConnector)).resolves.toBe('opencti/connector-ipinfo:1.2.3');
    await expect(computeManagedConnectorContractImage(managedConnector)).resolves.toBe('opencti/connector-ipinfo:1.2.3');
  });

  it('should resolve the image of a managed connector without contract snapshot to null with an error log on Connector, and throw on ManagedConnector', async () => {
    const logError = vi.spyOn(logApp, 'error').mockImplementation(() => {});
    const connector = asConnector({ id: 'connector-1', internal_id: 'connector-1', catalog_id: 'ipinfo' });
    await expect(computeConnectorContractImage(connector)).resolves.toBeNull();
    expect(logError).toHaveBeenCalledWith('[OPENCTI-MODULE] Managed connector without contract snapshot', {
      module: 'connector',
      connectorId: 'connector-1',
      catalogId: 'ipinfo',
    });
    logError.mockRestore();
    await expect(computeManagedConnectorContractImage(connector)).rejects.toThrowError(FunctionalError('Missing manager contract snapshot').message);
  });
});
