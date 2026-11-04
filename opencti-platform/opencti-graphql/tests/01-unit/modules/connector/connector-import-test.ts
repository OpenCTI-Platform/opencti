import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../../../src/modules/catalog/catalog-repository', () => ({
  findCatalogByCatalogId: vi.fn(),
  findLatestCompatibleCatalogContractByImageName: vi.fn(),
}));
vi.mock('../../../../src/modules/catalog/catalog-domain', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/modules/catalog/catalog-domain')>()),
  computeConnectorTargetContract: vi.fn(),
}));
vi.mock('../../../../src/modules/connector/connector-domain', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/modules/connector/connector-domain')>()),
  managedConnectorAdd: vi.fn(),
  managedConnectorEdit: vi.fn(),
}));
vi.mock('../../../../src/modules/connector/connector-repository', () => ({ findConnectors: vi.fn(), findConnectorManagers: vi.fn() }));
vi.mock('../../../../src/modules/user/user-domain', () => ({ userAlreadyExists: vi.fn() }));

import { findCatalogByCatalogId, findLatestCompatibleCatalogContractByImageName } from '../../../../src/modules/catalog/catalog-repository';
import { computeConnectorTargetContract } from '../../../../src/modules/catalog/catalog-domain';
import { managedConnectorAdd, managedConnectorEdit } from '../../../../src/modules/connector/connector-domain';
import { findConnectorManagers, findConnectors } from '../../../../src/modules/connector/connector-repository';
import { userAlreadyExists } from '../../../../src/modules/user/user-domain';
import { importConnector } from '../../../../src/modules/connector/connector-import';
import { ConfigImportMode } from '../../../../src/modules/configImport/configImport-types';
import type { AuthContext, AuthUser } from '../../../../src/types/user';
import { externalConnector, mitreConnector } from '../configPreset/configPreset-connectors-fixtures';

const context = { source: 'test' } as AuthContext;
const user = { id: 'user-id' } as AuthUser;
const overwrite = { mode: ConfigImportMode.Overwrite };

const connectorConfiguration = (overrides: Record<string, unknown> = {}) => ({
  name: 'MITRE',
  catalog_id: 'filigran-catalog',
  manager_contract_image: 'opencti/connector-mitre',
  confidence_level: 75,
  manager_contract_configuration: [{ key: 'MITRE_INTERVAL', value: '7' }],
  required_at_import: ['MITRE_API_KEY'],
  ...overrides,
});
const contract = { ...mitreConnector.manager_contract, manager_supported: true, slug: 'mitre', title: 'MITRE' };
const withConnectors = (connectors: unknown[]) => vi.mocked(findConnectors).mockResolvedValue(connectors as never);

beforeEach(() => {
  vi.resetAllMocks();
  vi.mocked(findCatalogByCatalogId).mockResolvedValue({ id: 'filigran-catalog' } as never);
  vi.mocked(findLatestCompatibleCatalogContractByImageName).mockResolvedValue(contract as never);
  vi.mocked(findConnectorManagers).mockResolvedValue([{ id: 'manager-id', public_key: 'public-key' }] as never);
  vi.mocked(computeConnectorTargetContract).mockReturnValue([]);
  vi.mocked(userAlreadyExists).mockResolvedValue(false);
  vi.mocked(managedConnectorAdd).mockResolvedValue({ id: 'created-id' } as never);
  vi.mocked(managedConnectorEdit).mockResolvedValue({ id: mitreConnector.id } as never);
  withConnectors([]);
});

const expectNothingWritten = () => {
  expect(managedConnectorAdd).not.toHaveBeenCalled();
  expect(managedConnectorEdit).not.toHaveBeenCalled();
};

describe('importConnector validation', () => {
  it.each([
    ['an unknown key', { connector_state: '{}' }],
    ['no image', { manager_contract_image: '' }],
    ['a confidence over 100', { confidence_level: 101 }],
  ])('refuses %s, without writing', async (_, overrides) => {
    expect(await importConnector(context, user, connectorConfiguration(overrides), overwrite)).toMatchObject({ status: 'failed', code: 'invalid' });
    expectNothingWritten();
  });

  it('fails a connector this platform cannot run, or without a connector manager', async () => {
    vi.mocked(findLatestCompatibleCatalogContractByImageName).mockResolvedValue(undefined as never);
    expect(await importConnector(context, user, connectorConfiguration(), overwrite))
      .toMatchObject({ status: 'failed', code: 'not_available', reason: 'Connector not available on this platform: opencti/connector-mitre' });
    vi.mocked(findLatestCompatibleCatalogContractByImageName).mockResolvedValue(contract as never);
    vi.mocked(findConnectorManagers).mockResolvedValue([]);
    expect(await importConnector(context, user, connectorConfiguration(), overwrite)).toMatchObject({ status: 'failed', code: 'no_manager' });
    expectNothingWritten();
  });

  it('fails with the reason of the contract when the configuration is not valid', async () => {
    vi.mocked(computeConnectorTargetContract).mockImplementation(() => {
      throw new Error('MITRE_INTERVAL must be integer');
    });
    const result = await importConnector(context, user, connectorConfiguration(), { ...overwrite, credentials: { MITRE_API_KEY: 'key' } });
    expect(result).toMatchObject({ status: 'failed', code: 'invalid', reason: 'MITRE_INTERVAL must be integer' });
    expectNothingWritten();
  });
});

describe('importConnector credentials', () => {
  it('fails a connector whose required secret is not given, and lists the secrets it takes', async () => {
    const result = await importConnector(context, user, connectorConfiguration(), overwrite);
    expect(result).toMatchObject({
      status: 'failed',
      code: 'credentials_required',
      reason: 'Credentials to provide: MITRE_API_KEY',
      credentials: [{ key: 'MITRE_API_KEY', description: 'The key of the MITRE API', required: true }],
    });
    expectNothingWritten();
  });

  it('creates the connector with the secret given, never with a secret of the bundle', async () => {
    const configuration = connectorConfiguration({ manager_contract_configuration: [{ key: 'MITRE_INTERVAL', value: '7' }, { key: 'MITRE_API_KEY', value: 'from-bundle' }] });
    const result = await importConnector(context, user, configuration, { ...overwrite, credentials: { MITRE_API_KEY: 'given-key', UNKNOWN: 'ignored' } });
    expect(result).toMatchObject({ status: 'created', exists: false });
    expect(managedConnectorAdd).toHaveBeenCalledWith(context, user, {
      name: 'MITRE',
      catalog_id: 'filigran-catalog',
      manager_contract_image: 'opencti/connector-mitre',
      manager_contract_configuration: [{ key: 'MITRE_INTERVAL', value: '7' }, { key: 'MITRE_API_KEY', value: 'given-key' }],
      // A new service account, with the confidence of the exported one
      user_id: '[C] MITRE',
      automatic_user: true,
      confidence_level: '75',
    });
  });

  it('validates on a dry run with the secrets given, without writing', async () => {
    const result = await importConnector(context, user, connectorConfiguration(), { ...overwrite, dryRun: true, credentials: { MITRE_API_KEY: 'given-key' } });
    expect(result).toMatchObject({ status: 'created' });
    expect(computeConnectorTargetContract).toHaveBeenCalledWith(
      [{ key: 'MITRE_INTERVAL', value: '7' }, { key: 'MITRE_API_KEY', value: 'given-key' }],
      contract,
      'public-key',
      undefined,
    );
    expectNothingWritten();
  });

  it('creates the service account under a free name', async () => {
    vi.mocked(userAlreadyExists).mockImplementation(async (_ctx: unknown, name: string) => name === '[C] MITRE');
    await importConnector(context, user, connectorConfiguration(), { ...overwrite, credentials: { MITRE_API_KEY: 'key' } });
    expect(managedConnectorAdd).toHaveBeenCalledWith(context, user, expect.objectContaining({ user_id: '[C] MITRE (1)' }));
  });
});

describe('importConnector overwrite and copy', () => {
  beforeEach(() => withConnectors([mitreConnector, externalConnector]));

  it('updates the managed connector with the same name, keeping its secrets when none is given', async () => {
    const result = await importConnector(context, user, connectorConfiguration({ manager_contract_configuration: [{ key: 'MITRE_INTERVAL', value: '14' }] }), overwrite);
    expect(result).toMatchObject({ status: 'overwritten', exists: true, credentials: [{ key: 'MITRE_API_KEY', required: false }] });
    expect(managedConnectorEdit).toHaveBeenCalledWith(context, user, {
      id: mitreConnector.id,
      name: 'mitre',
      title: 'MITRE',
      connector_user_id: mitreConnector.connector_user_id,
      manager_contract_configuration: [{ key: 'MITRE_INTERVAL', value: '14' }],
    });
    // The contract of the connector that runs, and its current configuration that keeps the secrets
    expect(computeConnectorTargetContract).toHaveBeenCalledWith(expect.anything(), mitreConnector.manager_contract, 'public-key', mitreConnector.manager_contract_configuration);
    expect(managedConnectorAdd).not.toHaveBeenCalled();
  });

  it('skips the managed connector when the bundle changes nothing of it', async () => {
    const result = await importConnector(context, user, connectorConfiguration(), overwrite);
    expect(result).toMatchObject({ status: 'skipped', code: 'unchanged', reason: 'Already up to date' });
    expectNothingWritten();
  });

  it('refuses to overwrite a connector registered from outside the platform', async () => {
    const result = await importConnector(context, user, connectorConfiguration({ name: 'External' }), overwrite);
    expect(result).toMatchObject({ status: 'failed', code: 'not_managed', exists: true });
    expectNothingWritten();
  });

  it('refuses a connector that exists on an add', async () => {
    expect(await importConnector(context, user, connectorConfiguration(), { mode: ConfigImportMode.Add })).toMatchObject({ status: 'failed', code: 'exists' });
  });

  it('creates a copy under a free name, never touching the existing connector', async () => {
    const result = await importConnector(context, user, connectorConfiguration(), { mode: ConfigImportMode.Copy, credentials: { MITRE_API_KEY: 'key' } });
    expect(result).toMatchObject({ status: 'created', exists: true, reason: 'Added as "MITRE (1)"' });
    expect(managedConnectorAdd).toHaveBeenCalledWith(context, user, expect.objectContaining({ name: 'MITRE (1)' }));
    expect(managedConnectorEdit).not.toHaveBeenCalled();
  });

  it('reserves on a dry run the names the earlier items would take', async () => {
    const reservedNames = new Set<string>();
    const options = { mode: ConfigImportMode.Copy, dryRun: true, reservedNames, credentials: { MITRE_API_KEY: 'key' } };
    const first = await importConnector(context, user, connectorConfiguration(), options);
    const second = await importConnector(context, user, connectorConfiguration(), options);
    expect([first.reason, second.reason]).toEqual(['Added as "MITRE (1)"', 'Added as "MITRE (2)"']);
    expectNothingWritten();
  });
});
