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
vi.mock('../../../../src/domain/group', () => ({ findDefaultIngestionGroups: vi.fn() }));
vi.mock('../../../../src/database/middleware-loader', () => ({ storeLoadById: vi.fn() }));

import { findCatalogByCatalogId, findLatestCompatibleCatalogContractByImageName } from '../../../../src/modules/catalog/catalog-repository';
import { computeConnectorTargetContract } from '../../../../src/modules/catalog/catalog-domain';
import { managedConnectorAdd, managedConnectorEdit } from '../../../../src/modules/connector/connector-domain';
import { findConnectorManagers, findConnectors } from '../../../../src/modules/connector/connector-repository';
import { userAlreadyExists } from '../../../../src/modules/user/user-domain';
import { findDefaultIngestionGroups } from '../../../../src/domain/group';
import { storeLoadById } from '../../../../src/database/middleware-loader';
import { importConfigPresetConnector } from '../../../../src/modules/connector/connector-import';
import { ConfigImportMode } from '../../../../src/modules/configImport/configImport-types';
import type { AuthContext, AuthUser } from '../../../../src/types/user';
import { externalConnector, mitreConnector } from '../configPreset/configPreset-connectors-fixtures';

const context = { source: 'test' } as AuthContext;
const user = { id: 'user-id' } as AuthUser;
const overwrite = { mode: ConfigImportMode.Overwrite, bundleId: 'mitre' };

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
  vi.mocked(findDefaultIngestionGroups).mockResolvedValue([{ id: 'connectors-group-id' }] as never);
  vi.mocked(managedConnectorAdd).mockResolvedValue({ id: 'created-id' } as never);
  vi.mocked(managedConnectorEdit).mockResolvedValue({ id: mitreConnector.id } as never);
  withConnectors([]);
});

const expectNothingWritten = () => {
  expect(managedConnectorAdd).not.toHaveBeenCalled();
  expect(managedConnectorEdit).not.toHaveBeenCalled();
};

describe('importConfigPresetConnector validation', () => {
  it.each([
    ['an unknown key', { connector_state: '{}' }],
    ['no image', { manager_contract_image: '' }],
    ['a confidence over 100', { confidence_level: 101 }],
  ])('refuses %s, without writing', async (_, overrides) => {
    expect(await importConfigPresetConnector(context, user, connectorConfiguration(overrides), overwrite)).toMatchObject({ status: 'failed', code: 'invalid' });
    expectNothingWritten();
  });

  it('fails a connector this platform cannot run, or without a connector manager', async () => {
    vi.mocked(findLatestCompatibleCatalogContractByImageName).mockResolvedValue(undefined as never);
    expect(await importConfigPresetConnector(context, user, connectorConfiguration(), overwrite))
      .toMatchObject({ status: 'failed', code: 'not_available', reason: 'Connector not available on this platform: opencti/connector-mitre' });
    vi.mocked(findLatestCompatibleCatalogContractByImageName).mockResolvedValue(contract as never);
    vi.mocked(findConnectorManagers).mockResolvedValue([]);
    expect(await importConfigPresetConnector(context, user, connectorConfiguration(), overwrite)).toMatchObject({ status: 'failed', code: 'no_manager' });
    expectNothingWritten();
  });

  it('fails with the reason of the contract when the configuration is not valid', async () => {
    vi.mocked(computeConnectorTargetContract).mockImplementation(() => {
      throw new Error('MITRE_INTERVAL must be integer');
    });
    const result = await importConfigPresetConnector(context, user, connectorConfiguration(), { ...overwrite, credentials: { MITRE_API_KEY: 'key' } });
    expect(result).toMatchObject({ status: 'failed', code: 'invalid', reason: 'MITRE_INTERVAL must be integer' });
    expectNothingWritten();
  });
});

describe('importConfigPresetConnector credentials', () => {
  it('fails a connector whose required secret is not given, and lists the secrets it takes', async () => {
    const result = await importConfigPresetConnector(context, user, connectorConfiguration(), overwrite);
    expect(result).toMatchObject({
      status: 'failed',
      code: 'credentials_required',
      reason: 'Configuration to provide: MITRE_API_KEY',
      credentials: [{ key: 'MITRE_API_KEY', description: 'The key of the MITRE API', required: true, secret: true, type: 'string' }],
    });
    expectNothingWritten();
  });

  it('creates the connector with the secret given, never with a secret of the bundle', async () => {
    const configuration = connectorConfiguration({ manager_contract_configuration: [{ key: 'MITRE_INTERVAL', value: '7' }, { key: 'MITRE_API_KEY', value: 'from-bundle' }] });
    const result = await importConfigPresetConnector(context, user, configuration, { ...overwrite, credentials: { MITRE_API_KEY: 'given-key', UNKNOWN: 'ignored' } });
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
    const result = await importConfigPresetConnector(context, user, connectorConfiguration(), { ...overwrite, dryRun: true, credentials: { MITRE_API_KEY: 'given-key' } });
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
    await importConfigPresetConnector(context, user, connectorConfiguration(), { ...overwrite, credentials: { MITRE_API_KEY: 'key' } });
    expect(managedConnectorAdd).toHaveBeenCalledWith(context, user, expect.objectContaining({ user_id: '[C] MITRE (1)' }));
  });
});

describe('importConfigPresetConnector required fields', () => {
  const withScore = {
    ...contract,
    config_schema: {
      ...contract.config_schema,
      properties: {
        ...contract.config_schema.properties,
        MITRE_SCORE: { type: 'integer', description: 'Minimum score' },
        MITRE_LIMIT: { type: 'integer', default: 500 },
      },
      required: ['MITRE_API_KEY', 'MITRE_SCORE', 'MITRE_LIMIT'],
    },
  };
  beforeEach(() => vi.mocked(findLatestCompatibleCatalogContractByImageName).mockResolvedValue(withScore as never));

  it('asks for a required field the bundle leaves empty, next to the secrets, and never for one with a default', async () => {
    const result = await importConfigPresetConnector(context, user, connectorConfiguration(), { ...overwrite, credentials: { MITRE_API_KEY: 'key' } });
    expect(result).toMatchObject({ status: 'failed', code: 'credentials_required', reason: 'Configuration to provide: MITRE_SCORE' });
    expect(result.credentials).toEqual([
      { key: 'MITRE_API_KEY', description: 'The key of the MITRE API', required: true, stored: false, secret: true, type: 'string' },
      { key: 'MITRE_SCORE', description: 'Minimum score', required: true, stored: false, secret: false, type: 'integer' },
    ]);
    expectNothingWritten();
  });

  it('creates the connector with the required field given', async () => {
    const result = await importConfigPresetConnector(context, user, connectorConfiguration(), { ...overwrite, credentials: { MITRE_API_KEY: 'key', MITRE_SCORE: '90' } });
    expect(result).toMatchObject({ status: 'created' });
    expect(vi.mocked(managedConnectorAdd).mock.calls[0][2].manager_contract_configuration)
      .toEqual([{ key: 'MITRE_INTERVAL', value: '7' }, { key: 'MITRE_API_KEY', value: 'key' }, { key: 'MITRE_SCORE', value: '90' }]);
  });

  it('does not ask for a required field the bundle carries', async () => {
    const configuration = connectorConfiguration({ manager_contract_configuration: [{ key: 'MITRE_INTERVAL', value: '7' }, { key: 'MITRE_SCORE', value: '75' }] });
    const result = await importConfigPresetConnector(context, user, configuration, { ...overwrite, credentials: { MITRE_API_KEY: 'key' } });
    expect(result).toMatchObject({ status: 'created' });
    expect(result.credentials?.map(({ key }) => key)).toEqual(['MITRE_API_KEY']);
  });

  it('keeps on overwrite the value the connector already has for a required field the bundle leaves empty', async () => {
    withConnectors([{
      ...mitreConnector,
      manager_contract: withScore,
      manager_contract_configuration: [...mitreConnector.manager_contract_configuration, { key: 'MITRE_SCORE', value: '80' }],
    }]);
    const result = await importConfigPresetConnector(context, user, connectorConfiguration({ manager_contract_configuration: [{ key: 'MITRE_INTERVAL', value: '14' }] }), overwrite);
    expect(result).toMatchObject({ status: 'overwritten', credentials: expect.arrayContaining([expect.objectContaining({ key: 'MITRE_SCORE', stored: true })]) });
    expect(vi.mocked(managedConnectorEdit).mock.calls[0][2].manager_contract_configuration)
      .toEqual([{ key: 'MITRE_INTERVAL', value: '14' }, { key: 'MITRE_SCORE', value: '80' }]);
  });
});

describe('importConfigPresetConnector default group of the ingestion users', () => {
  const withSecret = { ...overwrite, dryRun: true, credentials: { MITRE_API_KEY: 'key' } };

  it('fails a connector to create when the platform has no default group for the ingestion users, already in the dry run', async () => {
    vi.mocked(findDefaultIngestionGroups).mockResolvedValue([] as never);
    const result = await importConfigPresetConnector(context, user, connectorConfiguration(), withSecret);
    expect(result).toMatchObject({ status: 'failed', code: 'no_ingestion_group', reason: 'You have not defined a default group for ingestion users' });
    expectNothingWritten();
  });

  it('accepts it when a group of the same import becomes the default group of the ingestion users', async () => {
    vi.mocked(findDefaultIngestionGroups).mockResolvedValue([] as never);
    expect(await importConfigPresetConnector(context, user, connectorConfiguration(), { ...withSecret, ingestionGroupPlanned: true })).toMatchObject({ status: 'created' });
  });

  it('creates the connector with an existing user chosen at import, without a new service account', async () => {
    vi.mocked(findDefaultIngestionGroups).mockResolvedValue([] as never);
    vi.mocked(storeLoadById).mockResolvedValue({ id: 'chosen-user-id' } as never);
    const result = await importConfigPresetConnector(context, user, connectorConfiguration(), { ...overwrite, credentials: { MITRE_API_KEY: 'key' }, serviceAccountId: 'chosen-user-id' });
    expect(result).toMatchObject({ status: 'created' });
    const input = vi.mocked(managedConnectorAdd).mock.calls[0][2];
    expect(input).toMatchObject({ user_id: 'chosen-user-id', automatic_user: false });
    expect(input).not.toHaveProperty('confidence_level');
    expect(userAlreadyExists).not.toHaveBeenCalled();
  });

  it('fails a connector whose chosen user does not exist', async () => {
    vi.mocked(storeLoadById).mockResolvedValue(undefined as never);
    const result = await importConfigPresetConnector(context, user, connectorConfiguration(), { ...withSecret, serviceAccountId: 'deleted-user-id' });
    expect(result).toMatchObject({ status: 'failed', code: 'service_account_missing', reason: 'Service account not found' });
  });

  it('does not need it to overwrite a connector, which keeps its service account', async () => {
    vi.mocked(findDefaultIngestionGroups).mockResolvedValue([] as never);
    withConnectors([mitreConnector]);
    const result = await importConfigPresetConnector(context, user, connectorConfiguration({ manager_contract_configuration: [{ key: 'MITRE_INTERVAL', value: '14' }] }), overwrite);
    expect(result).toMatchObject({ status: 'overwritten' });
  });
});

describe('importConfigPresetConnector overwrite and copy', () => {
  beforeEach(() => withConnectors([mitreConnector, externalConnector]));

  it('updates the managed connector with the same name, keeping its secrets when none is given', async () => {
    const result = await importConfigPresetConnector(context, user, connectorConfiguration({ manager_contract_configuration: [{ key: 'MITRE_INTERVAL', value: '14' }] }), overwrite);
    expect(result).toMatchObject({ status: 'overwritten', exists: true, credentials: [{ key: 'MITRE_API_KEY', required: true, stored: true }] });
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

  it('gives back a secret only known by its name, which the contract would not keep', async () => {
    const withProxyToken = { ...mitreConnector, manager_contract_configuration: [...mitreConnector.manager_contract_configuration, { key: 'MITRE_PROXY_TOKEN', value: 'proxy-token' }] };
    withConnectors([withProxyToken]);
    const configuration = connectorConfiguration({ manager_contract_configuration: [{ key: 'MITRE_INTERVAL', value: '14' }], required_at_import: ['MITRE_API_KEY', 'MITRE_PROXY_TOKEN'] });
    const result = await importConfigPresetConnector(context, user, configuration, overwrite);
    expect(result).toMatchObject({ status: 'overwritten' });
    expect(vi.mocked(managedConnectorEdit).mock.calls[0][2].manager_contract_configuration)
      .toEqual([{ key: 'MITRE_INTERVAL', value: '14' }, { key: 'MITRE_PROXY_TOKEN', value: 'proxy-token' }]);
  });

  it('finds the connector by the id of the bundle when its display name changed', async () => {
    withConnectors([{ ...mitreConnector, title: 'MITRE ATT&CK' }]);
    const configuration = connectorConfiguration({ name: 'MITRE ATT&CK', manager_contract_configuration: [{ key: 'MITRE_INTERVAL', value: '14' }] });
    const result = await importConfigPresetConnector(context, user, configuration, overwrite);
    expect(result).toMatchObject({ status: 'overwritten', exists: true });
    expect(managedConnectorEdit).toHaveBeenCalledWith(context, user, expect.objectContaining({ id: mitreConnector.id, name: 'mitre', title: 'MITRE ATT&CK' }));
    expect(managedConnectorAdd).not.toHaveBeenCalled();
  });

  it('never overwrites another connector that only shares the display name, even of the same type', async () => {
    withConnectors([{ ...mitreConnector, name: 'mitre-att-ck', title: 'MITRE ATT&CK' }]);
    const configuration = connectorConfiguration({ name: 'MITRE ATT&CK', manager_contract_configuration: [{ key: 'MITRE_INTERVAL', value: '14' }] });
    const result = await importConfigPresetConnector(context, user, configuration, { ...overwrite, credentials: { MITRE_API_KEY: 'key' } });
    expect(result).toMatchObject({ status: 'failed', code: 'name_conflict', exists: true });
    expectNothingWritten();
  });

  it('adds it as a copy under a free name when the display name is taken', async () => {
    withConnectors([{ ...mitreConnector, name: 'mitre-att-ck', title: 'MITRE ATT&CK' }]);
    const configuration = connectorConfiguration({ name: 'MITRE ATT&CK' });
    const result = await importConfigPresetConnector(context, user, configuration, { mode: ConfigImportMode.Copy, bundleId: 'mitre', credentials: { MITRE_API_KEY: 'key' } });
    expect(result).toMatchObject({ status: 'created', reason: 'Added as "MITRE ATT&CK (1)"' });
  });

  it('asks for a stored secret again when the connector is added as a copy', async () => {
    const result = await importConfigPresetConnector(context, user, connectorConfiguration(), { mode: ConfigImportMode.Copy, bundleId: 'mitre', dryRun: true });
    expect(result).toMatchObject({ status: 'failed', code: 'credentials_required', credentials: [{ key: 'MITRE_API_KEY', required: true, stored: false }] });
  });

  it('says that the confidence level of the service account is not changed', async () => {
    vi.mocked(storeLoadById).mockResolvedValue({ id: 'mitre-user-id', user_confidence_level: { max_confidence: 50, overrides: [] } } as never);
    const unchanged = await importConfigPresetConnector(context, user, connectorConfiguration(), overwrite);
    expect(unchanged).toMatchObject({ status: 'skipped', code: 'unchanged', reason: 'Already up to date\nThe confidence level of the service account is not changed' });
    const changed = await importConfigPresetConnector(context, user, connectorConfiguration({ manager_contract_configuration: [{ key: 'MITRE_INTERVAL', value: '14' }] }), overwrite);
    expect(changed).toMatchObject({ status: 'overwritten', reason: 'The confidence level of the service account is not changed' });
    expect(storeLoadById).toHaveBeenCalledWith(context, user, mitreConnector.connector_user_id, 'User');
  });

  it('reads the connectors and the managers given by the dry run instead of loading them again', async () => {
    const loaded = { connectors: [mitreConnector], managers: [{ public_key: 'public-key' }] } as never;
    const result = await importConfigPresetConnector(context, user, connectorConfiguration({ manager_contract_configuration: [{ key: 'MITRE_INTERVAL', value: '14' }] }), { ...overwrite, dryRun: true, loaded });
    expect(result).toMatchObject({ status: 'overwritten' });
    expect(findConnectors).not.toHaveBeenCalled();
    expect(findConnectorManagers).not.toHaveBeenCalled();
  });

  it('skips the managed connector when the bundle changes nothing of it', async () => {
    const result = await importConfigPresetConnector(context, user, connectorConfiguration(), overwrite);
    expect(result).toMatchObject({ status: 'skipped', code: 'unchanged', reason: 'Already up to date' });
    expectNothingWritten();
  });

  it('refuses to overwrite a connector registered from outside the platform', async () => {
    const result = await importConfigPresetConnector(context, user, connectorConfiguration({ name: 'External' }), { ...overwrite, bundleId: 'external' });
    expect(result).toMatchObject({ status: 'failed', code: 'not_managed', exists: true });
    expectNothingWritten();
  });

  it('never overwrites a connector of another catalog or image that has the same name', async () => {
    withConnectors([{ ...mitreConnector, manager_contract_image: 'opencti/connector-other' }]);
    const result = await importConfigPresetConnector(context, user, connectorConfiguration({ manager_contract_configuration: [{ key: 'MITRE_INTERVAL', value: '14' }] }), overwrite);
    expect(result).toMatchObject({ status: 'failed', code: 'name_conflict', exists: true });
    expectNothingWritten();
  });

  it('refuses a connector that exists on an add', async () => {
    expect(await importConfigPresetConnector(context, user, connectorConfiguration(), { mode: ConfigImportMode.Add, bundleId: 'mitre' })).toMatchObject({ status: 'failed', code: 'exists' });
  });

  it('creates a copy under a free name, never touching the existing connector', async () => {
    const result = await importConfigPresetConnector(context, user, connectorConfiguration(), { mode: ConfigImportMode.Copy, bundleId: 'mitre', credentials: { MITRE_API_KEY: 'key' } });
    expect(result).toMatchObject({ status: 'created', exists: true, reason: 'Added as "MITRE (1)"' });
    expect(managedConnectorAdd).toHaveBeenCalledWith(context, user, expect.objectContaining({ name: 'MITRE (1)' }));
    expect(managedConnectorEdit).not.toHaveBeenCalled();
  });

  it('reserves on a dry run the names the earlier items would take', async () => {
    const reservedNames = new Set<string>();
    const options = { mode: ConfigImportMode.Copy, bundleId: 'mitre', dryRun: true, reservedNames, credentials: { MITRE_API_KEY: 'key' } };
    const first = await importConfigPresetConnector(context, user, connectorConfiguration(), options);
    const second = await importConfigPresetConnector(context, user, connectorConfiguration(), options);
    expect([first.reason, second.reason]).toEqual(['Added as "MITRE (1)"', 'Added as "MITRE (2)"']);
    expectNothingWritten();
  });
});
