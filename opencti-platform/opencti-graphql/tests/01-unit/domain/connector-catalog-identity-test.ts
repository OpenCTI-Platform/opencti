import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  batchConnectorCatalogIdentities,
  buildCatalogIdentityIndex,
  type CatalogIdentityContract,
  compactIdentityKey,
  connectorCatalogIdentity,
  connectorCatalogIdentityOptions,
  connectorCatalogIdentityUpdate,
  findCatalogContractByName,
  identityKeys,
  identityTokens,
  matchCatalogContractsByName,
  resetCatalogIdentityIndexCache,
  resolveConnectorCatalogIdentity,
} from '../../../src/domain/connector-catalog-identity';
import { patchAttribute } from '../../../src/database/middleware';
import { fullEntitiesList, storeLoadById } from '../../../src/database/middleware-loader';
import { notify } from '../../../src/database/redis';
import { publishUserAction } from '../../../src/listener/UserActionListener';
import { ConnectorCatalogIdentitySource } from '../../../src/generated/graphql';
import type { AuthContext, AuthUser } from '../../../src/types/user';

vi.mock('../../../src/database/middleware', () => ({
  patchAttribute: vi.fn(),
}));

vi.mock('../../../src/database/middleware-loader', () => ({
  fullEntitiesList: vi.fn(),
  storeLoadById: vi.fn(),
}));

vi.mock('../../../src/database/redis', () => ({
  notify: vi.fn(),
}));

vi.mock('../../../src/listener/UserActionListener', () => ({
  publishUserAction: vi.fn(),
}));

vi.mock('../../../src/database/repository', () => ({
  completeConnector: (connector: unknown) => connector,
}));

const testContext = { source: 'test' } as unknown as AuthContext;
const testUser = { id: 'test-user-id' } as unknown as AuthUser;

const contract = (slug: string, title: string, connector_type: string, logo_uri?: string): CatalogIdentityContract => ({
  slug,
  title,
  connector_type,
  logo_uri: logo_uri ?? `/catalog/logo/${slug}.png`,
  short_description: `${title} connector`,
});

// Titles, slugs and types as published in the connectors catalog.
const CATALOG = [
  contract('mitre', 'MITRE ATT&CK', 'EXTERNAL_IMPORT'),
  contract('mitre-atlas', 'MITRE ATLAS', 'EXTERNAL_IMPORT'),
  contract('cisa-kev', 'CISA Known Exploited Vulnerabilities (KEV)', 'EXTERNAL_IMPORT'),
  contract('opencti', 'OpenCTI Datasets', 'EXTERNAL_IMPORT'),
  contract('opencti-stream', 'OpenCTI Stream', 'EXTERNAL_IMPORT'),
  contract('disarm-framework', 'DISARM Framework', 'EXTERNAL_IMPORT'),
  contract('ransomware-live', 'Ransomware.live', 'EXTERNAL_IMPORT'),
  contract('abuse-ssl', 'Abuse SSL (Deprecated)', 'EXTERNAL_IMPORT'),
  contract('urlhaus', 'URLhaus', 'EXTERNAL_IMPORT'),
  contract('urlhaus-recent-payloads', 'URLhaus Recent Payloads', 'EXTERNAL_IMPORT'),
  contract('threatfox', 'ThreatFox', 'EXTERNAL_IMPORT'),
  contract('misp', 'MISP', 'EXTERNAL_IMPORT'),
  contract('misp-feed', 'MISP Feed', 'EXTERNAL_IMPORT'),
  contract('crowdsec-import', 'CrowdSec Feed', 'EXTERNAL_IMPORT'),
  contract('s3', 'S3', 'EXTERNAL_IMPORT'),
  contract('Silobreaker', 'Silobreaker', 'EXTERNAL_IMPORT'),
  contract('metras-feed', 'Metras Feed Connector', 'EXTERNAL_IMPORT'),
  contract('crowdsec', 'CrowdSec', 'INTERNAL_ENRICHMENT'),
  contract('import-external-reference', 'Import External Reference', 'INTERNAL_ENRICHMENT'),
  contract('import-document', 'Import Document', 'INTERNAL_IMPORT_FILE'),
  contract('import-document-ai', 'Import Document AI', 'INTERNAL_IMPORT_FILE'),
  contract('import-file-stix', 'Import File STIX', 'INTERNAL_IMPORT_FILE'),
  contract('import-file-yara', 'Import File YARA', 'INTERNAL_IMPORT_FILE'),
  contract('export-file-stix', 'Export File STIX', 'INTERNAL_EXPORT_FILE'),
  contract('export-file-csv', 'Export File Csv', 'INTERNAL_EXPORT_FILE'),
  contract('export-file-txt', 'Export File Text', 'INTERNAL_EXPORT_FILE'),
];

const index = buildCatalogIdentityIndex(CATALOG);

const baseConnector = {
  name: 'My connector',
  connector_type: 'EXTERNAL_IMPORT',
  slug: null,
  catalog_slug_manual: null,
  built_in: false,
  manager_contract: undefined,
};

describe('Connector catalog identity - normalisation', () => {
  it('should compact a name to lower-case letters and digits', () => {
    expect(compactIdentityKey('MITRE ATT&CK')).toEqual('mitreattck');
    expect(compactIdentityKey('Ransomware.live')).toEqual('ransomwarelive');
    expect(compactIdentityKey('  Sécurité  Feed-2 ')).toEqual('securitefeed2');
  });

  it('should drop parenthesised suffixes, the connector word and vendor prefixes', () => {
    expect(identityKeys('CISA Known Exploited Vulnerabilities (KEV)')).toEqual(['cisaknownexploitedvulnerabilities']);
    expect(identityKeys('MITRE ATLAS [composer]')).toEqual(['mitreatlas']);
    expect(identityKeys('Metras Feed Connector')).toEqual(['metrasfeed']);
    expect(identityKeys('Abuse.ch URLhaus')).toEqual(['abusechurlhaus', 'urlhaus']);
    expect(identityKeys('abuse ch - ThreatFox')).toEqual(['abusechthreatfox', 'threatfox']);
  });

  it('should only drop qualifiers at the end of a name', () => {
    expect(identityKeys('Foo (different) Bar')).toEqual(['foodifferentbar']);
    expect(identityKeys('Feed (KEV) [composer]')).toEqual(['feed']);
    // An interior qualifier tells two entries apart instead of making their names equal.
    const catalog = buildCatalogIdentityIndex([
      contract('foo-bar', 'Foo Bar', 'EXTERNAL_IMPORT'),
      contract('foo-different-bar', 'Foo (different) Bar', 'EXTERNAL_IMPORT'),
    ]);
    expect(findCatalogContractByName(catalog, 'Foo (different) Bar', 'EXTERNAL_IMPORT')?.slug).toEqual('foo-different-bar');
    expect(findCatalogContractByName(catalog, 'Foo Bar', 'EXTERNAL_IMPORT')?.slug).toEqual('foo-bar');
    expect(findCatalogContractByName(catalog, 'Foo Bar (v2)', 'EXTERNAL_IMPORT')?.slug).toEqual('foo-bar');
  });

  it('should only drop a vendor prefix on a word boundary', () => {
    expect(identityKeys('AbuseChecker')).toEqual(['abusechecker']);
  });

  it('should return no key for an empty name', () => {
    expect(identityKeys('')).toEqual([]);
    expect(identityKeys(null)).toEqual([]);
    expect(identityKeys('(only a suffix)')).toEqual([]);
  });

  it('should split names into words, camel case and digits included', () => {
    expect(identityTokens('ExportFileStix2')).toEqual(['export', 'file', 'stix', '2']);
    expect(identityTokens('Abuse.ch SSL Blacklist')).toEqual(['abuse', 'ch', 'ssl', 'blacklist']);
    expect(identityTokens('Intel471 (Deprecated)')).toEqual(['intel', '471']);
  });
});

describe('Connector catalog identity - name match', () => {
  // Names and types of the connectors of the OpenCTI docker compose files.
  it.each([
    ['MITRE ATT&CK', 'EXTERNAL_IMPORT', 'mitre'],
    ['CISA Known Exploited Vulnerabilities', 'EXTERNAL_IMPORT', 'cisa-kev'],
    ['OpenCTI Datasets', 'EXTERNAL_IMPORT', 'opencti'],
    ['DISARM Framework', 'EXTERNAL_IMPORT', 'disarm-framework'],
    ['Ransomware.live', 'EXTERNAL_IMPORT', 'ransomware-live'],
    ['Abuse.ch SSL Blacklist', 'EXTERNAL_IMPORT', 'abuse-ssl'],
    ['Abuse.ch URLhaus', 'EXTERNAL_IMPORT', 'urlhaus'],
    ['Abuse.ch ThreatFox', 'EXTERNAL_IMPORT', 'threatfox'],
    ['ImportDocument', 'INTERNAL_IMPORT_FILE', 'import-document'],
    ['ImportDocumentAnalysis', 'INTERNAL_ANALYSIS', 'import-document'],
    ['ImportFileStix', 'INTERNAL_IMPORT_FILE', 'import-file-stix'],
    ['ImportFileYARA', 'INTERNAL_IMPORT_FILE', 'import-file-yara'],
    ['ImportExternalReference', 'INTERNAL_ENRICHMENT', 'import-external-reference'],
    ['ExportFileStix2', 'INTERNAL_EXPORT_FILE', 'export-file-stix'],
    ['ExportFileCsv', 'INTERNAL_EXPORT_FILE', 'export-file-csv'],
    ['ExportFileTxt', 'INTERNAL_EXPORT_FILE', 'export-file-txt'],
  ])('should identify "%s" (%s) as %s', (name, connectorType, expectedSlug) => {
    expect(findCatalogContractByName(index, name, connectorType)?.slug).toEqual(expectedSlug);
  });

  it('should prefer an exact match to the entries containing the name', () => {
    expect(findCatalogContractByName(index, 'MISP', 'EXTERNAL_IMPORT')?.slug).toEqual('misp');
    expect(findCatalogContractByName(index, 'Import Document', 'INTERNAL_IMPORT_FILE')?.slug).toEqual('import-document');
    expect(findCatalogContractByName(index, 'Abuse.ch URLhaus', 'EXTERNAL_IMPORT')?.slug).toEqual('urlhaus');
  });

  it('should identify a name that contains a single catalog title', () => {
    expect(findCatalogContractByName(index, 'URLhaus feeds', 'EXTERNAL_IMPORT')?.slug).toEqual('urlhaus');
    expect(findCatalogContractByName(index, 'CrowdSec', 'EXTERNAL_IMPORT')?.slug).toEqual('crowdsec-import');
  });

  it('should only compare the name with entries of the same connector type', () => {
    expect(findCatalogContractByName(index, 'CrowdSec', 'INTERNAL_ENRICHMENT')?.slug).toEqual('crowdsec');
    expect(findCatalogContractByName(index, 'MITRE ATT&CK', 'STREAM')).toBeUndefined();
    expect(findCatalogContractByName(index, 'MITRE ATT&CK', null)).toBeUndefined();
  });

  it('should keep no identity when the name designates several entries', () => {
    const matches = matchCatalogContractsByName('MITRE ATT&CK and ATLAS', index.byConnectorType.get('EXTERNAL_IMPORT') ?? []);
    expect(matches.map((match) => match.slug).sort()).toEqual(['mitre', 'mitre-atlas']);
    expect(findCatalogContractByName(index, 'MITRE ATT&CK and ATLAS', 'EXTERNAL_IMPORT')).toBeUndefined();
  });

  it('should keep no identity when two entries share the same title', () => {
    const duplicated = buildCatalogIdentityIndex([
      contract('intel471', 'Intel471 (Deprecated)', 'EXTERNAL_IMPORT'),
      contract('intel471-next', 'Intel 471', 'EXTERNAL_IMPORT'),
    ]);
    expect(findCatalogContractByName(duplicated, 'Intel471', 'EXTERNAL_IMPORT')).toBeUndefined();
  });

  it('should identify a name equal to the slug of a single entry', () => {
    // Kubernetes and Helm deployments often name a connector after its image, opencti/connector-<slug>.
    expect(findCatalogContractByName(index, 'cisa-kev', 'EXTERNAL_IMPORT')?.slug).toEqual('cisa-kev');
    expect(findCatalogContractByName(index, 'opencti', 'EXTERNAL_IMPORT')?.slug).toEqual('opencti');
    expect(findCatalogContractByName(index, 'export-file-txt', 'INTERNAL_EXPORT_FILE')?.slug).toEqual('export-file-txt');
  });

  it('should never identify a name by containment of a slug', () => {
    // "opencti" is the slug of OpenCTI Datasets only, but a name containing it designates neither entry.
    expect(findCatalogContractByName(index, 'My OpenCTI mirror', 'EXTERNAL_IMPORT')).toBeUndefined();
    expect(findCatalogContractByName(index, 'cisa-kev-mirror', 'EXTERNAL_IMPORT')).toBeUndefined();
    expect(findCatalogContractByName(index, 'mitre-backup', 'EXTERNAL_IMPORT')).toBeUndefined();
  });

  it('should not identify short or unrelated names by containment', () => {
    expect(findCatalogContractByName(index, 'S3', 'EXTERNAL_IMPORT')?.slug).toEqual('s3');
    expect(findCatalogContractByName(index, 'S3 backups', 'EXTERNAL_IMPORT')).toBeUndefined();
    expect(findCatalogContractByName(index, 'My custom feed', 'EXTERNAL_IMPORT')).toBeUndefined();
    expect(findCatalogContractByName(index, '', 'EXTERNAL_IMPORT')).toBeUndefined();
  });
});

describe('Connector catalog identity - resolution order', () => {
  it('should use the composer contract of a managed connector first', () => {
    const managed = {
      ...baseConnector,
      catalog_slug_manual: 'misp',
      manager_contract: { slug: 'mitre-atlas', title: 'MITRE ATLAS', logo_uri: '/logo/atlas.png', connector_type: 'EXTERNAL_IMPORT', short_description: 'Adversarial AI' } as never,
    };
    expect(resolveConnectorCatalogIdentity(managed, index)).toEqual({
      slug: 'mitre-atlas',
      title: 'MITRE ATLAS',
      logo: '/logo/atlas.png',
      short_description: 'Adversarial AI',
      source: ConnectorCatalogIdentitySource.Composer,
    });
  });

  it('should keep a managed connector without contract out of the automatic identification', () => {
    // The embedded contract can be missing (an image no longer in the catalog): catalog_id still makes it managed.
    const managed = { ...baseConnector, name: 'MITRE ATT&CK', slug: 'urlhaus', catalog_slug_manual: 'threatfox', catalog_id: 'catalog-1' };
    expect(resolveConnectorCatalogIdentity(managed, index)).toBeNull();
  });

  it('should never identify a built-in connector', () => {
    expect(resolveConnectorCatalogIdentity({ ...baseConnector, name: 'MITRE ATT&CK', built_in: true }, index)).toBeNull();
    // Not even with a contract left over from an earlier deployment.
    const withContract = {
      ...baseConnector,
      built_in: true,
      manager_contract: { slug: 'mitre-atlas', title: 'MITRE ATLAS', logo_uri: '/logo/atlas.png', connector_type: 'EXTERNAL_IMPORT', short_description: '' } as never,
    };
    expect(resolveConnectorCatalogIdentity(withContract, index)).toBeNull();
  });

  it('should prefer the entry chosen by hand to the reported slug and the name', () => {
    const connector = { ...baseConnector, name: 'MITRE ATT&CK', slug: 'urlhaus', catalog_slug_manual: 'threatfox' };
    expect(resolveConnectorCatalogIdentity(connector, index)).toMatchObject({ slug: 'threatfox', source: ConnectorCatalogIdentitySource.Manual });
  });

  it('should prefer the reported slug to the name, whatever its case', () => {
    const connector = { ...baseConnector, name: 'MITRE ATT&CK', slug: 'SILOBREAKER' };
    expect(resolveConnectorCatalogIdentity(connector, index)).toMatchObject({ slug: 'Silobreaker', source: ConnectorCatalogIdentitySource.Reported });
  });

  it('should fall back to the next source when a slug is not in the catalog', () => {
    const connector = { ...baseConnector, name: 'MITRE ATT&CK', slug: 'my-fork', catalog_slug_manual: 'removed-entry' };
    expect(resolveConnectorCatalogIdentity(connector, index)).toEqual({
      slug: 'mitre',
      title: 'MITRE ATT&CK',
      logo: '/catalog/logo/mitre.png',
      short_description: 'MITRE ATT&CK connector',
      source: ConnectorCatalogIdentitySource.Name,
    });
  });

  it('should return no identity when nothing matches', () => {
    expect(resolveConnectorCatalogIdentity({ ...baseConnector, name: 'In-house enrichment' }, index)).toBeNull();
  });

  it('should skip catalog entries without slug or title and keep the first entry of a slug', () => {
    const partial = buildCatalogIdentityIndex([
      contract('', 'No slug', 'EXTERNAL_IMPORT'),
      contract('no-title', '', 'EXTERNAL_IMPORT'),
      contract('urlhaus', 'URLhaus', 'EXTERNAL_IMPORT', '/logo/first.png'),
      contract('URLhaus', 'URLhaus copy', 'EXTERNAL_IMPORT', '/logo/second.png'),
    ]);
    expect([...partial.bySlug.keys()]).toEqual(['urlhaus']);
    expect(partial.byConnectorType.get('EXTERNAL_IMPORT')?.map((indexed) => indexed.contract.slug)).toEqual(['urlhaus']);
    expect(resolveConnectorCatalogIdentity({ ...baseConnector, name: 'No slug' }, partial)).toBeNull();
    expect(resolveConnectorCatalogIdentity({ ...baseConnector, slug: 'urlhaus' }, partial)?.logo).toEqual('/logo/first.png');
  });

  it('should return a null logo when the catalog entry has none', () => {
    const withoutLogo = buildCatalogIdentityIndex([{ slug: 'threatfox', title: 'ThreatFox', connector_type: 'EXTERNAL_IMPORT', logo_uri: '', short_description: '' }]);
    expect(resolveConnectorCatalogIdentity({ ...baseConnector, slug: 'threatfox' }, withoutLogo)?.logo).toBeNull();
  });
});

describe('Connector catalog identity - loading', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    resetCatalogIdentityIndexCache();
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  const storedContract = (slug: string, title: string, contract_version: string, logo_uri: string) => ({
    slug,
    title,
    contract_version,
    contract_id: `${slug}-${contract_version}`,
    connector_type: 'EXTERNAL_IMPORT',
    logo_uri,
  });

  it('should list the catalog once for all the connectors of a request', async () => {
    vi.mocked(fullEntitiesList).mockResolvedValue([
      storedContract('threatfox', 'ThreatFox', '6.8.0', '/logo/old.png'),
      storedContract('threatfox', 'ThreatFox', '6.9.0', '/logo/new.png'),
      storedContract('urlhaus', 'URLhaus', '6.9.0', '/logo/urlhaus.png'),
    ] as never);
    const identities = await batchConnectorCatalogIdentities(testContext, testUser, [
      { ...baseConnector, name: 'Abuse.ch ThreatFox' },
      { ...baseConnector, name: 'Abuse.ch URLhaus' },
      { ...baseConnector, name: 'In-house feed' },
    ]);
    expect(fullEntitiesList).toHaveBeenCalledTimes(1);
    expect(identities).toEqual([
      { slug: 'threatfox', title: 'ThreatFox', logo: '/logo/new.png', short_description: null, source: ConnectorCatalogIdentitySource.Name },
      { slug: 'urlhaus', title: 'URLhaus', logo: '/logo/urlhaus.png', short_description: null, source: ConnectorCatalogIdentitySource.Name },
      null,
    ]);
  });

  it('should share one catalog listing between requests for a minute', async () => {
    vi.useFakeTimers();
    vi.mocked(fullEntitiesList).mockResolvedValue([storedContract('urlhaus', 'URLhaus', '6.9.0', '/logo/urlhaus.png')] as never);
    const connector = { ...baseConnector, name: 'Abuse.ch URLhaus' };
    await batchConnectorCatalogIdentities(testContext, testUser, [connector]);
    vi.advanceTimersByTime(59 * 1000);
    await batchConnectorCatalogIdentities(testContext, testUser, [connector]);
    expect(fullEntitiesList).toHaveBeenCalledTimes(1);
    vi.advanceTimersByTime(2 * 1000);
    await batchConnectorCatalogIdentities(testContext, testUser, [connector]);
    expect(fullEntitiesList).toHaveBeenCalledTimes(2);
  });

  it('should list the catalog outside the request that asked for it', async () => {
    // The listing is shared for a minute: the abort signal or the draft of one request must not reach the others.
    vi.mocked(fullEntitiesList).mockResolvedValue([storedContract('urlhaus', 'URLhaus', '6.9.0', '/logo/urlhaus.png')] as never);
    const requestContext = { ...testContext, requestAbortSignal: new AbortController().signal, draft_context: 'draft-1' } as unknown as AuthContext;
    await batchConnectorCatalogIdentities(requestContext, testUser, [{ ...baseConnector, name: 'Abuse.ch URLhaus' }]);
    const [listContext] = vi.mocked(fullEntitiesList).mock.calls[0] as unknown as [{ source: string; requestAbortSignal?: AbortSignal; draft_context?: string }];
    expect(listContext).not.toBe(requestContext);
    expect(listContext.source).toEqual('connector_catalog_identity');
    expect(listContext.requestAbortSignal).toBeUndefined();
    expect(listContext.draft_context).toBeUndefined();
  });

  it('should list the catalog again after a failed listing', async () => {
    vi.mocked(fullEntitiesList).mockRejectedValueOnce(new Error('search engine unavailable'));
    const connector = { ...baseConnector, name: 'Abuse.ch URLhaus' };
    await expect(batchConnectorCatalogIdentities(testContext, testUser, [connector])).rejects.toThrow('search engine unavailable');
    vi.mocked(fullEntitiesList).mockResolvedValueOnce([storedContract('urlhaus', 'URLhaus', '6.9.0', '/logo/urlhaus.png')] as never);
    const [identity] = await batchConnectorCatalogIdentities(testContext, testUser, [connector]);
    expect(identity).toMatchObject({ slug: 'urlhaus', source: ConnectorCatalogIdentitySource.Name });
    expect(fullEntitiesList).toHaveBeenCalledTimes(2);
  });

  it('should not list the catalog when every connector is managed or built-in', async () => {
    const identities = await batchConnectorCatalogIdentities(testContext, testUser, [
      { ...baseConnector, built_in: true },
      { ...baseConnector, name: 'Abuse.ch URLhaus', catalog_id: 'catalog-1' },
    ]);
    expect(fullEntitiesList).not.toHaveBeenCalled();
    expect(identities).toEqual([null, null]);
  });

  it('should resolve a connector through the loader of the request', async () => {
    const resolved = { slug: 'urlhaus', title: 'URLhaus', logo: null, short_description: null, source: ConnectorCatalogIdentitySource.Name };
    const load = vi.fn().mockResolvedValue(resolved);
    const context = { ...testContext, batch: { connectorCatalogIdentityBatchLoader: { load } } } as unknown as AuthContext;
    const connector = { ...baseConnector, name: 'Abuse.ch URLhaus' };
    await expect(connectorCatalogIdentity(context, testUser, connector)).resolves.toBe(resolved);
    expect(load).toHaveBeenCalledWith(connector);
    expect(fullEntitiesList).not.toHaveBeenCalled();
  });

  it('should resolve a connector without a request loader', async () => {
    vi.mocked(fullEntitiesList).mockResolvedValue([storedContract('urlhaus', 'URLhaus', '6.9.0', '/logo/urlhaus.png')] as never);
    const identity = await connectorCatalogIdentity(testContext, testUser, { ...baseConnector, name: 'Abuse.ch URLhaus' });
    expect(identity).toMatchObject({ slug: 'urlhaus', logo: '/logo/urlhaus.png', source: ConnectorCatalogIdentitySource.Name });
  });

  it('should list the catalog entries as options sorted by title', async () => {
    vi.mocked(fullEntitiesList).mockResolvedValue([
      storedContract('urlhaus', 'URLhaus', '6.9.0', '/logo/urlhaus.png'),
      storedContract('threatfox', 'ThreatFox', '6.9.0', ''),
    ] as never);
    const options = await connectorCatalogIdentityOptions(testContext);
    expect(options.map((option) => option.slug)).toEqual(['threatfox', 'urlhaus']);
    expect(options[0]).toMatchObject({ title: 'ThreatFox', logo: null, connector_type: 'EXTERNAL_IMPORT' });
  });
});

describe('Connector catalog identity - manual binding', () => {
  const storedConnector = { id: 'connector-1', internal_id: 'connector-1', name: 'Feed', connector_type: 'EXTERNAL_IMPORT', built_in: false };

  beforeEach(() => {
    vi.clearAllMocks();
    resetCatalogIdentityIndexCache();
    vi.mocked(fullEntitiesList).mockResolvedValue([
      { slug: 'threatfox', title: 'ThreatFox', contract_version: '6.9.0', contract_id: 'threatfox-6.9.0', connector_type: 'EXTERNAL_IMPORT' },
    ] as never);
    vi.mocked(patchAttribute).mockImplementation(async (_context, _user, _id, _type, patch) => ({ element: { ...storedConnector, ...patch } }) as never);
  });

  it('should store the catalog slug chosen by hand', async () => {
    vi.mocked(storeLoadById).mockResolvedValue(storedConnector as never);
    const result = await connectorCatalogIdentityUpdate(testContext, testUser, 'connector-1', 'ThreatFox');
    expect(patchAttribute).toHaveBeenCalledWith(testContext, testUser, 'connector-1', 'Connector', { catalog_slug_manual: 'threatfox' });
    expect(result).toMatchObject({ catalog_slug_manual: 'threatfox' });
    expect(publishUserAction).toHaveBeenCalledWith(expect.objectContaining({ event_access: 'administration', event_scope: 'update' }));
    expect(notify).toHaveBeenCalledTimes(1);
  });

  it('should clear the choice when no slug is given', async () => {
    vi.mocked(storeLoadById).mockResolvedValue({ ...storedConnector, catalog_slug_manual: 'threatfox' } as never);
    await connectorCatalogIdentityUpdate(testContext, testUser, 'connector-1', null);
    expect(fullEntitiesList).not.toHaveBeenCalled();
    expect(patchAttribute).toHaveBeenCalledWith(testContext, testUser, 'connector-1', 'Connector', { catalog_slug_manual: null });
  });

  it('should refuse a slug that is not in the catalog', async () => {
    vi.mocked(storeLoadById).mockResolvedValue(storedConnector as never);
    await expect(connectorCatalogIdentityUpdate(testContext, testUser, 'connector-1', 'unknown-entry')).rejects.toThrow('No catalog entry found with this slug');
    expect(patchAttribute).not.toHaveBeenCalled();
  });

  it('should refuse managed, built-in and unknown connectors', async () => {
    vi.mocked(storeLoadById).mockResolvedValueOnce({ ...storedConnector, catalog_id: 'catalog-1' } as never);
    await expect(connectorCatalogIdentityUpdate(testContext, testUser, 'connector-1', 'threatfox')).rejects.toThrow('managed connector');
    vi.mocked(storeLoadById).mockResolvedValueOnce({ ...storedConnector, built_in: true } as never);
    await expect(connectorCatalogIdentityUpdate(testContext, testUser, 'connector-1', 'threatfox')).rejects.toThrow('built-in connector');
    vi.mocked(storeLoadById).mockResolvedValueOnce(undefined as never);
    await expect(connectorCatalogIdentityUpdate(testContext, testUser, 'connector-1', 'threatfox')).rejects.toThrow('No connector found');
    expect(patchAttribute).not.toHaveBeenCalled();
  });
});
