import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../../../src/modules/ingestion/ingestion-rss-domain', () => ({ addIngestion: vi.fn(), findAllRssIngestion: vi.fn(), ingestionEditField: vi.fn() }));
vi.mock('../../../../src/modules/ingestion/ingestion-taxii-domain', () => ({ ingestionTaxiiAdd: vi.fn(), findAllTaxiiIngestion: vi.fn(), ingestionTaxiiEditField: vi.fn() }));
vi.mock('../../../../src/modules/ingestion/ingestion-csv-domain', () => ({
  addIngestionCsv: vi.fn(),
  findAllCsvIngestion: vi.fn(),
  ingestionCsvEditField: vi.fn(),
  findCsvMapperForIngestionById: vi.fn(),
}));
vi.mock('../../../../src/modules/ingestion/ingestion-json-domain', () => ({
  addIngestionJson: vi.fn(),
  findAllJsonIngestion: vi.fn(),
  ingestionJsonEditField: vi.fn(),
  isSensitiveHeaderName: (name: string) => /authorization|token|key|secret|password|cookie|credential/i.test(name),
  isSensitiveQueryAttribute: (attribute: { exposed?: string; to?: string }) => attribute.exposed === 'header' && /token|key/i.test(attribute.to ?? ''),
  sanitizeExportedHeaders: (headers: { name: string; value: string }[] | undefined) => headers,
  sanitizeExportedQueryAttributes: (attributes: unknown[] | undefined) => attributes,
}));
vi.mock('../../../../src/config/uriDenyList', () => ({ uriDenyList: () => ['*.denied.com'] }));
vi.mock('../../../../src/modules/internal/jsonMapper/jsonMapper-domain', () => ({ createJsonMapperFromConfiguration: vi.fn(), deleteJsonMapper: vi.fn(), findById: vi.fn() }));
vi.mock('../../../../src/modules/internal/mapper-utils', () => ({ convertRepresentationsIds: vi.fn() }));
vi.mock('../../../../src/modules/ingestion/ingestion-execution-identity', () => ({ createIngestionAutomaticUser: vi.fn() }));
vi.mock('../../../../src/modules/ingestion/ingestion-common', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/modules/ingestion/ingestion-common')>()),
  decryptIngestionCredential: vi.fn(),
}));
vi.mock('../../../../src/modules/connector/connector-import', () => ({
  NO_INGESTION_GROUP_REASON: 'You have not defined a default group for ingestion users',
  CONFIDENCE_NOT_CHANGED_REASON: 'The confidence level of the service account is not changed',
}));
vi.mock('../../../../src/modules/user/user-domain', () => ({ userAlreadyExists: vi.fn(), userDelete: vi.fn() }));
vi.mock('../../../../src/domain/group', () => ({ findDefaultIngestionGroups: vi.fn() }));
vi.mock('../../../../src/database/middleware-loader', () => ({ storeLoadById: vi.fn(), internalLoadById: vi.fn(), internalFindByIds: vi.fn(), fullEntitiesList: vi.fn() }));
vi.mock('../../../../src/database/cache', () => ({ getEntitiesMapFromCache: vi.fn() }));

import { addIngestion, findAllRssIngestion, ingestionEditField } from '../../../../src/modules/ingestion/ingestion-rss-domain';
import { addIngestionCsv, findAllCsvIngestion } from '../../../../src/modules/ingestion/ingestion-csv-domain';
import { findAllTaxiiIngestion, ingestionTaxiiAdd, ingestionTaxiiEditField } from '../../../../src/modules/ingestion/ingestion-taxii-domain';
import { addIngestionJson, findAllJsonIngestion } from '../../../../src/modules/ingestion/ingestion-json-domain';
import { createJsonMapperFromConfiguration, deleteJsonMapper } from '../../../../src/modules/internal/jsonMapper/jsonMapper-domain';
import { createIngestionAutomaticUser } from '../../../../src/modules/ingestion/ingestion-execution-identity';
import { decryptIngestionCredential } from '../../../../src/modules/ingestion/ingestion-common';
import { userAlreadyExists } from '../../../../src/modules/user/user-domain';
import { findDefaultIngestionGroups } from '../../../../src/domain/group';
import { fullEntitiesList, internalFindByIds, internalLoadById, storeLoadById } from '../../../../src/database/middleware-loader';
import { getEntitiesMapFromCache } from '../../../../src/database/cache';
import { AMBIGUOUS_FEED_REASON, feedAdapterOf, importConfigPresetFeed } from '../../../../src/modules/ingestion/ingestion-import';
import { ConfigImportMode } from '../../../../src/modules/configImport/configImport-types';
import type { AuthContext, AuthUser } from '../../../../src/types/user';

const context = { source: 'test' } as AuthContext;
const user = { id: 'user-id' } as AuthUser;
const overwrite = { mode: ConfigImportMode.Overwrite };
const copy = { mode: ConfigImportMode.Copy };

const socMarking = { id: 'soc-marking-id', standard_id: 'marking-definition--soc', definition_type: 'INTERNAL', definition: 'INTERNAL:SOC' };
const feedUser = { id: 'feed-user-id', user_confidence_level: { max_confidence: 60, overrides: [] } };

const rssConfiguration = (overrides: Record<string, unknown> = {}) => ({
  name: 'Security news',
  description: 'Daily news',
  scheduling_period: 'PT1H',
  uri: 'https://news.example.com/rss',
  ssl_verify: null,
  confidence_level: 60,
  report_types: ['threat-report'],
  markings: [{ standard_id: socMarking.standard_id, definition_type: socMarking.definition_type, definition: socMarking.definition }],
  author: null,
  ...overrides,
});
const storedRss = (overrides: Record<string, unknown> = {}) => ({
  id: 'rss-id',
  internal_id: 'rss-id',
  name: 'Security news',
  description: 'Daily news',
  scheduling_period: 'PT1H',
  uri: 'https://news.example.com/rss',
  user_id: feedUser.id,
  report_types: ['threat-report'],
  object_marking_refs: [socMarking.id],
  ingestion_running: true,
  ...overrides,
});
const taxiiConfiguration = (overrides: Record<string, unknown> = {}) => ({
  name: 'Partner TAXII',
  uri: 'https://taxii.example.com',
  confidence_level: null,
  authentication_type: 'basic',
  version: 'v21',
  collection: 'collection-id',
  ...overrides,
});
const storedTaxii = (overrides: Record<string, unknown> = {}) => ({
  id: 'taxii-id',
  internal_id: 'taxii-id',
  name: 'Partner TAXII',
  uri: 'https://taxii.example.com',
  version: 'v21',
  collection: 'collection-id',
  authentication_type: 'basic',
  authentication_value: 'encrypted',
  user_id: feedUser.id,
  ...overrides,
});
const jsonConfiguration = (overrides: Record<string, unknown> = {}) => ({
  name: 'Vendor API',
  uri: 'https://api.example.com/indicators',
  authentication_type: 'none',
  markings: [],
  verb: 'get',
  headers: [{ name: 'Accept', value: 'application/json' }, { name: 'X-Api-Key', value: '' }],
  query_attributes: [],
  json_mapper: { name: 'Vendor mapper', variables: [], representations: [] },
  ...overrides,
});

const MAPPER_AUTHOR_ID = 'identity--11111111-1111-4111-8111-111111111111';
const MAPPER_MARKING_ID = 'marking-definition--22222222-2222-4222-8222-222222222222';
const csvConfiguration = () => ({
  name: 'Vendor CSV',
  uri: 'https://csv.example.com/indicators.csv',
  authentication_type: 'none',
  markings: [],
  csv_mapper: {
    name: 'Vendor mapper',
    has_header: true,
    separator: ',',
    representations: [{
      id: 'indicator',
      attributes: [
        { key: 'createdBy', default_values: [MAPPER_AUTHOR_ID] },
        { key: 'objectMarking', default_values: [MAPPER_MARKING_ID] },
        { key: 'indicator_types', default_values: ['malicious-activity'] },
      ],
    }],
  },
});

const rss = feedAdapterOf('rss');
const csv = feedAdapterOf('csv');
const taxii = feedAdapterOf('taxii');
const json = feedAdapterOf('json');

beforeEach(() => {
  vi.resetAllMocks();
  vi.mocked(getEntitiesMapFromCache).mockImplementation(async (_context, _user, type) => {
    if (type === 'Marking-Definition') {
      return new Map([[socMarking.id, socMarking], [socMarking.standard_id, socMarking]]) as never;
    }
    return new Map([[feedUser.id, feedUser]]) as never;
  });
  vi.mocked(storeLoadById).mockImplementation(async (_context, _user, id) => (id === feedUser.id ? feedUser : undefined) as never);
  vi.mocked(findDefaultIngestionGroups).mockResolvedValue([{ id: 'ingestion-group-id' }] as never);
  vi.mocked(userAlreadyExists).mockResolvedValue(false);
  vi.mocked(findAllRssIngestion).mockResolvedValue([]);
  vi.mocked(findAllTaxiiIngestion).mockResolvedValue([]);
  vi.mocked(findAllJsonIngestion).mockResolvedValue([]);
  vi.mocked(findAllCsvIngestion).mockResolvedValue([]);
  vi.mocked(internalFindByIds).mockResolvedValue({} as never);
  vi.mocked(fullEntitiesList).mockResolvedValue([]);
  vi.mocked(addIngestion).mockResolvedValue({ id: 'created-id' } as never);
  vi.mocked(ingestionTaxiiAdd).mockResolvedValue({ id: 'created-id' } as never);
});

const expectNothingWritten = () => {
  expect(addIngestion).not.toHaveBeenCalled();
  expect(ingestionEditField).not.toHaveBeenCalled();
  expect(ingestionTaxiiAdd).not.toHaveBeenCalled();
  expect(ingestionTaxiiEditField).not.toHaveBeenCalled();
};

describe('importConfigPresetFeed validation', () => {
  it.each([
    ['an unknown key', { current_state_date: '2026-01-01' }],
    ['a blank name', { name: ' ' }],
    ['a confidence over 100', { confidence_level: 101 }],
  ])('refuses %s, without writing', async (_, overrides) => {
    expect(await importConfigPresetFeed(context, user, rss, rssConfiguration(overrides), overwrite)).toMatchObject({ status: 'failed', code: 'invalid' });
    expectNothingWritten();
  });

  it('fails a feed whose marking is neither on the platform nor created by the import', async () => {
    vi.mocked(getEntitiesMapFromCache).mockResolvedValue(new Map() as never);
    const configuration = rssConfiguration();
    expect(await importConfigPresetFeed(context, user, rss, configuration, overwrite))
      .toMatchObject({ status: 'failed', code: 'markings_not_found', reason: 'Markings not found: INTERNAL:SOC' });
    const plannedMarkings = new Map([[socMarking.standard_id, {}]]);
    expect(await importConfigPresetFeed(context, user, rss, configuration, { ...overwrite, dryRun: true, plannedMarkings })).toMatchObject({ status: 'created' });
    expectNothingWritten();
  });
});

describe('importConfigPresetFeed creation', () => {
  it('creates a stopped feed with a new service account, its markings by internal id, nothing written in a dry run', async () => {
    expect(await importConfigPresetFeed(context, user, rss, rssConfiguration(), { ...overwrite, dryRun: true })).toMatchObject({ status: 'created', exists: false, name: 'Security news' });
    expectNothingWritten();
    expect(await importConfigPresetFeed(context, user, rss, rssConfiguration(), overwrite)).toMatchObject({ status: 'created' });
    expect(addIngestion).toHaveBeenCalledWith(context, user, {
      name: 'Security news',
      description: 'Daily news',
      scheduling_period: 'PT1H',
      uri: 'https://news.example.com/rss',
      ssl_verify: null,
      report_types: ['threat-report'],
      object_marking_refs: [socMarking.id],
      created_by_ref: null,
      ingestion_running: false,
      user_id: '[F] Security news',
      automatic_user: true,
      confidence_level: 60,
    });
  });

  it('runs a created feed with the service account chosen in the preview', async () => {
    await importConfigPresetFeed(context, user, rss, rssConfiguration(), { ...overwrite, serviceAccountId: feedUser.id });
    expect(addIngestion).toHaveBeenCalledWith(context, user, expect.objectContaining({ user_id: feedUser.id, automatic_user: false }));
  });

  it('asks for a service account without a default group for ingestion users, unless the import creates one', async () => {
    vi.mocked(findDefaultIngestionGroups).mockResolvedValue([]);
    expect(await importConfigPresetFeed(context, user, rss, rssConfiguration(), overwrite)).toMatchObject({ status: 'failed', code: 'no_ingestion_group' });
    expect(await importConfigPresetFeed(context, user, rss, rssConfiguration(), { ...overwrite, dryRun: true, ingestionGroupPlanned: true })).toMatchObject({ status: 'created' });
    expectNothingWritten();
  });

  it('drops an author missing on the platform, with a reason', async () => {
    const configuration = rssConfiguration({ author: { standard_id: 'identity--filigran', name: 'Filigran' } });
    expect(await importConfigPresetFeed(context, user, rss, configuration, overwrite)).toMatchObject({ status: 'created', reason: 'Author not found: Filigran' });
    expect(addIngestion).toHaveBeenCalledWith(context, user, expect.objectContaining({ created_by_ref: null }));
    vi.mocked(internalLoadById).mockResolvedValue({ id: 'filigran-id' } as never);
    await importConfigPresetFeed(context, user, rss, configuration, overwrite);
    expect(addIngestion).toHaveBeenLastCalledWith(context, user, expect.objectContaining({ created_by_ref: 'filigran-id' }));
  });
});

describe('importConfigPresetFeed with feeds of the same name', () => {
  it('overwrites the feed of the same name, keeping its user and its running state', async () => {
    vi.mocked(findAllRssIngestion).mockResolvedValue([storedRss({ uri: 'https://old.example.com/rss' })] as never);
    expect(await importConfigPresetFeed(context, user, rss, rssConfiguration(), overwrite)).toMatchObject({ status: 'overwritten', exists: true });
    const [, , id, input] = vi.mocked(ingestionEditField).mock.calls[0];
    expect(id).toEqual('rss-id');
    expect(input).toContainEqual({ key: 'uri', value: ['https://news.example.com/rss'] });
    expect(input.map(({ key }) => key)).not.toEqual(expect.arrayContaining(['user_id']));
    expect(input.map(({ key }) => key)).not.toContain('ingestion_running');
    expect(addIngestion).not.toHaveBeenCalled();
  });

  it('skips a feed that is already up to date, and tells when the confidence of its user differs', async () => {
    vi.mocked(findAllRssIngestion).mockResolvedValue([storedRss()] as never);
    expect(await importConfigPresetFeed(context, user, rss, rssConfiguration(), overwrite)).toMatchObject({ status: 'skipped', code: 'unchanged', reason: 'Already up to date' });
    expect(await importConfigPresetFeed(context, user, rss, rssConfiguration({ confidence_level: 80 }), overwrite)).toMatchObject({
      status: 'skipped',
      reason: 'Already up to date\nThe confidence level of the service account is not changed',
    });
    expectNothingWritten();
  });

  it('refuses to overwrite when several feeds have the name, or an earlier item of the import took it', async () => {
    vi.mocked(findAllRssIngestion).mockResolvedValue([storedRss(), storedRss({ id: 'other-id' })] as never);
    expect(await importConfigPresetFeed(context, user, rss, rssConfiguration(), overwrite)).toMatchObject({ status: 'failed', code: 'ambiguous', reason: AMBIGUOUS_FEED_REASON });
    vi.mocked(findAllRssIngestion).mockResolvedValue([]);
    expect(await importConfigPresetFeed(context, user, rss, rssConfiguration(), { ...overwrite, reservedNames: new Set(['Security news']) }))
      .toMatchObject({ status: 'failed', code: 'ambiguous' });
    expectNothingWritten();
  });

  it('adds a copy under the first free name, after the names an earlier item of the import took', async () => {
    vi.mocked(findAllRssIngestion).mockResolvedValue([storedRss()] as never);
    expect(await importConfigPresetFeed(context, user, rss, rssConfiguration(), { ...copy, reservedNames: new Set(['Security news (1)']) }))
      .toMatchObject({ status: 'created', name: 'Security news (2)', reason: 'Added as "Security news (2)"' });
    expect(addIngestion).toHaveBeenCalledWith(context, user, expect.objectContaining({ name: 'Security news (2)', user_id: '[F] Security news (2)' }));
  });
});

describe('importConfigPresetFeed credentials', () => {
  it('asks for the parts of the authentication of a created feed, and writes them', async () => {
    const result = await importConfigPresetFeed(context, user, taxii, taxiiConfiguration(), overwrite);
    expect(result).toMatchObject({ status: 'failed', code: 'credentials_required', reason: 'Configuration to provide: username, password' });
    expect(result.credentials?.map(({ key, secret, stored }) => [key, secret, stored])).toEqual([['username', false, false], ['password', true, false]]);
    expect(await importConfigPresetFeed(context, user, taxii, taxiiConfiguration(), { ...overwrite, credentials: { username: 'analyst', password: 'p4ss' } }))
      .toMatchObject({ status: 'created' });
    expect(ingestionTaxiiAdd).toHaveBeenCalledWith(context, user, expect.objectContaining({ authentication_type: 'basic', authentication_value: 'analyst:p4ss', ingestion_running: false }));
  });

  it('refuses a credential that the authentication cannot hold', async () => {
    expect(await importConfigPresetFeed(context, user, taxii, taxiiConfiguration(), { ...overwrite, credentials: { username: 'a:b', password: 'p4ss' } }))
      .toMatchObject({ status: 'failed', code: 'invalid' });
    expectNothingWritten();
  });

  it('keeps the stored credentials of an overwritten feed, and completes the parts given with them', async () => {
    vi.mocked(findAllTaxiiIngestion).mockResolvedValue([storedTaxii({ collection: 'old-collection' })] as never);
    const result = await importConfigPresetFeed(context, user, taxii, taxiiConfiguration(), overwrite);
    expect(result).toMatchObject({ status: 'overwritten' });
    expect(result.credentials?.every(({ stored }) => stored)).toBe(true);
    expect(vi.mocked(ingestionTaxiiEditField).mock.calls[0][3].map(({ key }) => key)).not.toContain('authentication_value');
    expect(vi.mocked(ingestionTaxiiEditField).mock.calls[0][3].map(({ key }) => key)).not.toContain('authentication_type');
    vi.mocked(decryptIngestionCredential).mockResolvedValue('analyst:old-pass');
    await importConfigPresetFeed(context, user, taxii, taxiiConfiguration(), { ...overwrite, credentials: { password: 'new-pass' } });
    expect(ingestionTaxiiEditField).toHaveBeenLastCalledWith(context, user, 'taxii-id', [{ key: 'authentication_value', value: ['analyst:new-pass'] }]);
  });

  it('asks for new credentials when the authentication type changes, written after the type that resets them', async () => {
    vi.mocked(findAllTaxiiIngestion).mockResolvedValue([storedTaxii()] as never);
    const configuration = taxiiConfiguration({ authentication_type: 'bearer' });
    expect(await importConfigPresetFeed(context, user, taxii, configuration, overwrite)).toMatchObject({ status: 'failed', code: 'credentials_required' });
    await importConfigPresetFeed(context, user, taxii, configuration, { ...overwrite, credentials: { token: 'new-token' } });
    expect(vi.mocked(ingestionTaxiiEditField).mock.calls[0][3]).toContainEqual({ key: 'authentication_type', value: ['bearer'] });
    expect(vi.mocked(ingestionTaxiiEditField).mock.calls[1][3]).toEqual([{ key: 'authentication_value', value: ['new-token'] }]);
  });

  it('asks for the value of a sensitive header, and creates the mapper and the service account of a JSON feed', async () => {
    vi.mocked(createJsonMapperFromConfiguration).mockResolvedValue({ id: 'mapper-id' } as never);
    vi.mocked(createIngestionAutomaticUser).mockResolvedValue({ id: 'service-account-id' } as never);
    vi.mocked(addIngestionJson).mockResolvedValue({ id: 'created-id' } as never);
    expect(await importConfigPresetFeed(context, user, json, jsonConfiguration(), overwrite))
      .toMatchObject({ status: 'failed', code: 'credentials_required', reason: 'Configuration to provide: header:X-Api-Key' });
    expect(await importConfigPresetFeed(context, user, json, jsonConfiguration(), { ...overwrite, credentials: { 'header:X-Api-Key': 'api-key' } }))
      .toMatchObject({ status: 'created', reason: 'JSON mapper created: Vendor mapper' });
    expect(createIngestionAutomaticUser).toHaveBeenCalledWith(context, user, { userName: '[F] Vendor API', serviceAccount: true, confidenceLevel: undefined });
    expect(addIngestionJson).toHaveBeenCalledWith(context, user, expect.objectContaining({
      json_mapper_id: 'mapper-id',
      user_id: 'service-account-id',
      headers: [{ name: 'Accept', value: 'application/json' }, { name: 'X-Api-Key', value: 'api-key' }],
    }));
  });
});

describe('importConfigPresetFeed mapper default values', () => {
  it('reports the attributes whose default value is not on the platform, removed when the mapper is written', async () => {
    vi.mocked(internalFindByIds).mockResolvedValue({ [MAPPER_MARKING_ID]: { id: 'mapper-marking-id' } } as never);
    vi.mocked(addIngestionCsv).mockResolvedValue({ id: 'created-id' } as never);
    expect(await importConfigPresetFeed(context, user, csv, csvConfiguration(), { ...overwrite, dryRun: true }))
      .toMatchObject({ status: 'created', reason: 'Mapper default values not found: createdBy' });
    expect(internalFindByIds).toHaveBeenCalledWith(context, user, [MAPPER_AUTHOR_ID, MAPPER_MARKING_ID], expect.anything());
  });

  it('counts a marking the same import creates as found', async () => {
    const plannedMarkings = new Map([[MAPPER_AUTHOR_ID, {}], [MAPPER_MARKING_ID, {}]]);
    expect(await importConfigPresetFeed(context, user, csv, csvConfiguration(), { ...overwrite, dryRun: true, plannedMarkings }))
      .toMatchObject({ status: 'created', reason: undefined });
    expect(internalFindByIds).not.toHaveBeenCalled();
  });
});

describe('importConfigPresetFeed review fixes', () => {
  it('refuses a denied URI in the preview, and a configuration nested too deeply', async () => {
    expect(await importConfigPresetFeed(context, user, rss, rssConfiguration({ uri: 'https://feeds.denied.com/rss' }), { ...overwrite, dryRun: true }))
      .toMatchObject({ status: 'failed', code: 'invalid', reason: 'This URI is not allowed for ingestion.' });
    let nested: Record<string, unknown> = {};
    const deep = nested;
    for (let i = 0; i < 100; i += 1) {
      nested.child = {};
      nested = nested.child as Record<string, unknown>;
    }
    expect(await importConfigPresetFeed(context, user, json, jsonConfiguration({ body: deep }), { ...overwrite, dryRun: true }))
      .toMatchObject({ status: 'failed', code: 'invalid', reason: 'configuration: too deeply nested' });
    expectNothingWritten();
  });

  it('tells the credentials of a copy when it refuses to overwrite', async () => {
    vi.mocked(findAllTaxiiIngestion).mockResolvedValue([storedTaxii(), storedTaxii({ id: 'other-id' })] as never);
    const result = await importConfigPresetFeed(context, user, taxii, taxiiConfiguration(), { ...overwrite, dryRun: true });
    expect(result).toMatchObject({ status: 'failed', code: 'ambiguous' });
    expect(result.credentials?.map(({ key, stored }) => [key, stored])).toEqual([['username', false], ['password', false]]);
  });

  it('accepts the HTTP verbs of the JSON feed forms, and an empty sub page verb', async () => {
    const configuration = jsonConfiguration({ verb: 'GET', pagination_with_sub_page_query_verb: '', headers: [] });
    expect(await importConfigPresetFeed(context, user, json, configuration, { ...overwrite, dryRun: true })).toMatchObject({ status: 'created' });
  });

  it('offers the blanked default of a query attribute sent in a sensitive header, and writes it', async () => {
    vi.mocked(createJsonMapperFromConfiguration).mockResolvedValue({ id: 'mapper-id' } as never);
    vi.mocked(createIngestionAutomaticUser).mockResolvedValue({ id: 'service-account-id' } as never);
    vi.mocked(addIngestionJson).mockResolvedValue({ id: 'created-id' } as never);
    const configuration = jsonConfiguration({ headers: [], query_attributes: [{ type: 'header', from: 'x-next', to: 'X-Next-Token', default: '', exposed: 'header' }] });
    const result = await importConfigPresetFeed(context, user, json, configuration, { ...overwrite, dryRun: true });
    expect(result).toMatchObject({ status: 'created' });
    expect(result.credentials).toContainEqual(expect.objectContaining({ key: 'header:X-Next-Token', required: false, secret: true }));
    await importConfigPresetFeed(context, user, json, configuration, { ...overwrite, credentials: { 'header:X-Next-Token': 'first-token' } });
    expect(addIngestionJson).toHaveBeenCalledWith(context, user, expect.objectContaining({
      query_attributes: [{ type: 'header', from: 'x-next', to: 'X-Next-Token', default: 'first-token', exposed: 'header' }],
    }));
  });

  it('fails a feed whose mapper sets a marking missing on the platform, without creating the mapper', async () => {
    const configuration = jsonConfiguration({
      headers: [],
      json_mapper: { name: 'Vendor mapper', variables: [], representations: [{ attributes: [{ key: 'objectMarking', default_values: [MAPPER_MARKING_ID] }] }] },
    });
    expect(await importConfigPresetFeed(context, user, json, configuration, overwrite))
      .toMatchObject({ status: 'failed', code: 'markings_not_found', reason: `Markings not found: ${MAPPER_MARKING_ID}` });
    expect(createJsonMapperFromConfiguration).not.toHaveBeenCalled();
    expect(addIngestionJson).not.toHaveBeenCalled();
  });

  it('deletes the mapper it created when the JSON feed cannot be written', async () => {
    vi.mocked(createJsonMapperFromConfiguration).mockResolvedValue({ id: 'mapper-id' } as never);
    vi.mocked(createIngestionAutomaticUser).mockResolvedValue({ id: 'service-account-id' } as never);
    vi.mocked(addIngestionJson).mockRejectedValue(new Error('Feed refused'));
    await expect(importConfigPresetFeed(context, user, json, jsonConfiguration({ headers: [] }), overwrite)).rejects.toThrow('Feed refused');
    expect(deleteJsonMapper).toHaveBeenCalledWith(context, user, 'mapper-id');
  });

  it('writes only the fields that change, so that an overwrite keeps the cursor of a TAXII feed', async () => {
    const stored = storedTaxii({ description: 'Old', added_after_start: new Date('2026-01-01T00:00:00.000Z') });
    vi.mocked(findAllTaxiiIngestion).mockResolvedValue([stored] as never);
    const configuration = taxiiConfiguration({ description: 'New', added_after_start: '2026-01-01T00:00:00.000Z' });
    expect(await importConfigPresetFeed(context, user, taxii, configuration, overwrite)).toMatchObject({ status: 'overwritten' });
    expect(vi.mocked(ingestionTaxiiEditField).mock.calls[0][3]).toEqual([{ key: 'description', value: ['New'] }]);
  });
});
