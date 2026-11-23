import { beforeEach, describe, expect, it, vi } from 'vitest';

const mocks = vi.hoisted(() => ({
  settings: {} as Record<string, string | undefined>,
  post: vi.fn(),
  clientOptions: [] as any[],
  warn: vi.fn(),
  jwt: vi.fn(async (user: { id: string }, target: string) => `jwt-${user.id}@${target}`),
}));

vi.mock('../../../../../../src/config/conf', () => ({
  isFeatureEnabled: (flag: string) => flag === 'XTM_COUNTERPARTS',
  default: { get: (key: string) => mocks.settings[key] },
  logApp: { info: vi.fn(), error: vi.fn(), warn: mocks.warn, debug: vi.fn() },
}));

// The keys are read from the database; the domain is tested on given sources.
vi.mock('../../../../../../src/modules/xtm/counterpart/core/counterpart-keys', () => ({ counterpartKeysOf: vi.fn(async () => []) }));

vi.mock('../../../../../../src/utils/http-client', () => ({
  getHttpClient: (options: any) => {
    mocks.clientOptions.push(options);
    return { post: mocks.post };
  },
}));

vi.mock('../../../../../../src/domain/xtm-auth', () => ({ issueXtmJwt: mocks.jwt }));

import { counterpartKeysOf } from '../../../../../../src/modules/xtm/counterpart/core/counterpart-keys';
import { fetchOpenAevObjects, getOpenAevUrl, isOpenAevConnected, OPENAEV_DEFAULT_TENANT_ID } from '../../../../../../src/modules/xtm/counterpart/openaev/openaev-client';
import {
  CounterpartLookupError,
  findXtmConnections,
  findXtmCounterpartsByIds,
  resetCounterpartCache,
  sanitiseFacts,
} from '../../../../../../src/modules/xtm/counterpart/core/counterpart-domain';
import { openAevProvider } from '../../../../../../src/modules/xtm/counterpart/openaev/openaev-provider';
import '../../../../../../src/modules/xtm/counterpart/opencrq/opencrq-provider';

const ALICE = { id: 'alice', user_email: 'alice@example.com' };

const remote = (key: string, extra: Record<string, unknown> = {}) => ({
  object_key: key,
  object_id: `id-${key}`,
  object_type: 'Endpoint',
  object_name: key,
  object_url: `https://aev.example.com/admin/assets/id-${key}`,
  ...extra,
});

const connect = () => {
  mocks.settings['xtm:openaev_url'] = 'https://aev.example.com//';
};

describe('OpenAEV client', () => {
  beforeEach(() => {
    mocks.settings = {};
    mocks.post.mockReset();
    mocks.clientOptions = [];
    mocks.warn.mockReset();
    mocks.jwt.mockClear();
    resetCounterpartCache();
  });

  it('is connected by its URL alone: the lookups run as the calling user', () => {
    expect(getOpenAevUrl()).toBeNull();
    expect(isOpenAevConnected()).toBe(false);
    mocks.settings['xtm:openaev_url'] = 'https://aev.example.com/';
    expect(getOpenAevUrl()).toBe('https://aev.example.com');
    expect(isOpenAevConnected()).toBe(true);
  });

  it('never calls OpenAEV when not connected or without keys', async () => {
    expect(await fetchOpenAevObjects('assets', ['web-01'], ALICE)).toEqual([]);
    connect();
    expect(await fetchOpenAevObjects('assets', [], ALICE)).toEqual([]);
    expect(mocks.post).not.toHaveBeenCalled();
  });

  it('posts the keys to the default tenant with a JWT of the calling user addressed to OpenAEV', async () => {
    connect();
    mocks.post.mockResolvedValue({ data: [remote('web-01')] });
    const result = await fetchOpenAevObjects('assets', ['web-01'], ALICE);
    expect(result).toEqual([remote('web-01')]);
    expect(mocks.post).toHaveBeenCalledWith(
      `/api/tenants/${OPENAEV_DEFAULT_TENANT_ID}/xtm/objects/assets`,
      { counterpart_keys: ['web-01'] },
      { maxRedirects: 0 },
    );
    expect(mocks.jwt).toHaveBeenCalledWith(ALICE, 'https://aev.example.com');
    expect(mocks.clientOptions[0].baseURL).toBe('https://aev.example.com');
    expect(mocks.clientOptions[0].headers.Authorization).toBe('Bearer jwt-alice@https://aev.example.com');
  });

  it('uses the configured tenant', async () => {
    connect();
    mocks.settings['xtm:openaev_tenant_id'] = 'tenant/a';
    mocks.post.mockResolvedValue({ data: [] });
    await fetchOpenAevObjects('threats', ['x'], ALICE);
    expect(mocks.post.mock.calls[0][0]).toBe('/api/tenants/tenant%2Fa/xtm/objects/threats');
  });

  it('a 404 (no such route) is not_supported', async () => {
    connect();
    mocks.post.mockRejectedValueOnce(Object.assign(new Error('nf'), { status: 404 }));
    await expect(fetchOpenAevObjects('assets', ['web-01'], ALICE)).rejects.toMatchObject({ reason: 'not_supported' });
  });

  it('a 403 (no OpenAEV right on that kind) is forbidden', async () => {
    connect();
    mocks.post.mockRejectedValueOnce(Object.assign(new Error('denied'), { status: 403 }));
    await expect(fetchOpenAevObjects('assets', ['web-01'], ALICE)).rejects.toMatchObject({ reason: 'forbidden' });
    // 403 and 404 are left to the domain: the client warns only on an outage.
    expect(mocks.warn).not.toHaveBeenCalled();
  });

  it('trusts the administrator-configured URL past the outbound guard', async () => {
    connect();
    mocks.post.mockResolvedValue({ data: [] });
    await fetchOpenAevObjects('assets', ['web-01'], ALICE);
    expect(mocks.clientOptions[0].trusted).toBe(true);
  });

  it.each([401, 500, 502])('a %s is unavailable', async (status) => {
    connect();
    mocks.post.mockRejectedValueOnce(Object.assign(new Error('boom'), { status }));
    await expect(fetchOpenAevObjects('assets', ['web-01'], ALICE)).rejects.toMatchObject({ reason: 'unavailable' });
  });

  it('a timeout or a non-list body is unavailable, logged without the token', async () => {
    connect();
    mocks.post.mockRejectedValueOnce(Object.assign(new Error('timeout'), { code: 'ECONNABORTED' }));
    await expect(fetchOpenAevObjects('assets', ['web-01'], ALICE)).rejects.toBeInstanceOf(CounterpartLookupError);
    mocks.post.mockResolvedValueOnce({ data: { unexpected: true } });
    await expect(fetchOpenAevObjects('assets', ['web-01'], ALICE)).rejects.toMatchObject({ reason: 'unavailable' });
    expect(JSON.stringify(mocks.warn.mock.calls)).not.toContain('jwt-alice');
  });
});

describe('OpenAEV counterpart provider', () => {
  beforeEach(() => {
    mocks.settings = {};
    mocks.post.mockReset();
    mocks.clientOptions = [];
    resetCounterpartCache();
  });

  it('supports the five kinds', () => {
    for (const kind of ['ASSET', 'ATTACK_PATTERN', 'VULNERABILITY', 'THREAT', 'ALERT'] as const) {
      expect(openAevProvider.supports(kind)).toBe(true);
    }
  });

  it('maps the kind to its path, normalises the returned keys and drops what was not asked or is malformed', async () => {
    connect();
    mocks.post.mockResolvedValue({
      data: [
        remote('cve-2024-3400', { object_type: 'Vulnerability', object_name: undefined }),
        remote('CVE-2023-0001'),
        { object_key: 'CVE-2024-3400', object_id: 42, object_url: 'x' },
        null,
      ],
    });
    const result = await openAevProvider.resolve('VULNERABILITY', ['CVE-2024-3400'], ALICE);
    expect(mocks.post.mock.calls[0][0]).toContain('/xtm/objects/vulnerabilities');
    expect(result).toEqual([{
      key: 'CVE-2024-3400',
      product: 'openaev',
      object_id: 'id-cve-2024-3400',
      object_type: 'Vulnerability',
      object_name: null,
      object_url: 'https://aev.example.com/admin/assets/id-cve-2024-3400',
      facts: [],
    }]);
  });

  it('keeps the well-formed key facts OpenAEV answers and drops the rest', async () => {
    connect();
    mocks.post.mockResolvedValue({
      data: [remote('CVE-2024-3400', {
        object_facts: [
          { fact_key: 'findings', fact_value: '5' },
          { fact_key: 'affected_assets', fact_value: '2' },
          { fact_key: 'Bad Key', fact_value: '1' },
          { fact_key: 'simulations', fact_value: 'x'.repeat(65) },
          { fact_key: 'last_simulation', fact_value: 7 },
          null,
        ],
      })],
    });
    const [found] = await openAevProvider.resolve('VULNERABILITY', ['CVE-2024-3400'], ALICE);
    expect(found.facts).toEqual([{ key: 'findings', value: '5' }, { key: 'affected_assets', value: '2' }]);
    expect(sanitiseFacts('not a list')).toEqual([]);
    expect(sanitiseFacts(Array.from({ length: 20 }, () => ({ fact_key: 'findings', fact_value: '1' })))).toHaveLength(10);
  });

  it('a user without rights in OpenAEV gets the link without facts, as OpenAEV answers it', async () => {
    connect();
    mocks.post.mockResolvedValue({ data: [remote('web-01', { object_facts: null })] });
    const [found] = await openAevProvider.resolve('ASSET', ['web-01'], ALICE);
    expect(found.object_url).toBe('https://aev.example.com/admin/assets/id-web-01');
    expect(found.facts).toEqual([]);
  });

  it('serves the GraphQL entry points through the registered provider', async () => {
    const context = {} as any;
    const user = { id: 'alice', user_email: 'alice@example.com' } as any;
    expect(await findXtmConnections(context, user)).toEqual([
      { product: 'openaev', connected: false },
      { product: 'opencrq', connected: false },
    ]);
    connect();
    expect(await findXtmConnections(context, user)).toEqual([
      { product: 'openaev', connected: true },
      { product: 'opencrq', connected: false },
    ]);
    vi.mocked(counterpartKeysOf).mockResolvedValueOnce([{ id: 'ap-1', kind: 'ATTACK_PATTERN', keys: ['T1059.001'] }]);
    mocks.post.mockResolvedValue({ data: [remote('T1059.001', { object_type: 'AttackPattern' })] });
    const results = await findXtmCounterpartsByIds(context, user, ['ap-1', 'unreadable-1']);
    expect(results.map(({ id, product, status }) => ({ id, product, status }))).toEqual([
      { id: 'ap-1', product: 'openaev', status: 'found' },
    ]);
    expect(results[0].counterpart?.key).toBe('T1059.001');
    expect(mocks.post).toHaveBeenCalledWith(expect.stringContaining('/xtm/objects/attack-patterns'), { counterpart_keys: ['T1059.001'] }, { maxRedirects: 0 });
  });
});
