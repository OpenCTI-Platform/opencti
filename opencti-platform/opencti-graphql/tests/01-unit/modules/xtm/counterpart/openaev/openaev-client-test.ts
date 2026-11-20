import { beforeEach, describe, expect, it, vi } from 'vitest';

const mocks = vi.hoisted(() => ({
  settings: {} as Record<string, string | undefined>,
  post: vi.fn(),
  clientOptions: [] as any[],
  warn: vi.fn(),
}));

vi.mock('../../../../../../src/config/conf', () => ({
  default: { get: (key: string) => mocks.settings[key] },
  logApp: { info: vi.fn(), error: vi.fn(), warn: mocks.warn, debug: vi.fn() },
}));

vi.mock('../../../../../../src/utils/http-client', () => ({
  getHttpClient: (options: any) => {
    mocks.clientOptions.push(options);
    return { post: mocks.post };
  },
}));

import { fetchOpenAevObjects, getOpenAevUrl, isOpenAevConnected, OPENAEV_DEFAULT_TENANT_ID } from '../../../../../../src/modules/xtm/counterpart/openaev/openaev-client';
import {
  findXtmConnections,
  findXtmCounterparts,
  openAevProvider,
  resetCounterpartCache,
  sanitiseFacts,
} from '../../../../../../src/modules/xtm/counterpart/core/counterpart-domain';

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
  mocks.settings['xtm:openaev_token'] = 'secret-token';
};

describe('OpenAEV client', () => {
  beforeEach(() => {
    mocks.settings = {};
    mocks.post.mockReset();
    mocks.clientOptions = [];
    mocks.warn.mockReset();
    resetCounterpartCache();
  });

  it('is not connected without both the URL and the token', () => {
    expect(getOpenAevUrl()).toBeNull();
    expect(isOpenAevConnected()).toBe(false);
    mocks.settings['xtm:openaev_url'] = 'https://aev.example.com/';
    expect(getOpenAevUrl()).toBe('https://aev.example.com');
    expect(isOpenAevConnected()).toBe(false);
    mocks.settings['xtm:openaev_token'] = 'secret-token';
    expect(isOpenAevConnected()).toBe(true);
  });

  it('never calls OpenAEV when not connected or without keys', async () => {
    expect(await fetchOpenAevObjects('assets', ['web-01'])).toEqual([]);
    connect();
    expect(await fetchOpenAevObjects('assets', [])).toEqual([]);
    expect(mocks.post).not.toHaveBeenCalled();
  });

  it('posts the keys to the default tenant with the token', async () => {
    connect();
    mocks.post.mockResolvedValue({ data: [remote('web-01')] });
    const result = await fetchOpenAevObjects('assets', ['web-01']);
    expect(result).toEqual([remote('web-01')]);
    expect(mocks.post).toHaveBeenCalledWith(
      `/api/tenants/${OPENAEV_DEFAULT_TENANT_ID}/xtm/objects/assets`,
      { counterpart_keys: ['web-01'] },
    );
    expect(mocks.clientOptions[0].baseURL).toBe('https://aev.example.com');
    expect(mocks.clientOptions[0].headers.Authorization).toBe('Bearer secret-token');
  });

  it('uses the configured tenant', async () => {
    connect();
    mocks.settings['xtm:openaev_tenant_id'] = 'tenant/a';
    mocks.post.mockResolvedValue({ data: [] });
    await fetchOpenAevObjects('threats', ['x']);
    expect(mocks.post.mock.calls[0][0]).toBe('/api/tenants/tenant%2Fa/xtm/objects/threats');
  });

  it('answers nothing on a non-list body or an error, without logging the token', async () => {
    connect();
    mocks.post.mockResolvedValueOnce({ data: { unexpected: true } });
    expect(await fetchOpenAevObjects('assets', ['web-01'])).toEqual([]);
    mocks.post.mockRejectedValueOnce(Object.assign(new Error('boom'), { status: 502, code: 'ERR_BAD_RESPONSE' }));
    expect(await fetchOpenAevObjects('assets', ['web-01'])).toEqual([]);
    expect(mocks.warn).toHaveBeenCalledWith('[OPENAEV] Counterpart lookup failed', { path: 'assets', status: 502, code: 'ERR_BAD_RESPONSE' });
    expect(JSON.stringify(mocks.warn.mock.calls)).not.toContain('secret-token');
  });
});

describe('OpenAEV counterpart provider', () => {
  beforeEach(() => {
    mocks.settings = {};
    mocks.post.mockReset();
    mocks.clientOptions = [];
    resetCounterpartCache();
  });

  it('supports the four kinds', () => {
    expect(openAevProvider.supports('ASSET')).toBe(true);
    expect(openAevProvider.supports('ATTACK_PATTERN')).toBe(true);
    expect(openAevProvider.supports('VULNERABILITY')).toBe(true);
    expect(openAevProvider.supports('THREAT')).toBe(true);
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
    const result = await openAevProvider.resolve('VULNERABILITY', ['CVE-2024-3400']);
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
    const [found] = await openAevProvider.resolve('VULNERABILITY', ['CVE-2024-3400']);
    expect(found.facts).toEqual([{ key: 'findings', value: '5' }, { key: 'affected_assets', value: '2' }]);
    expect(sanitiseFacts('not a list')).toEqual([]);
    expect(sanitiseFacts(Array.from({ length: 20 }, () => ({ fact_key: 'findings', fact_value: '1' })))).toHaveLength(10);
  });

  it('serves the GraphQL entry points through the registered provider', async () => {
    const context = {} as any;
    const user = {} as any;
    expect(await findXtmConnections(context, user)).toEqual([
      { product: 'openaev', connected: false, url: null },
      { product: 'opencrq', connected: false, url: null },
    ]);
    connect();
    expect(await findXtmConnections(context, user)).toEqual([
      { product: 'openaev', connected: true, url: 'https://aev.example.com' },
      { product: 'opencrq', connected: false, url: null },
    ]);
    mocks.post.mockResolvedValue({ data: [remote('T1059.001', { object_type: 'AttackPattern' })] });
    const found = await findXtmCounterparts(context, user, 'ATTACK_PATTERN', ['t1059.001', 'Phishing']);
    expect(found.map((c) => c.key)).toEqual(['T1059.001']);
    expect(mocks.post).toHaveBeenCalledWith(expect.stringContaining('/xtm/objects/attack-patterns'), { counterpart_keys: ['T1059.001'] });
  });
});
