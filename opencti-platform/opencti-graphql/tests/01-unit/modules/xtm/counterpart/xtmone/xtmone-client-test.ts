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

vi.mock('../../../../../../src/modules/xtm/counterpart/core/counterpart-keys', () => ({ counterpartKeysOf: vi.fn(async () => []) }));

vi.mock('../../../../../../src/utils/http-client', () => ({
  getHttpClient: (options: any) => {
    mocks.clientOptions.push(options);
    return { post: mocks.post };
  },
}));

vi.mock('../../../../../../src/domain/xtm-auth', () => ({ issueXtmJwt: mocks.jwt }));

import { fetchXtmOneAssets, getXtmOneUrl, isXtmOneConnected, XTM_ONE_LOOKUP_PATH } from '../../../../../../src/modules/xtm/counterpart/xtmone/xtmone-client';
import { resetCounterpartCache, resolveCounterpartsOfSources } from '../../../../../../src/modules/xtm/counterpart/core/counterpart-domain';
import { xtmOneProvider } from '../../../../../../src/modules/xtm/counterpart/xtmone/xtmone-provider';

const ALICE = { id: 'alice', user_email: 'alice@example.com' };

const item = (key: string, extra: Record<string, unknown> = {}) => ({
  key,
  id: `asset-${key}`,
  name: key,
  category: 'server',
  criticality: 'high',
  matches: 1,
  url: `https://one.example.com/ctem/inventory/assets/asset-${key}`,
  ...extra,
});

const connect = () => {
  mocks.settings['xtm:xtm_one_url'] = 'https://one.example.com/';
  mocks.settings['xtm:xtm_one_token'] = 'platform-token';
};

describe('XTM One counterpart client', () => {
  beforeEach(() => {
    mocks.settings = {};
    mocks.post.mockReset();
    mocks.clientOptions = [];
    mocks.warn.mockReset();
    mocks.jwt.mockClear();
    resetCounterpartCache();
  });

  it('is connected by the XTM One connection of the platform (URL and token)', () => {
    expect(getXtmOneUrl()).toBeNull();
    expect(isXtmOneConnected()).toBe(false);
    mocks.settings['xtm:xtm_one_url'] = 'https://one.example.com//';
    expect(getXtmOneUrl()).toBe('https://one.example.com');
    expect(isXtmOneConnected()).toBe(false);
    mocks.settings['xtm:xtm_one_token'] = 'platform-token';
    expect(isXtmOneConnected()).toBe(true);
  });

  it('never calls XTM One when not connected or without keys', async () => {
    expect(await fetchXtmOneAssets(['web-01'], ALICE)).toEqual([]);
    connect();
    expect(await fetchXtmOneAssets([], ALICE)).toEqual([]);
    expect(mocks.post).not.toHaveBeenCalled();
  });

  it('posts the keys to the inventory lookup with a JWT of the calling user, never the platform token', async () => {
    connect();
    mocks.post.mockResolvedValue({ data: { items: [item('web-01')] } });
    const result = await fetchXtmOneAssets(['web-01'], ALICE);
    expect(mocks.post).toHaveBeenCalledWith(XTM_ONE_LOOKUP_PATH, { keys: ['web-01'] }, { maxRedirects: 0 });
    expect(mocks.clientOptions[0].baseURL).toBe('https://one.example.com');
    expect(mocks.jwt).toHaveBeenCalledWith(ALICE, 'https://one.example.com');
    expect(mocks.clientOptions[0].headers.Authorization).toBe('Bearer jwt-alice@https://one.example.com');
    expect(JSON.stringify(mocks.clientOptions[0].headers)).not.toContain('platform-token');
    expect(result).toEqual([{
      object_key: 'web-01',
      object_id: 'asset-web-01',
      object_type: 'asset',
      object_name: 'web-01',
      object_url: 'https://one.example.com/ctem/inventory/assets/asset-web-01',
      object_facts: [{ key: 'criticality', value: 'high' }, { key: 'category', value: 'server' }],
    }]);
  });

  it('drops malformed items and empty facts', async () => {
    connect();
    mocks.post.mockResolvedValue({ data: { items: [item('web-01', { criticality: null, category: '' }), { key: 'web-02', id: 'no-url' }, 'junk'] } });
    const result = await fetchXtmOneAssets(['web-01', 'web-02'], ALICE);
    expect(result.map((r) => r.object_key)).toEqual(['web-01']);
    expect(result[0].object_facts).toEqual([]);
  });

  it('a 404 (an XTM One without the lookup) is not_supported, anything else unavailable, never logging the token', async () => {
    connect();
    mocks.post.mockRejectedValueOnce(Object.assign(new Error('nf'), { response: { status: 404 } }));
    await expect(fetchXtmOneAssets(['web-01'], ALICE)).rejects.toMatchObject({ reason: 'not_supported' });
    mocks.post.mockRejectedValueOnce(Object.assign(new Error('denied'), { response: { status: 403 } }));
    await expect(fetchXtmOneAssets(['web-01'], ALICE)).rejects.toMatchObject({ reason: 'forbidden' });
    expect(mocks.warn).not.toHaveBeenCalled();
    mocks.post.mockRejectedValueOnce(Object.assign(new Error('boom'), { response: { status: 502 } }));
    await expect(fetchXtmOneAssets(['web-01'], ALICE)).rejects.toMatchObject({ reason: 'unavailable' });
    mocks.post.mockResolvedValueOnce({ data: {} });
    await expect(fetchXtmOneAssets(['web-01'], ALICE)).rejects.toMatchObject({ reason: 'unavailable' });
    expect(JSON.stringify(mocks.warn.mock.calls)).not.toContain('jwt-alice');
  });

  it('supports assets only and resolves them through the shared resolver under the caller', async () => {
    expect(xtmOneProvider.supports('ASSET')).toBe(true);
    expect(xtmOneProvider.supports('VULNERABILITY')).toBe(false);
    expect(xtmOneProvider.supports('THREAT')).toBe(false);
    const sources = [{ id: 'sys-1', kind: 'ASSET' as const, keys: ['web-01'] }, { id: 'vuln-1', kind: 'VULNERABILITY' as const, keys: ['CVE-2024-3400'] }];
    expect(await resolveCounterpartsOfSources(sources, ALICE, [xtmOneProvider])).toEqual([]);
    connect();
    mocks.post.mockResolvedValue({ data: { items: [item('web-01')] } });
    const results = await resolveCounterpartsOfSources(sources, ALICE, [xtmOneProvider]);
    expect(results.map(({ id, product, status }) => ({ id, product, status }))).toEqual([
      { id: 'sys-1', product: 'xtmone', status: 'found' },
      { id: 'vuln-1', product: 'xtmone', status: 'not_supported' },
    ]);
    expect(results[0].counterpart?.facts).toEqual([{ key: 'criticality', value: 'high' }, { key: 'category', value: 'server' }]);
    expect(mocks.post).toHaveBeenCalledTimes(1);
  });
});
