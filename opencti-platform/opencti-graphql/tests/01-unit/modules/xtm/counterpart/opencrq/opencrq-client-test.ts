import { beforeEach, describe, expect, it, vi } from 'vitest';

const mocks = vi.hoisted(() => ({
  settings: {} as Record<string, string | undefined>,
  get: vi.fn(),
  clientOptions: [] as any[],
  warn: vi.fn(),
  jwt: vi.fn(async (user: { id: string }, target: string) => `jwt-${user.id}@${target}`),
  exchange: vi.fn(async (_user: { id: string }, _audience: string): Promise<string | undefined> => undefined),
}));

vi.mock('../../../../../../src/config/conf', () => ({
  default: { get: (key: string) => mocks.settings[key] },
  logApp: { info: vi.fn(), error: vi.fn(), warn: mocks.warn, debug: vi.fn() },
}));

// The keys are read from the database; the domain is tested on given sources.
vi.mock('../../../../../../src/modules/xtm/counterpart/core/counterpart-keys', () => ({ counterpartKeysOf: vi.fn(async () => []) }));

vi.mock('../../../../../../src/utils/http-client', () => ({
  getHttpClient: (options: any) => {
    mocks.clientOptions.push(options);
    return { get: mocks.get };
  },
}));

vi.mock('../../../../../../src/domain/xtm-auth', () => ({ issueXtmJwt: mocks.jwt, exchangeXtmOneUserToken: mocks.exchange }));

import { fetchOpenCrqObjects, getOpenCrqApiUrl, getOpenCrqUrl, isOpenCrqConnected } from '../../../../../../src/modules/xtm/counterpart/opencrq/opencrq-client';
import { openCrqProvider, resetCounterpartCache, resolveCounterpartsOfSources } from '../../../../../../src/modules/xtm/counterpart/core/counterpart-domain';

const STIX = 'intrusion-set--3b0a1c2d-0000-4000-8000-000000000001';
const ALICE = { id: 'alice', user_email: 'alice@example.com' };

const remote = (key: string, extra: Record<string, unknown> = {}) => ({
  object_key: key,
  object_id: `id-${key}`,
  object_type: 'threat',
  object_name: key,
  object_url: `https://crq.example.com/threats/id-${key}`,
  ...extra,
});

const connect = () => {
  mocks.settings['xtm:opencrq_url'] = 'https://crq.example.com/';
};

const tRpc = (data: unknown) => ({ data: { result: { data } } });

describe('OpenCRQ client', () => {
  beforeEach(() => {
    mocks.settings = {};
    mocks.get.mockReset();
    mocks.clientOptions = [];
    mocks.warn.mockReset();
    mocks.jwt.mockClear();
    mocks.exchange.mockReset();
    mocks.exchange.mockResolvedValue(undefined);
    resetCounterpartCache();
  });

  it('is connected by its URL alone and derives the tRPC base', () => {
    expect(getOpenCrqUrl()).toBeNull();
    expect(getOpenCrqApiUrl()).toBeNull();
    expect(isOpenCrqConnected()).toBe(false);
    mocks.settings['xtm:opencrq_url'] = 'https://crq.example.com//';
    expect(getOpenCrqUrl()).toBe('https://crq.example.com');
    expect(getOpenCrqApiUrl()).toBe('https://crq.example.com/trpc');
    expect(isOpenCrqConnected()).toBe(true);
    mocks.settings['xtm:opencrq_api_url'] = 'https://crq-api.internal/trpc/';
    expect(getOpenCrqApiUrl()).toBe('https://crq-api.internal/trpc');
  });

  it('never calls OpenCRQ when not connected or without keys', async () => {
    expect(await fetchOpenCrqObjects('THREAT', [STIX], ALICE)).toEqual([]);
    connect();
    expect(await fetchOpenCrqObjects('THREAT', [], ALICE)).toEqual([]);
    expect(mocks.get).not.toHaveBeenCalled();
  });

  it('queries xtm.lookup with the kind and keys and a JWT of the calling user addressed to OpenCRQ', async () => {
    connect();
    mocks.get.mockResolvedValue(tRpc([remote(STIX)]));
    const result = await fetchOpenCrqObjects('THREAT', [STIX], ALICE);
    expect(result).toEqual([remote(STIX)]);
    const url = mocks.get.mock.calls[0][0] as string;
    expect(url.startsWith('/xtm.lookup?input=')).toBe(true);
    expect(JSON.parse(decodeURIComponent(url.slice('/xtm.lookup?input='.length)))).toEqual({ kind: 'THREAT', keys: [STIX] });
    expect(mocks.clientOptions[0].baseURL).toBe('https://crq.example.com/trpc');
    expect(mocks.jwt).toHaveBeenCalledWith(ALICE, 'https://crq.example.com');
    expect(mocks.clientOptions[0].headers.Authorization).toBe('Bearer jwt-alice@https://crq.example.com');
    expect(mocks.clientOptions[0].headers).not.toHaveProperty('X-XTM-User-Token');
  });

  it('forwards the user token XTM One exchanged for the calling user, addressed to OpenCRQ', async () => {
    connect();
    mocks.exchange.mockResolvedValue('xtm-one-token-alice');
    mocks.get.mockResolvedValue(tRpc([remote(STIX)]));
    await fetchOpenCrqObjects('THREAT', [STIX], ALICE);
    expect(mocks.exchange).toHaveBeenCalledWith(ALICE, 'https://crq.example.com');
    expect(mocks.clientOptions[0].headers['X-XTM-User-Token']).toBe('xtm-one-token-alice');
    expect(mocks.clientOptions[0].headers.Authorization).toBe('Bearer jwt-alice@https://crq.example.com');
  });

  it('keeps the lookup without the header when XTM One is absent or refuses the exchange', async () => {
    connect();
    mocks.exchange.mockResolvedValue(undefined);
    mocks.get.mockResolvedValue(tRpc([remote(STIX)]));
    expect(await fetchOpenCrqObjects('THREAT', [STIX], ALICE)).toEqual([remote(STIX)]);
    expect(mocks.clientOptions[0].headers).not.toHaveProperty('X-XTM-User-Token');
  });

  it('a 404 (no xtm.lookup on that OpenCRQ) is not_supported, anything else unavailable, never logging the token', async () => {
    connect();
    mocks.get.mockRejectedValueOnce(Object.assign(new Error('nf'), { status: 404 }));
    await expect(fetchOpenCrqObjects('THREAT', [STIX], ALICE)).rejects.toMatchObject({ reason: 'not_supported' });
    mocks.get.mockRejectedValueOnce(Object.assign(new Error('boom'), { status: 401 }));
    await expect(fetchOpenCrqObjects('THREAT', [STIX], ALICE)).rejects.toMatchObject({ reason: 'unavailable' });
    mocks.get.mockResolvedValueOnce({ data: { result: {} } });
    await expect(fetchOpenCrqObjects('THREAT', [STIX], ALICE)).rejects.toMatchObject({ reason: 'unavailable' });
    expect(JSON.stringify(mocks.warn.mock.calls)).not.toContain('jwt-alice');
  });

  it('resolves CVEs, threats and assets with the risk facts and ignores unsupported kinds', async () => {
    connect();
    expect(openCrqProvider.supports('ATTACK_PATTERN')).toBe(false);
    expect(openCrqProvider.supports('ALERT')).toBe(false);
    expect(openCrqProvider.supports('VULNERABILITY')).toBe(true);
    mocks.get.mockResolvedValue(tRpc([
      remote('cve-2024-3400', {
        object_type: 'vulnerability',
        object_facts: [
          { key: 'risk_scenarios', value: '2' },
          { key: 'annual_loss', value: '1250000' },
          { key: 'Bad Key', value: '1' },
        ],
      }),
      remote('CVE-2000-0001'),
      { object_key: 'CVE-2024-0002', object_id: 'no-url' },
    ]));
    const found = await openCrqProvider.resolve('VULNERABILITY', ['CVE-2024-3400'], ALICE);
    expect(found).toEqual([{
      key: 'CVE-2024-3400',
      product: 'opencrq',
      object_id: 'id-cve-2024-3400',
      object_type: 'vulnerability',
      object_name: 'cve-2024-3400',
      object_url: 'https://crq.example.com/threats/id-cve-2024-3400',
      facts: [{ key: 'risk_scenarios', value: '2' }, { key: 'annual_loss', value: '1250000' }],
    }]);
  });

  it('a user without rights in OpenCRQ gets the link without the financial facts, as OpenCRQ answers it', async () => {
    connect();
    mocks.get.mockResolvedValue(tRpc([remote('web-01', { object_type: 'asset', object_facts: [] })]));
    const [found] = await openCrqProvider.resolve('ASSET', ['web-01'], ALICE);
    expect(found.object_url).toBe('https://crq.example.com/threats/id-web-01');
    expect(found.facts).toEqual([]);
  });

  it('is skipped by the resolver when not connected and cached per user and product when it is', async () => {
    const sources = [{ id: 'sys-1', kind: 'ASSET' as const, keys: ['web-01'] }];
    expect(await resolveCounterpartsOfSources(sources, ALICE, [openCrqProvider])).toEqual([]);
    expect(mocks.get).not.toHaveBeenCalled();
    connect();
    mocks.get.mockResolvedValue(tRpc([remote('web-01', { object_type: 'asset' })]));
    const first = await resolveCounterpartsOfSources(sources, ALICE, [openCrqProvider]);
    const second = await resolveCounterpartsOfSources(sources, ALICE, [openCrqProvider]);
    expect(first.map((r) => r.counterpart?.key)).toEqual(['web-01']);
    expect(second).toEqual(first);
    expect(mocks.get).toHaveBeenCalledTimes(1);
  });
});
