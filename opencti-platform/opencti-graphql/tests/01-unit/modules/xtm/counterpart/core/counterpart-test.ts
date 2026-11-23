import { beforeEach, describe, expect, it, vi } from 'vitest';

const mocks = vi.hoisted(() => ({ warn: vi.fn(), flagOn: true }));

vi.mock('../../../../../../src/config/conf', () => ({
  isFeatureEnabled: (flag: string) => flag === 'XTM_COUNTERPARTS' && mocks.flagOn !== false,
  default: { get: () => undefined },
  logApp: { info: vi.fn(), error: vi.fn(), warn: mocks.warn, debug: vi.fn() },
}));

// The keys are read from the database; the domain is tested on given sources.
vi.mock('../../../../../../src/modules/xtm/counterpart/core/counterpart-keys', () => ({ counterpartKeysOf: vi.fn(async () => []) }));

vi.mock('../../../../../../src/utils/http-client', () => ({
  getHttpClient: () => ({ post: () => Promise.reject(new Error('no network in unit tests')) }),
}));

vi.mock('../../../../../../src/domain/xtm-auth', () => ({
  issueXtmJwt: async (user: { id: string }, target: string) => `jwt-${user.id}-${target}`,
}));

import {
  type CounterpartProvider,
  COUNTERPART_CACHE_TTL_MS,
  CounterpartLookupError,
  normaliseCounterpartKey,
  resetCounterpartCache,
  resolveCounterpartsOfSources,
  registerCounterpartProvider,
  xtmConnections,
  findXtmConnections,
  findXtmCounterpartsByIds,
  type XtmCounterpart,
} from '../../../../../../src/modules/xtm/counterpart/core/counterpart-domain';

describe('XTM counterparts: dedicated feature flag XTM_COUNTERPARTS', () => {
  it('answers no connection and no counterpart while the flag is off', async () => {
    mocks.flagOn = false;
    try {
      const context = {} as never;
      const user = { id: 'alice', user_email: 'alice@example.com' } as never;
      expect(await findXtmConnections(context, user)).toEqual([]);
      expect(await findXtmCounterpartsByIds(context, user, ['id-1'])).toEqual([]);
    } finally {
      mocks.flagOn = true;
    }
  });
});

const ALICE = { id: 'alice', user_email: 'alice@example.com' };
const BOB = { id: 'bob', user_email: 'bob@example.com' };

const counterpart = (key: string, product = 'test'): XtmCounterpart => ({
  key,
  product,
  object_id: `id-${key}`,
  object_type: 'asset',
  object_name: key,
  object_url: `https://aev.example.com/admin/assets/id-${key}`,
  facts: [],
});

const provider = (connected: boolean, found: string[], product = 'test'): CounterpartProvider & { resolve: ReturnType<typeof vi.fn> } => ({
  product,
  url: () => 'https://aev.example.com',
  isConnected: () => connected,
  supports: () => true,
  resolve: vi.fn(async (_kind, keys: string[]) => keys.filter((k) => found.includes(k)).map((k) => counterpart(k, product))),
});

describe('XTM counterparts: key normalisation', () => {
  it('normalises each kind to the key both products store', () => {
    expect(normaliseCounterpartKey('ASSET', '  WEB-01.Corp.local ')).toBe('web-01.corp.local');
    expect(normaliseCounterpartKey('ATTACK_PATTERN', 't1059.001')).toBe('T1059.001');
    expect(normaliseCounterpartKey('VULNERABILITY', 'cve-2024-3400')).toBe('CVE-2024-3400');
    expect(normaliseCounterpartKey('THREAT', 'Intrusion-Set--3B0A1C2D-0000-4000-8000-000000000001'))
      .toBe('intrusion-set--3b0a1c2d-0000-4000-8000-000000000001');
  });

  it('drops keys that can never match', () => {
    expect(normaliseCounterpartKey('ATTACK_PATTERN', 'Phishing')).toBeNull();
    expect(normaliseCounterpartKey('VULNERABILITY', 'GHSA-xxxx')).toBeNull();
    expect(normaliseCounterpartKey('THREAT', 'not-a-stix-id')).toBeNull();
    expect(normaliseCounterpartKey('ASSET', '   ')).toBeNull();
    expect(normaliseCounterpartKey('ASSET', null)).toBeNull();
  });

  it('keeps an alert link as written and drops anything that is not an http(s) URL', () => {
    const link = 'https://edr.example.com/alerts/AbC-123?tenant=Main';
    expect(normaliseCounterpartKey('ALERT', `  ${link} `)).toBe(link);
    expect(normaliseCounterpartKey('ALERT', 'alert-123')).toBeNull();
    expect(normaliseCounterpartKey('ALERT', 'javascript:alert(1)')).toBeNull();
    expect(normaliseCounterpartKey('ALERT', `https://edr.example.com/${'a'.repeat(2048)}`)).toBeNull();
    expect(normaliseCounterpartKey('ALERT', `https://edr.example.com/${'a'.repeat(600)}`)).not.toBeNull();
  });
});

describe('XTM counterparts: connections and cache', () => {
  beforeEach(() => resetCounterpartCache());

  const SOURCES = [{ id: 'sys-1', kind: 'ASSET' as const, keys: ['web-01'] }, { id: 'sys-2', kind: 'ASSET' as const, keys: ['db-02'] }];

  it('asks the product as the caller with the keys read on the server', async () => {
    const p = provider(true, ['web-01']);
    await resolveCounterpartsOfSources(SOURCES, ALICE, [p]);
    expect(p.resolve).toHaveBeenCalledWith('ASSET', ['web-01', 'db-02'], ALICE);
  });

  it('not connected never calls the provider', async () => {
    const p = provider(false, ['web-01']);
    expect(await resolveCounterpartsOfSources(SOURCES, ALICE, [p])).toEqual([]);
    expect(p.resolve).not.toHaveBeenCalled();
  });

  it('caches hits and misses per user for the TTL, then asks again', async () => {
    const p = provider(true, ['web-01']);
    let clock = 1_000;
    const now = () => clock;
    await resolveCounterpartsOfSources(SOURCES, ALICE, [p], now);
    const cached = await resolveCounterpartsOfSources(SOURCES, ALICE, [p], now);
    expect(cached.map((r) => r.status)).toEqual(['found', 'not_found']);
    expect(p.resolve).toHaveBeenCalledTimes(1);
    // Another user is never served Alice's answer: the product applies each user's own rights.
    await resolveCounterpartsOfSources(SOURCES, BOB, [p], now);
    expect(p.resolve).toHaveBeenCalledTimes(2);
    clock += COUNTERPART_CACHE_TTL_MS + 1;
    await resolveCounterpartsOfSources(SOURCES, ALICE, [p], now);
    expect(p.resolve).toHaveBeenCalledTimes(3);
  });

  it('reports the connection without any credential or address', () => {
    expect(xtmConnections([provider(true, []), { ...provider(false, []), product: 'other' }])).toEqual([
      { product: 'test', connected: true },
      { product: 'other', connected: false },
    ]);
  });
});

describe('XTM counterparts: id-based resolution', () => {
  beforeEach(() => {
    resetCounterpartCache();
    mocks.warn.mockReset();
  });

  const SYSTEM = { id: 'sys-1', kind: 'ASSET' as const, keys: ['web-01'] };
  const OTHER_SYSTEM = { id: 'sys-2', kind: 'ASSET' as const, keys: ['db-02'] };
  const CVE = { id: 'vuln-1', kind: 'VULNERABILITY' as const, keys: ['CVE-2024-3400'] };

  it('answers one status per (id, product) with the counterpart when found', async () => {
    const aev = provider(true, ['web-01'], 'openaev');
    const crq = provider(true, ['CVE-2024-3400'], 'opencrq');
    const results = await resolveCounterpartsOfSources([SYSTEM, OTHER_SYSTEM, CVE], ALICE, [aev, crq]);
    expect(results.map(({ id, product, status }) => ({ id, product, status }))).toEqual([
      { id: 'sys-1', product: 'openaev', status: 'found' },
      { id: 'sys-2', product: 'openaev', status: 'not_found' },
      { id: 'vuln-1', product: 'openaev', status: 'not_found' },
      { id: 'sys-1', product: 'opencrq', status: 'not_found' },
      { id: 'sys-2', product: 'opencrq', status: 'not_found' },
      { id: 'vuln-1', product: 'opencrq', status: 'found' },
    ]);
    expect(results[0].counterpart?.object_id).toBe('id-web-01');
    expect(results[1].counterpart).toBeNull();
    // One call per kind and product, whatever the number of objects.
    expect(aev.resolve).toHaveBeenCalledTimes(2);
  });

  it('a product that is not connected gets no entry', async () => {
    const results = await resolveCounterpartsOfSources([SYSTEM], ALICE, [provider(false, ['web-01'], 'openaev')]);
    expect(results).toEqual([]);
  });

  it('a mixed-kind request with one failing call keeps the answers of the other kinds', async () => {
    const aev = provider(true, ['web-01', 'CVE-2024-3400'], 'openaev');
    aev.resolve.mockImplementation(async (kind: string, keys: string[]) => {
      if (kind === 'VULNERABILITY') {
        throw new CounterpartLookupError('unavailable', 'down');
      }
      return keys.filter((k) => k === 'web-01').map((k) => counterpart(k, 'openaev'));
    });
    const results = await resolveCounterpartsOfSources([SYSTEM, CVE], ALICE, [aev]);
    expect(results.map((r) => r.status)).toEqual(['found', 'unavailable']);
  });

  it('never caches an unavailable answer', async () => {
    const aev = provider(true, ['web-01'], 'openaev');
    aev.resolve.mockRejectedValueOnce(new CounterpartLookupError('unavailable', 'timeout'));
    expect((await resolveCounterpartsOfSources([SYSTEM], ALICE, [aev]))[0].status).toBe('unavailable');
    expect((await resolveCounterpartsOfSources([SYSTEM], ALICE, [aev]))[0].status).toBe('found');
    expect(aev.resolve).toHaveBeenCalledTimes(2);
  });

  it('remembers a 404 route as not supported per product and kind, with one warning', async () => {
    const aev = provider(true, [], 'openaev');
    aev.resolve.mockRejectedValue(new CounterpartLookupError('not_supported', 'no route'));
    expect((await resolveCounterpartsOfSources([SYSTEM], ALICE, [aev]))[0].status).toBe('not_supported');
    expect((await resolveCounterpartsOfSources([OTHER_SYSTEM], BOB, [aev]))[0].status).toBe('not_supported');
    expect(aev.resolve).toHaveBeenCalledTimes(1);
    expect(mocks.warn).toHaveBeenCalledTimes(1);
    // Another kind of the same product is still asked.
    aev.resolve.mockResolvedValueOnce([]);
    expect((await resolveCounterpartsOfSources([CVE], ALICE, [aev]))[0].status).toBe('not_found');
  });

  it('asks a 404 route again once the TTL has passed, warning once per process (R1)', async () => {
    const aev = provider(true, ['web-01'], 'openaev');
    let clock = 1_000;
    const now = () => clock;
    aev.resolve.mockRejectedValueOnce(new CounterpartLookupError('not_supported', 'no route'));
    expect((await resolveCounterpartsOfSources([SYSTEM], ALICE, [aev], now))[0].status).toBe('not_supported');
    expect((await resolveCounterpartsOfSources([SYSTEM], ALICE, [aev], now))[0].status).toBe('not_supported');
    expect(aev.resolve).toHaveBeenCalledTimes(1);
    clock += COUNTERPART_CACHE_TTL_MS + 1;
    // The product enabled the route meanwhile: one call per product and route, then found.
    expect((await resolveCounterpartsOfSources([SYSTEM], ALICE, [aev], now))[0].status).toBe('found');
    expect(aev.resolve).toHaveBeenCalledTimes(2);
    // Still unsupported after the TTL: asked again, no second warning.
    aev.resolve.mockRejectedValueOnce(new CounterpartLookupError('not_supported', 'no route'));
    clock += COUNTERPART_CACHE_TTL_MS + 1;
    expect((await resolveCounterpartsOfSources([OTHER_SYSTEM], ALICE, [aev], now))[0].status).toBe('not_supported');
    expect(mocks.warn).toHaveBeenCalledTimes(1);
  });

  it('a 403 draws nothing for that user only, cached for the TTL, without a warning (R2)', async () => {
    const aev = provider(true, ['web-01'], 'openaev');
    let clock = 1_000;
    const now = () => clock;
    aev.resolve.mockRejectedValueOnce(new CounterpartLookupError('forbidden', 'no right'));
    expect((await resolveCounterpartsOfSources([SYSTEM], ALICE, [aev], now))[0].status).toBe('not_supported');
    expect((await resolveCounterpartsOfSources([SYSTEM], ALICE, [aev], now))[0].status).toBe('not_supported');
    expect(aev.resolve).toHaveBeenCalledTimes(1);
    // Bob has the right: his own call, his own answer.
    expect((await resolveCounterpartsOfSources([SYSTEM], BOB, [aev], now))[0].status).toBe('found');
    expect(aev.resolve).toHaveBeenCalledTimes(2);
    expect(mocks.warn).not.toHaveBeenCalled();
    clock += COUNTERPART_CACHE_TTL_MS + 1;
    expect((await resolveCounterpartsOfSources([SYSTEM], ALICE, [aev], now))[0].status).toBe('found');
    expect(aev.resolve).toHaveBeenCalledTimes(3);
  });

  it('a kind the product does not support is not_supported without a call', async () => {
    const crq = { ...provider(true, []), product: 'opencrq', supports: (kind: string) => kind !== 'ALERT' };
    const results = await resolveCounterpartsOfSources([{ id: 'inc-1', kind: 'ALERT', keys: ['https://edr.example.com/a/1'] }], ALICE, [crq]);
    expect(results).toEqual([{ id: 'inc-1', product: 'opencrq', status: 'not_supported', counterpart: null }]);
    expect(crq.resolve).not.toHaveBeenCalled();
  });

  it('an alert with several links is found when one of them matches', async () => {
    const aev = provider(true, ['https://edr.example.com/a/2'], 'openaev');
    const alert = { id: 'inc-1', kind: 'ALERT' as const, keys: ['https://edr.example.com/a/1', 'https://edr.example.com/a/2'] };
    const [result] = await resolveCounterpartsOfSources([alert], ALICE, [aev]);
    expect(result.status).toBe('found');
    expect(result.counterpart?.key).toBe('https://edr.example.com/a/2');
  });

  it('the registry serves the providers in registration order, a second registration replacing the first', () => {
    const first = { ...provider(true, []), product: 'first' };
    const second = { ...provider(false, []), product: 'second' };
    registerCounterpartProvider(first);
    registerCounterpartProvider(second);
    registerCounterpartProvider({ ...first, isConnected: () => false });
    expect(xtmConnections()).toEqual([
      { product: 'first', connected: false },
      { product: 'second', connected: false },
    ]);
  });
});
