import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../../../../../../src/config/conf', () => ({
  default: { get: () => undefined },
  logApp: { info: vi.fn(), error: vi.fn(), warn: vi.fn(), debug: vi.fn() },
}));

vi.mock('../../../../../../src/utils/http-client', () => ({
  getHttpClient: () => ({ post: () => Promise.reject(new Error('no network in unit tests')) }),
}));

import {
  type CounterpartProvider,
  COUNTERPART_CACHE_TTL_MS,
  normaliseCounterpartKey,
  normaliseCounterpartKeys,
  resetCounterpartCache,
  resolveCounterparts,
  xtmConnections,
  type XtmCounterpart,
} from '../../../../../../src/modules/xtm/counterpart/core/counterpart-domain';

const counterpart = (key: string): XtmCounterpart => ({
  key,
  product: 'test',
  object_id: `id-${key}`,
  object_type: 'asset',
  object_name: key,
  object_url: `https://aev.example.com/admin/assets/id-${key}`,
  facts: [],
});

const provider = (connected: boolean, found: string[]): CounterpartProvider & { resolve: ReturnType<typeof vi.fn> } => ({
  product: 'test',
  url: () => 'https://aev.example.com',
  isConnected: () => connected,
  supports: () => true,
  resolve: vi.fn(async (_kind, keys: string[]) => keys.filter((k) => found.includes(k)).map(counterpart)),
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

  it('dedupes and caps the batch', () => {
    expect(normaliseCounterpartKeys('VULNERABILITY', ['CVE-2024-1111', 'cve-2024-1111', 'bad'])).toEqual(['CVE-2024-1111']);
    const many = Array.from({ length: 300 }, (_, i) => `host-${i}`);
    expect(normaliseCounterpartKeys('ASSET', many)).toHaveLength(200);
  });
});

describe('XTM counterparts: resolution', () => {
  beforeEach(() => resetCounterpartCache());

  it('connected with a match answers the counterpart only for the matched key', async () => {
    const p = provider(true, ['web-01']);
    const result = await resolveCounterparts('ASSET', ['WEB-01', 'db-02'], [p]);
    expect(result.map((c) => c.key)).toEqual(['web-01']);
    expect(p.resolve).toHaveBeenCalledWith('ASSET', ['web-01', 'db-02']);
  });

  it('connected without a match answers nothing', async () => {
    expect(await resolveCounterparts('ASSET', ['db-02'], [provider(true, [])])).toEqual([]);
  });

  it('not connected never calls the provider', async () => {
    const p = provider(false, ['web-01']);
    expect(await resolveCounterparts('ASSET', ['web-01'], [p])).toEqual([]);
    expect(p.resolve).not.toHaveBeenCalled();
  });

  it('caches hits and misses for the TTL, then asks again', async () => {
    const p = provider(true, ['web-01']);
    let clock = 1_000;
    const now = () => clock;
    await resolveCounterparts('ASSET', ['web-01', 'db-02'], [p], now);
    const cached = await resolveCounterparts('ASSET', ['web-01', 'db-02'], [p], now);
    expect(cached.map((c) => c.key)).toEqual(['web-01']);
    expect(p.resolve).toHaveBeenCalledTimes(1);
    clock += COUNTERPART_CACHE_TTL_MS + 1;
    await resolveCounterparts('ASSET', ['web-01'], [p], now);
    expect(p.resolve).toHaveBeenCalledTimes(2);
  });

  it('reports the connection without any credential', () => {
    expect(xtmConnections([provider(true, []), { ...provider(false, []), product: 'other' }])).toEqual([
      { product: 'test', connected: true, url: 'https://aev.example.com' },
      { product: 'other', connected: false, url: null },
    ]);
  });
});
