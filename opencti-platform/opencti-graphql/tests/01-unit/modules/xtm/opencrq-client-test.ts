import { beforeEach, describe, expect, it, vi } from 'vitest';

const mocks = vi.hoisted(() => ({
  settings: {} as Record<string, string | undefined>,
  get: vi.fn(),
  clientOptions: [] as any[],
  warn: vi.fn(),
}));

vi.mock('../../../../src/config/conf', () => ({
  default: { get: (key: string) => mocks.settings[key] },
  logApp: { info: vi.fn(), error: vi.fn(), warn: mocks.warn, debug: vi.fn() },
}));

vi.mock('../../../../src/utils/http-client', () => ({
  getHttpClient: (options: any) => {
    mocks.clientOptions.push(options);
    return { get: mocks.get };
  },
}));

import { fetchOpenCrqObjects, getOpenCrqApiUrl, getOpenCrqUrl, isOpenCrqConnected } from '../../../../src/modules/xtm/openaev/opencrq-client';
import { openCrqProvider, resetCounterpartCache, resolveCounterparts } from '../../../../src/modules/xtm/openaev/openaev-counterpart-domain';

const STIX = 'intrusion-set--3b0a1c2d-0000-4000-8000-000000000001';

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
  mocks.settings['xtm:opencrq_token'] = 'ogrc_secret';
};

const tRpc = (data: unknown) => ({ data: { result: { data } } });

describe('OpenCRQ client', () => {
  beforeEach(() => {
    mocks.settings = {};
    mocks.get.mockReset();
    mocks.clientOptions = [];
    mocks.warn.mockReset();
    resetCounterpartCache();
  });

  it('is not connected without both the URL and the token, and derives the tRPC base', () => {
    expect(getOpenCrqUrl()).toBeNull();
    expect(getOpenCrqApiUrl()).toBeNull();
    expect(isOpenCrqConnected()).toBe(false);
    mocks.settings['xtm:opencrq_url'] = 'https://crq.example.com//';
    expect(getOpenCrqUrl()).toBe('https://crq.example.com');
    expect(getOpenCrqApiUrl()).toBe('https://crq.example.com/trpc');
    expect(isOpenCrqConnected()).toBe(false);
    mocks.settings['xtm:opencrq_token'] = 'ogrc_secret';
    expect(isOpenCrqConnected()).toBe(true);
    mocks.settings['xtm:opencrq_api_url'] = 'https://crq-api.internal/trpc/';
    expect(getOpenCrqApiUrl()).toBe('https://crq-api.internal/trpc');
  });

  it('never calls OpenCRQ when not connected or without keys', async () => {
    expect(await fetchOpenCrqObjects('THREAT', [STIX])).toEqual([]);
    connect();
    expect(await fetchOpenCrqObjects('THREAT', [])).toEqual([]);
    expect(mocks.get).not.toHaveBeenCalled();
  });

  it('queries xtm.lookup with the kind and keys and the service-account token', async () => {
    connect();
    mocks.get.mockResolvedValue(tRpc([remote(STIX)]));
    const result = await fetchOpenCrqObjects('THREAT', [STIX]);
    expect(result).toEqual([remote(STIX)]);
    const url = mocks.get.mock.calls[0][0] as string;
    expect(url.startsWith('/xtm.lookup?input=')).toBe(true);
    expect(JSON.parse(decodeURIComponent(url.slice('/xtm.lookup?input='.length)))).toEqual({ kind: 'THREAT', keys: [STIX] });
    expect(mocks.clientOptions[0].baseURL).toBe('https://crq.example.com/trpc');
    expect(mocks.clientOptions[0].headers.Authorization).toBe('Bearer ogrc_secret');
  });

  it('answers an empty list on an error or an unexpected body, and never logs the token', async () => {
    connect();
    mocks.get.mockRejectedValue(Object.assign(new Error('boom'), { status: 401 }));
    expect(await fetchOpenCrqObjects('THREAT', [STIX])).toEqual([]);
    expect(JSON.stringify(mocks.warn.mock.calls)).not.toContain('ogrc_secret');
    mocks.get.mockResolvedValue({ data: { result: {} } });
    expect(await fetchOpenCrqObjects('THREAT', [STIX])).toEqual([]);
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
    const found = await openCrqProvider.resolve('VULNERABILITY', ['CVE-2024-3400']);
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

  it('is skipped by the resolver when not connected and cached per product when it is', async () => {
    expect(await resolveCounterparts('ASSET', ['WEB-01'], [openCrqProvider])).toEqual([]);
    expect(mocks.get).not.toHaveBeenCalled();
    connect();
    mocks.get.mockResolvedValue(tRpc([remote('web-01', { object_type: 'asset' })]));
    const first = await resolveCounterparts('ASSET', ['WEB-01'], [openCrqProvider]);
    const second = await resolveCounterparts('ASSET', ['web-01'], [openCrqProvider]);
    expect(first.map((c) => c.key)).toEqual(['web-01']);
    expect(second).toEqual(first);
    expect(mocks.get).toHaveBeenCalledTimes(1);
  });
});
