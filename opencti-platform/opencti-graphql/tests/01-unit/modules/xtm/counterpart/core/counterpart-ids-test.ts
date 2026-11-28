import { beforeEach, describe, expect, it, vi } from 'vitest';

// findXtmCounterpartsByIds with the real counterpart-keys: only the database loader is mocked.
const mocks = vi.hoisted(() => ({
  settings: {} as Record<string, string | undefined>,
  post: vi.fn(),
  findByIds: vi.fn(),
  relations: vi.fn(async () => []),
}));

vi.mock(import('../../../../../../src/config/conf'), async (importOriginal) => {
  const actual = await importOriginal();
  return {
    ...actual,
    isFeatureEnabled: (flag: string) => flag === 'XTM_COUNTERPARTS',
    default: { ...actual.default, get: (key: string) => mocks.settings[key] },
    logApp: { ...actual.logApp, warn: vi.fn() },
  } as any;
});

vi.mock('../../../../../../src/database/middleware-loader', () => ({
  internalFindByIds: mocks.findByIds,
  fullRelationsList: mocks.relations,
}));

vi.mock('../../../../../../src/utils/http-client', () => ({
  getHttpClient: () => ({ post: mocks.post }),
}));

vi.mock('../../../../../../src/domain/xtm-auth', () => ({ issueXtmJwt: vi.fn(async () => 'jwt') }));

import {
  findXtmCounterpartsByIds,
  MAX_COUNTERPART_IDS,
  registerCounterpartProvider,
  resetCounterpartCache,
} from '../../../../../../src/modules/xtm/counterpart/core/counterpart-domain';
import { openAevProvider } from '../../../../../../src/modules/xtm/counterpart/openaev/openaev-provider';
import { openCrqProvider } from '../../../../../../src/modules/xtm/counterpart/opencrq/opencrq-provider';

// What the counterpart module descriptor registers at boot
registerCounterpartProvider(openAevProvider);
registerCounterpartProvider(openCrqProvider);

const context = {} as any;
const user = { id: 'alice', user_email: 'alice@example.com' } as any;

const attackPattern = (id: string, mitre: string) => ({
  internal_id: id,
  standard_id: `attack-pattern--${id}`,
  entity_type: 'Attack-Pattern',
  x_mitre_id: mitre,
});

describe('findXtmCounterpartsByIds with the real counterpart keys', () => {
  beforeEach(() => {
    mocks.settings = {};
    mocks.post.mockReset();
    mocks.findByIds.mockReset();
    resetCounterpartCache();
  });

  it('reads nothing and calls no product when no product is connected', async () => {
    expect(await findXtmCounterpartsByIds(context, user, ['ap-1'])).toEqual([]);
    expect(mocks.findByIds).not.toHaveBeenCalled();
    expect(mocks.post).not.toHaveBeenCalled();
  });

  it('reads at most the capped number of ids', async () => {
    mocks.settings['xtm:openaev_url'] = 'https://aev.example.com';
    mocks.findByIds.mockResolvedValue([]);
    const ids = Array.from({ length: MAX_COUNTERPART_IDS + 50 }, (_, i) => `id-${i}`);
    await findXtmCounterpartsByIds(context, user, ids);
    expect(mocks.findByIds).toHaveBeenCalledTimes(1);
    expect((mocks.findByIds.mock.calls[0] as any[])[2]).toHaveLength(MAX_COUNTERPART_IDS);
  });

  it('gives no entry and sends no call for an object the user cannot read', async () => {
    mocks.settings['xtm:openaev_url'] = 'https://aev.example.com';
    mocks.findByIds.mockResolvedValue([]);
    expect(await findXtmCounterpartsByIds(context, user, ['restricted-1'])).toEqual([]);
    expect(mocks.post).not.toHaveBeenCalled();
  });

  it('sends the key read from the object and answers its counterpart', async () => {
    mocks.settings['xtm:openaev_url'] = 'https://aev.example.com';
    mocks.findByIds.mockResolvedValue([attackPattern('ap-1', 'T1059.001')]);
    mocks.post.mockResolvedValue({
      data: [{
        object_key: 'T1059.001',
        object_id: 'aev-1',
        object_type: 'AttackPattern',
        object_name: 'PowerShell',
        object_url: 'https://aev.example.com/admin/attack_patterns/aev-1',
      }],
    });
    const results = await findXtmCounterpartsByIds(context, user, ['ap-1']);
    expect(results.map(({ id, product, status }) => ({ id, product, status }))).toEqual([
      { id: 'ap-1', product: 'openaev', status: 'found' },
    ]);
    expect(mocks.post).toHaveBeenCalledWith(expect.stringContaining('/xtm/objects/attack-patterns'), { counterpart_keys: ['T1059.001'] }, { maxRedirects: 0 });
  });
});
