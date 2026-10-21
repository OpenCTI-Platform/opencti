import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';

// The storage of the platform, in memory: the operational state and the salts held in Redis, the objects in scope read
// page by page as the database listing does (a callback answering false stops it), the objects a write reached. A
// write of the object `failOn` fails once, as an unavailable Elasticsearch.
const STORE = vi.hoisted(() => ({
  settings: {} as Record<string, unknown>,
  state: {} as Record<string, string>,
  salts: new Map<string, string>(),
  entities: [] as Array<Record<string, unknown>>,
  pageSize: 2,
  written: [] as string[],
  failOn: undefined as string | undefined,
}));

vi.mock('../../../../../src/domain/settings', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../../src/domain/settings')>(),
  getSettingsFromDatabase: vi.fn(async () => STORE.settings),
}));

vi.mock('../../../../../src/database/cache', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../../src/database/cache')>(),
  getEntitiesListFromCache: vi.fn(async () => []),
}));

vi.mock('../../../../../src/database/engine', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../../src/database/engine')>(),
  elCount: vi.fn(async () => 0),
}));

vi.mock('../../../../../src/database/middleware-loader', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../../src/database/middleware-loader')>(),
  fullEntitiesList: vi.fn(async (_context: unknown, _user: unknown, _types: unknown, args: { callback?: (elements: unknown[]) => Promise<boolean | void> }) => {
    for (let index = 0; index < STORE.entities.length; index += STORE.pageSize) {
      if ((await args.callback?.(STORE.entities.slice(index, index + STORE.pageSize))) === false) {
        break;
      }
    }
    return [];
  }),
}));

vi.mock('../../../../../src/lock/master-lock', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../../src/lock/master-lock')>(),
  lockResources: vi.fn(async () => ({ unlock: async () => undefined })),
}));

vi.mock('../../../../../src/manager/telemetryManager', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../../src/manager/telemetryManager')>(),
  addThreatPulseLookupsCount: vi.fn(),
}));

vi.mock('../../../../../src/modules/xtm/pulse/pulse-cache', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../../src/modules/xtm/pulse/pulse-cache')>(),
  redisGetPulseConfigGeneration: vi.fn(async () => '1'),
  redisGetPulseState: vi.fn(async () => ({ ...STORE.state })),
  redisSetPulseState: vi.fn(async (state: Record<string, string | undefined>) => {
    Object.entries(state).forEach(([field, value]) => {
      if (value === undefined) {
        delete STORE.state[field];
      } else {
        STORE.state[field] = value;
      }
    });
  }),
  redisGetPulseSalt: vi.fn(async (day: string) => STORE.salts.get(day) ?? null),
  redisSetPulseSalt: vi.fn(async (day: string, salt: string) => {
    STORE.salts.set(day, salt);
  }),
  redisGetPulseResponse: vi.fn(async () => null),
  redisSetPulseResponse: vi.fn(async () => undefined),
}));

vi.mock('../../../../../src/modules/xtm/pulse/pulse-information', async (importOriginal) => ({
  ...await importOriginal<typeof import('../../../../../src/modules/xtm/pulse/pulse-information')>(),
  writePulseDocuments: vi.fn(async (_context: unknown, updates: Array<{ entity: { internal_id: string } }>) => {
    if (STORE.failOn && updates.some(({ entity }) => entity.internal_id === STORE.failOn)) {
      STORE.failOn = undefined;
      throw new Error('Elasticsearch unavailable');
    }
    STORE.written.push(...updates.map(({ entity }) => entity.internal_id));
  }),
}));

import conf from '../../../../../src/config/conf';
import { PulseMode } from '../../../../../src/generated/graphql';
import { runPulsePreview, runPulseRefresh } from '../../../../../src/modules/xtm/pulse/pulse-domain';
import { computeStableKeys } from '../../../../../src/modules/xtm/pulse/pulse-hashing';
import { PULSE_CONSENT_VERSION } from '../../../../../src/modules/xtm/pulse/pulse-types';
import { ENTITY_TYPE_MALWARE } from '../../../../../src/schema/stixDomainObject';
import { executionContext } from '../../../../../src/utils/access';
import { PulseHubMock, RATE_LIMIT_RETRY_AFTER_SECONDS } from '../../../../utils/pulseHubMock';

const testContext = executionContext('pulse-refresh-resume-test');
const PLATFORM = { platformId: 'platform-under-test', platformToken: 'token-under-test' };
const NOW = Date.parse('2026-10-12T12:00:00.000Z');
const RETRY_AT = NOW + RATE_LIMIT_RETRY_AFTER_SECONDS * 1000;
// Ten objects in scope, read two per page: a page refreshed costs one lookup.
const ENTITIES = Array.from({ length: 10 }, (_, index) => ({
  id: `malware-${index}`,
  internal_id: `malware-${index}`,
  entity_type: ENTITY_TYPE_MALWARE,
  name: `Pulse resume ${index}`,
}));
const ids = (from: number, to: number) => ENTITIES.slice(from, to).map(({ internal_id }) => internal_id);

const configure = (mode: PulseMode) => ({
  id: PLATFORM.platformId,
  xtm_hub_token: PLATFORM.platformToken,
  pulse_mode: mode,
  pulse_scopes: [ENTITY_TYPE_MALWARE],
  pulse_consent_version: PULSE_CONSENT_VERSION,
  pulse_consent_date: new Date(NOW),
});

describe('Threat Pulse refresh interrupted midway', () => {
  const hub = new PulseHubMock();
  let previousOverride: string | undefined;
  const lookups = () => hub.requests.filter(({ operation }) => operation === 'pulseLookup').length;

  beforeAll(async () => {
    previousOverride = conf.get('xtm:xtmhub_api_override_url');
    conf.set('xtm:xtmhub_api_override_url', await hub.start());
  });

  afterAll(async () => {
    conf.set('xtm:xtmhub_api_override_url', previousOverride);
    await hub.stop();
  });

  beforeEach(() => {
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(NOW);
    hub.reset();
    hub.registerPlatform(PLATFORM.platformId, PLATFORM.platformToken);
    STORE.state = {};
    STORE.salts.clear();
    STORE.entities = ENTITIES;
    STORE.written = [];
    STORE.failOn = undefined;
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  describe('network refresh', () => {
    beforeEach(() => {
      STORE.settings = configure(PulseMode.ContributeAndRead);
      STORE.state = { contribution_accepted: 'true' };
      // XTM Hub answers the full reads to a platform that contributed recently.
      hub.seed([{ platformId: PLATFORM.platformId, key: computeStableKeys(ENTITIES[0])[0], objectType: 'malware', eventKind: 'created', day: hub.today(), sector: 'finance', region: 'europe' }]);
    });

    it('should resume from its checkpoint at the instant XTM Hub gave with its rate limit', async () => {
      // The quota of XTM Hub covers two pages: the lookups of the third one are rate limited.
      hub.limitCalls('pulseLookup', 2);
      await expect(runPulseRefresh(testContext)).rejects.toMatchObject({ code: 'rate_limited' });
      expect(STORE.written).toEqual(ids(0, 4));
      expect(STORE.state).toMatchObject({ refresh_offset: '4', refresh_retry_at: new Date(RETRY_AT).toISOString() });
      expect(STORE.state.last_refresh_at).toBeUndefined();

      // Before that instant, a run asks nothing of XTM Hub.
      const lookupsBefore = lookups();
      vi.setSystemTime(RETRY_AT - 1000);
      expect(await runPulseRefresh(testContext)).toBe(0);
      expect(lookups()).toBe(lookupsBefore);

      // After it, the refresh goes on after the objects already refreshed and covers the scope.
      hub.limitCalls('pulseLookup', undefined);
      vi.setSystemTime(RETRY_AT + 1000);
      STORE.written = [];
      expect(await runPulseRefresh(testContext)).toBe(6);
      expect(STORE.written).toEqual(ids(4, 10));
      expect(lookups()).toBe(lookupsBefore + 3);
      expect(STORE.state.refresh_offset).toBeUndefined();
      expect(STORE.state.refresh_retry_at).toBeUndefined();
      expect(STORE.state.last_refresh_at).toBe(new Date(RETRY_AT + 1000).toISOString());
    });

    it('should keep its checkpoint when XTM Hub rate limits the first page, and wait for the instant XTM Hub gave', async () => {
      STORE.state.refresh_offset = '2';
      hub.limitCalls('pulseLookup', 0);
      await expect(runPulseRefresh(testContext)).rejects.toMatchObject({ code: 'rate_limited' });
      expect(STORE.written).toEqual([]);
      expect(STORE.state).toMatchObject({ refresh_offset: '2', refresh_retry_at: new Date(RETRY_AT).toISOString() });
    });

    it('should keep its checkpoint when another failure interrupts it, and go on at the next cycle', async () => {
      // A retry instant XTM Hub gave earlier, now past.
      STORE.state.refresh_retry_at = new Date(NOW - 1000).toISOString();
      // The write of the fourth page fails: the three first ones are kept, the fourth one is refreshed again.
      STORE.failOn = 'malware-6';
      await expect(runPulseRefresh(testContext)).rejects.toThrow('Elasticsearch unavailable');
      expect(STORE.written).toEqual(ids(0, 6));
      expect(STORE.state.refresh_offset).toBe('6');
      expect(STORE.state.refresh_retry_at).toBeUndefined();

      STORE.written = [];
      expect(await runPulseRefresh(testContext)).toBe(4);
      expect(STORE.written).toEqual(ids(6, 10));
      expect(STORE.state.refresh_offset).toBeUndefined();
      expect(STORE.state.last_refresh_at).toBe(new Date(NOW).toISOString());
    });
  });

  describe('preview pass', () => {
    beforeEach(() => {
      STORE.settings = configure(PulseMode.Preview);
      // Every object is among the most prevalent keys of the community: the digest matches each of them.
      hub.seed(ENTITIES.flatMap((entity) => ['p1', 'p2', 'p3', 'p4', 'p5'].map((platformId) => ({
        platformId,
        key: computeStableKeys(entity)[0],
        objectType: 'malware',
        eventKind: 'sighted',
        day: hub.today(),
        sector: 'finance',
        region: 'europe',
      }))));
    });

    it('should keep the objects it matched when a failure interrupts it, and go on after them', async () => {
      STORE.failOn = 'malware-6';
      await expect(runPulsePreview(testContext)).rejects.toThrow('Elasticsearch unavailable');
      expect(STORE.written).toEqual(ids(0, 6));
      expect(STORE.state).toMatchObject({ preview_offset: '6', preview_digest_day: hub.today() });
      expect(STORE.state.preview_refresh_at).toBeUndefined();

      STORE.written = [];
      expect(await runPulsePreview(testContext)).toBe(4);
      expect(STORE.written).toEqual(ids(6, 10));
      expect(STORE.state.preview_offset).toBeUndefined();
      expect(STORE.state.preview_refresh_at).toBe(new Date(NOW).toISOString());
    });
  });
});
