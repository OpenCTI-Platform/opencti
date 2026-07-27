import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { KnowledgeNotificationEvent } from '../../../src/manager/notificationManager';
import type { AuthContext, AuthUser } from '../../../src/types/user';
import type { BasicStoreEntityTrigger } from '../../../src/modules/notification/notification-types';

// Mock the stream layer so collectDigestContent is driven with canned batches (no Redis needed).
const fetchRangeNotificationsMock = vi.fn();
vi.mock('../../../src/database/stream/stream-handler', () => ({
  fetchRangeNotifications: (...args: unknown[]) => fetchRangeNotificationsMock(...args),
  storeNotificationEvent: vi.fn(),
  createStreamProcessor: vi.fn(),
}));

// Mock the cache so getDigestNotifications is fed with canned triggers/users (no ElasticSearch needed).
vi.mock('../../../src/database/cache', () => ({
  getEntitiesListFromCache: vi.fn().mockResolvedValue([]),
  getEntityFromCache: vi.fn(),
}));

// Mock the representative resolution so the digest message generation does not hit the database.
vi.mock('../../../src/database/stix-representative', () => ({
  extractStixRepresentative: vi.fn().mockResolvedValue('repr'),
  extractStixRepresentativeForUser: vi.fn().mockResolvedValue('repr'),
}));

import { collectDigestContent, DEFAULT_MAX_DIGEST_CONTENT_SIZE, handleDigestNotifications } from '../../../src/manager/notificationManager';
import { getEntitiesListFromCache, getEntityFromCache } from '../../../src/database/cache';
import { storeNotificationEvent } from '../../../src/database/stream/stream-handler';
import { ENTITY_TYPE_TRIGGER } from '../../../src/modules/notification/notification-types';

let objSeq = 0;
const liveEvent = (notificationId: string, userId = 'user-1'): KnowledgeNotificationEvent => {
  objSeq += 1;
  return {
    version: '1',
    type: 'live',
    notification_id: notificationId,
    targets: [{ user: { user_id: userId, user_email: '', notifiers: [], user_service_account: false }, type: 'live', message: 'm' }],
    data: { id: `obj-${objSeq}`, type: 'Report' } as KnowledgeNotificationEvent['data'],
    origin: {},
  };
};

// Byte size of an event, mirroring how collectDigestContent measures the retained content.
const eventBytes = (event: KnowledgeNotificationEvent) => Buffer.byteLength(JSON.stringify(event));

// Wrap events the way rawFetchRangeNotifications delivers them: paired with their stored byte size.
const sizedBatch = (events: KnowledgeNotificationEvent[]) => events.map((event) => ({ event, byteSize: eventBytes(event) }));

// Make the mocked fetchRangeNotifications deliver the given batches, honouring an early-stop (false).
const driveBatches = (batches: KnowledgeNotificationEvent[][]) => {
  fetchRangeNotificationsMock.mockImplementation(async (_start, _end, callback) => {
    for (let i = 0; i < batches.length; i += 1) {
      const shouldContinue = await callback(sizedBatch(batches[i]));
      if (shouldContinue === false) break;
    }
  });
};

describe('collectDigestContent', () => {
  afterEach(() => {
    vi.clearAllMocks();
    objSeq = 0; // keep tests isolated: the generated obj ids restart from 1 for each test
  });

  it('keeps only the events whose notification_id belongs to the digest triggers', async () => {
    driveBatches([[
      liveEvent('trigger-A'),
      liveEvent('trigger-B'),
      liveEvent('trigger-A'),
      liveEvent('trigger-C'),
    ]]);
    const { content, truncated } = await collectDigestContent(new Date(1), new Date(2), ['trigger-A', 'trigger-B']);
    expect(truncated).toBe(false);
    expect(content).toHaveLength(3);
    expect(content.map((c) => c.notification_id).sort()).toEqual(['trigger-A', 'trigger-A', 'trigger-B']);
  });

  it('accumulates matching events across multiple batches', async () => {
    driveBatches([
      [liveEvent('trigger-A'), liveEvent('trigger-X')],
      [liveEvent('trigger-A')],
    ]);
    const { content, truncated } = await collectDigestContent(new Date(1), new Date(2), ['trigger-A']);
    expect(truncated).toBe(false);
    expect(content).toHaveLength(2);
  });

  it('caps the content at the byte budget and reports truncation', async () => {
    const events = Array.from({ length: 10 }, () => liveEvent('trigger-A'));
    driveBatches([events]);
    // Budget sized for exactly 3 events: truncation triggers when the cumulative byte size reaches it.
    const budget = eventBytes(events[0]) + eventBytes(events[1]) + eventBytes(events[2]);
    const { content, truncated, byteSize } = await collectDigestContent(new Date(1), new Date(2), ['trigger-A'], budget);
    expect(truncated).toBe(true);
    expect(content).toHaveLength(3);
    expect(byteSize).toBeGreaterThanOrEqual(budget);
  });

  it('stops requesting further batches once the byte budget is reached', async () => {
    const firstBatch = [liveEvent('trigger-A'), liveEvent('trigger-A'), liveEvent('trigger-A')];
    const secondBatch = [liveEvent('trigger-A')];
    let batchesConsumed = 0;
    fetchRangeNotificationsMock.mockImplementation(async (_start, _end, callback) => {
      const batches = [firstBatch, secondBatch];
      for (let b = 0; b < batches.length; b += 1) {
        batchesConsumed += 1;

        const shouldContinue = await callback(sizedBatch(batches[b]));
        if (shouldContinue === false) break;
      }
    });
    // Budget sized for 2 events: truncation hits inside the first batch.
    const budget = eventBytes(firstBatch[0]) + eventBytes(firstBatch[1]);
    const { content, truncated } = await collectDigestContent(new Date(1), new Date(2), ['trigger-A'], budget);
    expect(truncated).toBe(true);
    expect(content).toHaveLength(2);
    expect(batchesConsumed).toBe(1); // the second batch is never requested
  });

  it('exposes a strictly positive default cap', () => {
    expect(DEFAULT_MAX_DIGEST_CONTENT_SIZE).toBeGreaterThan(0);
  });
});

describe('handleDigestNotifications', () => {
  // Freeze time so the digest trigger_time matches the computed run minute deterministically.
  const FROZEN = new Date('2026-01-15T10:30:00.000Z');
  const DIGEST_USER_ID = 'digest-user-1';

  // A daily digest watching trigger-A, restricted to the digest user.
  const digestTrigger = {
    internal_id: 'digest-1',
    id: 'digest-1',
    trigger_type: 'digest',
    period: 'day',
    trigger_time: '10:30:00.000Z', // aligned with FROZEN (HH:mm:ss.SSS)
    trigger_ids: ['trigger-A'],
    notifiers: ['notifier-1'],
    restricted_members: [{ id: DIGEST_USER_ID }],
  } as unknown as BasicStoreEntityTrigger;

  const digestUser = {
    id: DIGEST_USER_ID,
    internal_id: DIGEST_USER_ID,
    user_email: 'digest-user@local',
    user_service_account: false,
    groups: [],
    organizations: [],
    personal_notifiers: [],
  } as unknown as AuthUser;

  // Feed getDigestNotifications: triggers list resolves the digest, users list resolves its member.
  const primeCache = () => {
    const resolveFromCache = (_ctx: AuthContext, _user: AuthUser, type: string) => {
      return Promise.resolve(type === ENTITY_TYPE_TRIGGER ? [digestTrigger] : [digestUser]);
    };
    vi.mocked(getEntitiesListFromCache).mockImplementation(resolveFromCache as unknown as typeof getEntitiesListFromCache);
    vi.mocked(getEntityFromCache).mockResolvedValue({ platform_notifier_auto_trigger_assignee: true } as unknown as Awaited<ReturnType<typeof getEntityFromCache>>);
  };

  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(FROZEN);
    primeCache();
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.clearAllMocks();
    objSeq = 0;
  });

  it('stores a digest event built from the events collected for the digest triggers', async () => {
    driveBatches([[
      liveEvent('trigger-A', DIGEST_USER_ID),
      liveEvent('trigger-B', DIGEST_USER_ID), // not part of the digest triggers, must be ignored
      liveEvent('trigger-A', DIGEST_USER_ID),
    ]]);
    await handleDigestNotifications({} as AuthContext);
    expect(vi.mocked(storeNotificationEvent)).toHaveBeenCalledTimes(1);
    const digestEvent = vi.mocked(storeNotificationEvent).mock.calls[0][1] as unknown as { notification_id: string; data: unknown[] };
    expect(digestEvent.notification_id).toBe('digest-1');
    expect(digestEvent.data).toHaveLength(2); // only the two trigger-A events
  });

  it('does not emit a digest event when no collected event matches the digest', async () => {
    driveBatches([[liveEvent('trigger-other', DIGEST_USER_ID)]]);
    await handleDigestNotifications({} as AuthContext);
    expect(vi.mocked(storeNotificationEvent)).not.toHaveBeenCalled();
  });
});
