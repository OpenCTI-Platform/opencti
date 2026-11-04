import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { ActivityNotificationEvent, DigestContentEvent, KnowledgeNotificationEvent } from '../../../src/manager/notificationManager';
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

import { collectDigestContent, DEFAULT_MAX_DIGEST_CONTENT_SIZE, handleDigestNotifications, isStixObjectNotificationData } from '../../../src/manager/notificationManager';
import { getEntitiesListFromCache, getEntityFromCache } from '../../../src/database/cache';
import { storeNotificationEvent } from '../../../src/database/stream/stream-handler';
import { extractStixRepresentativeForUser } from '../../../src/database/stix-representative';
import { ENTITY_TYPE_TRIGGER } from '../../../src/modules/notification/notification-types';
import { ACCOUNT_STATUS_ACTIVE } from '../../../src/config/conf';
import { STIX_EXT_OCTI } from '../../../src/types/stix-2-1-extensions';

let objSeq = 0;
const liveEvent = (notificationId: string, userId = 'user-1'): KnowledgeNotificationEvent => {
  objSeq += 1;
  return {
    version: '1',
    type: 'live',
    notification_id: notificationId,
    targets: [{ user: { user_id: userId, user_email: '', notifiers: [], user_service_account: false }, type: 'live', message: 'm' }],
    // A STIX object: always with its OpenCTI extension
    data: { id: `obj-${objSeq}`, type: 'Report', extensions: { [STIX_EXT_OCTI]: { type: 'Report' } } } as unknown as KnowledgeNotificationEvent['data'],
    origin: {},
  };
};

// Byte size of an event, mirroring how collectDigestContent measures the retained content.
const eventBytes = (event: DigestContentEvent) => Buffer.byteLength(JSON.stringify(event));

// Wrap events the way rawFetchRangeNotifications delivers them: paired with their stored byte size.
const sizedBatch = (events: DigestContentEvent[]) => events.map((event) => ({ event, byteSize: eventBytes(event) }));

// Make the mocked fetchRangeNotifications deliver the given batches, honouring an early-stop (false).
const driveBatches = (batches: DigestContentEvent[][]) => {
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
    account_status: ACCOUNT_STATUS_ACTIVE,
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

  it('takes the message of a login activity from its target: its data is the bare authentication context, without id', async () => {
    // As stored by the activity manager for a login: the context data of the action, the message prefixed with the user name
    const loginEvent: ActivityNotificationEvent = {
      version: '1',
      type: 'live',
      notification_id: 'trigger-A',
      targets: [{
        user: { user_id: DIGEST_USER_ID, user_email: '', notifiers: [], user_service_account: false },
        type: 'login',
        message: '`admin` login from provider `local` ',
      }],
      data: { provider: 'local', username: 'admin@opencti.io' } as unknown as ActivityNotificationEvent['data'],
      origin: {},
    };
    driveBatches([[loginEvent]]);
    await handleDigestNotifications({} as AuthContext);
    expect(vi.mocked(storeNotificationEvent)).toHaveBeenCalledTimes(1);
    const digestEvent = vi.mocked(storeNotificationEvent).mock.calls[0][1] as unknown as { data: Array<{ type: string; message: string; instance: unknown }> };
    expect(digestEvent.data).toEqual([expect.objectContaining({
      type: 'login',
      message: '`admin` login from provider `local` ',
      instance: { provider: 'local', username: 'admin@opencti.io' },
    })]);
    expect(vi.mocked(extractStixRepresentativeForUser)).not.toHaveBeenCalled();
  });

  it('takes the message from its target when the data has extensions but no OpenCTI one', async () => {
    const event: ActivityNotificationEvent = {
      version: '1',
      type: 'live',
      notification_id: 'trigger-A',
      targets: [{ user: { user_id: DIGEST_USER_ID, user_email: '', notifiers: [], user_service_account: false }, type: 'read', message: 'matched message' }],
      data: { id: 'obj-x', type: 'report', extensions: {} } as unknown as ActivityNotificationEvent['data'],
      origin: {},
    };
    driveBatches([[event]]);
    await handleDigestNotifications({} as AuthContext);
    const digestEvent = vi.mocked(storeNotificationEvent).mock.calls[0][1] as unknown as { data: Array<{ message: string }> };
    expect(digestEvent.data).toEqual([expect.objectContaining({ message: 'matched message' })]);
    expect(vi.mocked(extractStixRepresentativeForUser)).not.toHaveBeenCalled();
  });

  it('still sends the other digests due at the same time when one of them fails', async () => {
    const otherDigestTrigger = { ...digestTrigger, internal_id: 'digest-2', id: 'digest-2', trigger_ids: ['trigger-B'] } as unknown as BasicStoreEntityTrigger;
    const resolveFromCache = (_ctx: AuthContext, _user: AuthUser, type: string) => {
      return Promise.resolve(type === ENTITY_TYPE_TRIGGER ? [digestTrigger, otherDigestTrigger] : [digestUser]);
    };
    vi.mocked(getEntitiesListFromCache).mockImplementation(resolveFromCache as unknown as typeof getEntitiesListFromCache);
    driveBatches([[liveEvent('trigger-A', DIGEST_USER_ID), liveEvent('trigger-B', DIGEST_USER_ID)]]);
    // The first digest fails when it is stored
    vi.mocked(storeNotificationEvent).mockRejectedValueOnce(new Error('Redis unavailable'));
    await expect(handleDigestNotifications({} as AuthContext)).resolves.toBeUndefined();
    const storedDigestIds = vi.mocked(storeNotificationEvent).mock.calls.map((call) => (call[1] as unknown as { notification_id: string }).notification_id);
    expect(storedDigestIds).toEqual(['digest-1', 'digest-2']);
  });

  it('does not emit a digest event when no collected event matches the digest', async () => {
    driveBatches([[liveEvent('trigger-other', DIGEST_USER_ID)]]);
    await handleDigestNotifications({} as AuthContext);
    expect(vi.mocked(storeNotificationEvent)).not.toHaveBeenCalled();
  });
});

describe('isStixObjectNotificationData', () => {
  it('recognizes a STIX object by the type of its OpenCTI extension', () => {
    const stix = { id: 'report--1', type: 'report', extensions: { [STIX_EXT_OCTI]: { type: 'Report' } } } as unknown as DigestContentEvent['data'];
    expect(isStixObjectNotificationData(stix)).toBe(true);
  });

  it.each([
    ['the context data of a login', { provider: 'local', username: 'admin@opencti.io' }],
    ['an activity data with a representative', { id: 'x', representative: { main: 'Report A', secondary: '' } }],
    ['empty extensions', { id: 'x', type: 'report', extensions: {} }],
    ['an OpenCTI extension without type', { id: 'x', type: 'report', extensions: { [STIX_EXT_OCTI]: {} } }],
    ['a null OpenCTI extension', { id: 'x', type: 'report', extensions: { [STIX_EXT_OCTI]: null } }],
    ['an OpenCTI extension but no STIX type', { id: 'x', extensions: { [STIX_EXT_OCTI]: { type: 'Report' } } }],
  ])('rejects %s', (_label, data) => {
    expect(isStixObjectNotificationData(data as unknown as DigestContentEvent['data'])).toBe(false);
  });
});
