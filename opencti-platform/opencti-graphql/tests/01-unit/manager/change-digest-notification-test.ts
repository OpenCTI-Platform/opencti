import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { AuthContext, AuthUser } from '../../../src/types/user';
import type { BasicStoreEntityTrigger } from '../../../src/modules/notification/notification-types';

// Mock the stream layer to capture the stored digest events (no Redis needed).
vi.mock('../../../src/database/stream/stream-handler', () => ({
  fetchRangeNotifications: vi.fn(),
  storeNotificationEvent: vi.fn(),
  createStreamProcessor: vi.fn(),
}));

// Mock the cache so the triggers and their recipients are canned (no ElasticSearch needed).
vi.mock('../../../src/database/cache', () => ({
  getEntitiesListFromCache: vi.fn().mockResolvedValue([]),
  getEntityFromCache: vi.fn(),
}));

// Mock the landscape diff of a change digest: the orchestration of the manager is under test.
const buildChangeDigestDataMock = vi.fn();
vi.mock('../../../src/modules/timeMachine/timeMachine-changeDigest', () => ({
  TRIGGER_TYPE_CHANGE_DIGEST: 'change_digest',
  buildChangeDigestData: (...args: unknown[]) => buildChangeDigestDataMock(...args),
}));

// Capture the "change digests sent" telemetry counter (no Redis needed).
const addChangeDigestSentCountMock = vi.fn();
vi.mock('../../../src/manager/telemetryManager', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../src/manager/telemetryManager')>()),
  addChangeDigestSentCount: () => addChangeDigestSentCountMock(),
}));

// The Redis schedule of the change digest jobs, kept in memory (member -> score, like the sorted set), and the failed
// attempts per job.
const scheduledJobs = vi.hoisted(() => new Map<string, number>());
const failedAttempts = vi.hoisted(() => new Map<string, number>());
vi.mock('../../../src/database/redis', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../src/database/redis')>()),
  redisAddChangeDigestJobs: async (jobs: Array<{ score: number; member: string }>) => {
    jobs.forEach(({ score, member }) => {
      if (!scheduledJobs.has(member)) scheduledJobs.set(member, score);
    });
  },
  redisExpireChangeDigestJobs: async (expiredBefore: number) => {
    const expired = [...scheduledJobs.entries()].filter(([, score]) => score < expiredBefore);
    expired.forEach(([member]) => scheduledJobs.delete(member));
    return expired.length;
  },
  redisGetChangeDigestJobs: async (dueAt: number, count: number) => {
    return [...scheduledJobs.entries()]
      .filter(([, score]) => score <= dueAt)
      .sort(([memberA, scoreA], [memberB, scoreB]) => scoreA - scoreB || memberA.localeCompare(memberB))
      .slice(0, count)
      .map(([member]) => member);
  },
  redisIsChangeDigestJobDue: async (member: string, dueAt: number) => scheduledJobs.has(member) && (scheduledJobs.get(member) as number) <= dueAt,
  redisCountChangeDigestJobFailure: async (member: string) => {
    failedAttempts.set(member, (failedAttempts.get(member) ?? 0) + 1);
    return failedAttempts.get(member) as number;
  },
  redisRescheduleChangeDigestJob: async (member: string, retryAt: number) => {
    if (scheduledJobs.has(member)) scheduledJobs.set(member, retryAt);
  },
  redisRemoveChangeDigestJob: async (member: string) => {
    scheduledJobs.delete(member);
    failedAttempts.delete(member);
  },
}));

// The job locks: held ids and the abort controller of each lock taken (no Redis needed).
const jobLocks = vi.hoisted(() => new Map<string, AbortController>());
vi.mock('../../../src/lock/master-lock', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../src/lock/master-lock')>()),
  lockResources: async (ids: string[]) => {
    if (ids.some((id) => jobLocks.has(id))) {
      throw new Error('Execution timeout, too many concurrent call on the same entities');
    }
    const controller = new AbortController();
    ids.forEach((id) => jobLocks.set(id, controller));
    return {
      signal: controller.signal,
      unlock: async () => ids.forEach((id) => jobLocks.delete(id)),
    };
  },
}));

import {
  CHANGE_DIGEST_JOB_LOCK_PREFIX,
  CHANGE_DIGEST_MAX_ATTEMPTS,
  CHANGE_DIGEST_MAX_DELAY_MS,
  changeDigestQueue,
  handleChangeDigestNotifications,
  toChangeDigestJobMember,
} from '../../../src/manager/notificationManager';
import { getEntitiesListFromCache, getEntityFromCache } from '../../../src/database/cache';
import { storeNotificationEvent } from '../../../src/database/stream/stream-handler';
import { ENTITY_TYPE_TRIGGER } from '../../../src/modules/notification/notification-types';
import { ACCOUNT_STATUS_ACTIVE } from '../../../src/config/conf';

interface StoredDigestEvent {
  type: string;
  notification_id: string;
  delivery_key?: string;
  target: { user_id: string; notifiers: string[] };
  data: unknown[];
}

describe('handleChangeDigestNotifications', () => {
  // Monday 09:00 UTC, aligned with the weekly trigger time of the change digest
  const FROZEN = new Date('2026-01-12T09:00:00.000Z');

  const buildUser = (id: string) => ({
    id,
    internal_id: id,
    user_email: `${id}@local`,
    user_service_account: false,
    groups: [],
    organizations: [],
    personal_notifiers: [],
    account_status: ACCOUNT_STATUS_ACTIVE,
  } as unknown as AuthUser);
  const analyst = buildUser('analyst-1');
  const manager = buildUser('manager-1');

  const changeDigest = {
    internal_id: 'change-digest-1',
    id: 'change-digest-1',
    name: 'Weekly landscape',
    trigger_type: 'change_digest',
    period: 'week',
    trigger_time: '1-09:00:00.000Z',
    filters: null,
    scope_entity_types: ['Intrusion-Set'],
    notifiers: ['notifier-ui'],
    restricted_members: [{ id: analyst.id }, { id: manager.id }],
  } as unknown as BasicStoreEntityTrigger;
  const regularDigest = { ...changeDigest, internal_id: 'digest-1', id: 'digest-1', trigger_type: 'digest', trigger_ids: [] } as unknown as BasicStoreEntityTrigger;
  const digestLine = { notification_id: 'change-digest-1', instance: { id: 'intrusion-set--1' }, type: 'update', message: '`2` new relationship(s)' };

  const primeCache = (triggers: BasicStoreEntityTrigger[]) => {
    const resolveFromCache = (_ctx: AuthContext, _user: AuthUser, type: string) => {
      return Promise.resolve(type === ENTITY_TYPE_TRIGGER ? triggers : [analyst, manager]);
    };
    vi.mocked(getEntitiesListFromCache).mockImplementation(resolveFromCache as unknown as typeof getEntitiesListFromCache);
    vi.mocked(getEntityFromCache).mockResolvedValue({ platform_notifier_auto_trigger_assignee: true } as unknown as Awaited<ReturnType<typeof getEntityFromCache>>);
  };

  const storedEvents = () => vi.mocked(storeNotificationEvent).mock.calls.map((call) => call[1] as unknown as StoredDigestEvent);

  beforeEach(() => {
    scheduledJobs.clear();
    failedAttempts.clear();
    jobLocks.clear();
    vi.useFakeTimers();
    vi.setSystemTime(FROZEN);
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.clearAllMocks();
  });

  it('computes the digest of each recipient with their own rights over the last period and stores it', async () => {
    primeCache([changeDigest]);
    buildChangeDigestDataMock.mockImplementation(async (_ctx: AuthContext, recipient: AuthUser) => (recipient.id === analyst.id ? [digestLine] : []));
    await handleChangeDigestNotifications({} as AuthContext);
    await changeDigestQueue.idle();
    expect(buildChangeDigestDataMock).toHaveBeenCalledTimes(2);
    expect(buildChangeDigestDataMock.mock.calls.map((call) => (call[1] as AuthUser).id).sort()).toEqual([analyst.id, manager.id]);
    buildChangeDigestDataMock.mock.calls.forEach(([, , trigger, from, to]) => {
      expect((trigger as BasicStoreEntityTrigger).internal_id).toBe('change-digest-1');
      expect(from).toBe('2026-01-05T09:00:00.000Z');
      expect(to).toBe('2026-01-12T09:00:00.000Z');
    });
    // Only the recipient with changes in the period receives a digest
    const events = storedEvents();
    expect(events).toHaveLength(1);
    expect(events[0].type).toBe('digest');
    expect(events[0].notification_id).toBe('change-digest-1');
    expect(events[0].target.user_id).toBe(analyst.id);
    expect(events[0].target.notifiers).toEqual(['notifier-ui']);
    expect(events[0].data).toEqual([digestLine]);
    // Delivered once per trigger, recipient and period, even if a retry stores it again
    expect(events[0].delivery_key).toBe(toChangeDigestJobMember({ triggerId: 'change-digest-1', userId: analyst.id, fromDate: '2026-01-05T09:00:00.000Z', toDate: FROZEN.toISOString() }));
    // Only the stored digest is counted as sent
    expect(addChangeDigestSentCountMock).toHaveBeenCalledTimes(1);
  });

  it('does not count a digest as sent when it cannot be stored', async () => {
    primeCache([changeDigest]);
    buildChangeDigestDataMock.mockResolvedValue([digestLine]);
    vi.mocked(storeNotificationEvent)
      .mockRejectedValueOnce(new Error('stream unavailable'))
      .mockResolvedValueOnce(undefined as unknown as Awaited<ReturnType<typeof storeNotificationEvent>>);
    await handleChangeDigestNotifications({} as AuthContext);
    await changeDigestQueue.idle();
    expect(vi.mocked(storeNotificationEvent)).toHaveBeenCalledTimes(2);
    expect(addChangeDigestSentCountMock).toHaveBeenCalledTimes(1);
  });

  it('ignores the change digests that are not due and the regular digests', async () => {
    primeCache([{ ...changeDigest, trigger_time: '2-09:00:00.000Z' } as unknown as BasicStoreEntityTrigger, regularDigest]);
    await handleChangeDigestNotifications({} as AuthContext);
    await changeDigestQueue.idle();
    expect(buildChangeDigestDataMock).not.toHaveBeenCalled();
    expect(vi.mocked(storeNotificationEvent)).not.toHaveBeenCalled();
  });

  it('keeps serving the other recipients when the digest of one recipient fails', async () => {
    primeCache([changeDigest]);
    buildChangeDigestDataMock.mockImplementation(async (_ctx: AuthContext, recipient: AuthUser) => {
      if (recipient.id === analyst.id) throw new Error('landscape diff failed');
      return [digestLine];
    });
    await handleChangeDigestNotifications({} as AuthContext);
    await changeDigestQueue.idle();
    const events = storedEvents();
    expect(events).toHaveLength(1);
    expect(events[0].target.user_id).toBe(manager.id);
    expect(addChangeDigestSentCountMock).toHaveBeenCalledTimes(1);
  });

  it('returns to the scheduler before the digests are computed and never queues a digest twice', async () => {
    primeCache([changeDigest]);
    let release: () => void = () => {};
    const computing = new Promise<void>((resolve) => {
      release = resolve;
    });
    buildChangeDigestDataMock.mockImplementation(async () => {
      await computing;
      return [digestLine];
    });
    // The scheduler is not held by the computations of the recipients
    await handleChangeDigestNotifications({} as AuthContext);
    expect(storedEvents()).toHaveLength(0);
    expect(changeDigestQueue.size()).toBe(2);
    // The same minute processed again does not queue the same digests again
    await handleChangeDigestNotifications({} as AuthContext);
    expect(changeDigestQueue.size()).toBe(2);
    // A digest leaves the schedule only once it is done
    expect(scheduledJobs.size).toBe(2);
    release();
    await changeDigestQueue.idle();
    expect(buildChangeDigestDataMock).toHaveBeenCalledTimes(2);
    expect(storedEvents()).toHaveLength(2);
    expect(scheduledJobs.size).toBe(0);
  });

  it('sends at a later pass the digests still scheduled after a restart, over their own period', async () => {
    primeCache([changeDigest]);
    buildChangeDigestDataMock.mockResolvedValue([digestLine]);
    // Left by a previous lock holder: the digest of the analyst for the period that ended an hour ago
    const fromDate = '2026-01-05T08:00:00.000Z';
    const toDate = '2026-01-12T08:00:00.000Z';
    scheduledJobs.set(toChangeDigestJobMember({ triggerId: 'change-digest-1', userId: analyst.id, fromDate, toDate }), Date.parse(toDate));
    // 09:05, the change digest is not due
    vi.setSystemTime(new Date('2026-01-12T09:05:00.000Z'));
    await handleChangeDigestNotifications({} as AuthContext);
    await changeDigestQueue.idle();
    expect(buildChangeDigestDataMock).toHaveBeenCalledTimes(1);
    const [, recipient, , from, to] = buildChangeDigestDataMock.mock.calls[0];
    expect((recipient as AuthUser).id).toBe(analyst.id);
    expect(from).toBe(fromDate);
    expect(to).toBe(toDate);
    expect(storedEvents()).toHaveLength(1);
    expect(scheduledJobs.size).toBe(0);
  });

  it('keeps the digests that have not started scheduled when the manager stops', async () => {
    primeCache([changeDigest]);
    let release: () => void = () => {};
    const computing = new Promise<void>((resolve) => {
      release = resolve;
    });
    buildChangeDigestDataMock.mockImplementation(async () => {
      await computing;
      return [digestLine];
    });
    // Three digests for two computations at a time: the third one waits in the queue
    const toDate = '2026-01-12T08:00:00.000Z';
    scheduledJobs.set(toChangeDigestJobMember({ triggerId: 'change-digest-1', userId: analyst.id, fromDate: '2026-01-05T08:00:00.000Z', toDate }), Date.parse(toDate));
    await handleChangeDigestNotifications({} as AuthContext);
    expect(changeDigestQueue.size()).toBe(3);
    // The manager stops: what has not started is forgotten by the queue, not by the schedule
    changeDigestQueue.clear();
    expect(changeDigestQueue.size()).toBe(2);
    release();
    await changeDigestQueue.idle();
    expect(buildChangeDigestDataMock).toHaveBeenCalledTimes(2);
    expect(scheduledJobs.size).toBe(1);
    // The next pass, a minute later, sends the digest left in the schedule
    vi.setSystemTime(new Date('2026-01-12T09:01:00.000Z'));
    await handleChangeDigestNotifications({} as AuthContext);
    await changeDigestQueue.idle();
    expect(buildChangeDigestDataMock).toHaveBeenCalledTimes(3);
    expect(storedEvents()).toHaveLength(3);
    expect(scheduledJobs.size).toBe(0);
  });

  it('does not send a digest that left the schedule before its turn in the queue', async () => {
    primeCache([changeDigest]);
    let release: () => void = () => {};
    const computing = new Promise<void>((resolve) => {
      release = resolve;
    });
    buildChangeDigestDataMock.mockImplementation(async () => {
      await computing;
      return [digestLine];
    });
    const toDate = '2026-01-12T08:00:00.000Z';
    scheduledJobs.set(toChangeDigestJobMember({ triggerId: 'change-digest-1', userId: analyst.id, fromDate: '2026-01-05T08:00:00.000Z', toDate }), Date.parse(toDate));
    await handleChangeDigestNotifications({} as AuthContext);
    expect(changeDigestQueue.size()).toBe(3);
    // The waiting digest (the manager's, last in order) was sent meanwhile by an earlier job of the same digest
    const waiting = toChangeDigestJobMember({ triggerId: 'change-digest-1', userId: manager.id, fromDate: '2026-01-05T09:00:00.000Z', toDate: FROZEN.toISOString() });
    expect(scheduledJobs.delete(waiting)).toBe(true);
    release();
    await changeDigestQueue.idle();
    expect(buildChangeDigestDataMock).toHaveBeenCalledTimes(2);
    expect(storedEvents().map((event) => event.target.user_id)).toEqual([analyst.id, analyst.id]);
  });

  it('tries a failed digest again five minutes later and sends it once it succeeds', async () => {
    primeCache([changeDigest]);
    let failures = 1;
    buildChangeDigestDataMock.mockImplementation(async (_ctx: AuthContext, recipient: AuthUser) => {
      if (recipient.id === analyst.id && failures > 0) {
        failures -= 1;
        throw new Error('engine unavailable');
      }
      return [digestLine];
    });
    const analystJob = toChangeDigestJobMember({ triggerId: 'change-digest-1', userId: analyst.id, fromDate: '2026-01-05T09:00:00.000Z', toDate: FROZEN.toISOString() });
    await handleChangeDigestNotifications({} as AuthContext);
    await changeDigestQueue.idle();
    expect(storedEvents().map((event) => event.target.user_id)).toEqual([manager.id]);
    expect(scheduledJobs.get(analystJob)).toBe(Date.parse('2026-01-12T09:05:00.000Z'));
    // Not tried again before its time
    vi.setSystemTime(new Date('2026-01-12T09:04:00.000Z'));
    await handleChangeDigestNotifications({} as AuthContext);
    await changeDigestQueue.idle();
    expect(buildChangeDigestDataMock).toHaveBeenCalledTimes(2);
    vi.setSystemTime(new Date('2026-01-12T09:05:00.000Z'));
    await handleChangeDigestNotifications({} as AuthContext);
    await changeDigestQueue.idle();
    expect(buildChangeDigestDataMock).toHaveBeenCalledTimes(3);
    expect(storedEvents().map((event) => event.target.user_id)).toEqual([manager.id, analyst.id]);
    expect(scheduledJobs.size).toBe(0);
    expect(failedAttempts.size).toBe(0);
  });

  it('tries a failing digest five times with a growing delay, then drops it', async () => {
    primeCache([changeDigest]);
    buildChangeDigestDataMock.mockImplementation(async (_ctx: AuthContext, recipient: AuthUser) => {
      if (recipient.id === analyst.id) throw new Error('landscape diff failed');
      return [];
    });
    const analystJob = toChangeDigestJobMember({ triggerId: 'change-digest-1', userId: analyst.id, fromDate: '2026-01-05T09:00:00.000Z', toDate: FROZEN.toISOString() });
    await handleChangeDigestNotifications({} as AuthContext);
    await changeDigestQueue.idle();
    const retries: string[] = [];
    while (scheduledJobs.has(analystJob)) {
      const retryAt = scheduledJobs.get(analystJob) as number;
      retries.push(new Date(retryAt).toISOString());
      vi.setSystemTime(new Date(retryAt));
      await handleChangeDigestNotifications({} as AuthContext);
      await changeDigestQueue.idle();
    }
    expect(retries).toEqual(['2026-01-12T09:05:00.000Z', '2026-01-12T09:15:00.000Z', '2026-01-12T09:35:00.000Z', '2026-01-12T10:15:00.000Z']);
    expect(buildChangeDigestDataMock.mock.calls.filter((call) => (call[1] as AuthUser).id === analyst.id)).toHaveLength(CHANGE_DIGEST_MAX_ATTEMPTS);
    expect(failedAttempts.size).toBe(0);
    expect(storedEvents()).toHaveLength(0);
  });

  it('leaves a digest to the platform that holds its job and sends it once the job is released', async () => {
    primeCache([changeDigest]);
    buildChangeDigestDataMock.mockResolvedValue([digestLine]);
    const analystJob = toChangeDigestJobMember({ triggerId: 'change-digest-1', userId: analyst.id, fromDate: '2026-01-05T09:00:00.000Z', toDate: FROZEN.toISOString() });
    // The previous holder of the notification manager is still computing the digest of the analyst
    jobLocks.set(`${CHANGE_DIGEST_JOB_LOCK_PREFIX}${analystJob}`, new AbortController());
    await handleChangeDigestNotifications({} as AuthContext);
    await changeDigestQueue.idle();
    expect(storedEvents().map((event) => event.target.user_id)).toEqual([manager.id]);
    expect(scheduledJobs.get(analystJob)).toBe(FROZEN.getTime());
    expect(failedAttempts.size).toBe(0);
    // It stopped without sending: the job is free and still due at the next pass
    jobLocks.clear();
    vi.setSystemTime(new Date('2026-01-12T09:01:00.000Z'));
    await handleChangeDigestNotifications({} as AuthContext);
    await changeDigestQueue.idle();
    expect(storedEvents().map((event) => event.target.user_id)).toEqual([manager.id, analyst.id]);
    expect(scheduledJobs.size).toBe(0);
    expect(jobLocks.size).toBe(0);
  });

  it('does not store a digest whose job lock is lost during the computation and leaves the job to its new owner', async () => {
    primeCache([changeDigest]);
    const analystJob = toChangeDigestJobMember({ triggerId: 'change-digest-1', userId: analyst.id, fromDate: '2026-01-05T09:00:00.000Z', toDate: FROZEN.toISOString() });
    buildChangeDigestDataMock.mockImplementation(async (_ctx: AuthContext, recipient: AuthUser) => {
      if (recipient.id === analyst.id) jobLocks.get(`${CHANGE_DIGEST_JOB_LOCK_PREFIX}${analystJob}`)?.abort();
      return [digestLine];
    });
    await handleChangeDigestNotifications({} as AuthContext);
    await changeDigestQueue.idle();
    expect(storedEvents().map((event) => event.target.user_id)).toEqual([manager.id]);
    expect(scheduledJobs.get(analystJob)).toBe(FROZEN.getTime());
    expect(failedAttempts.size).toBe(0);
  });

  it('removes without computing them the jobs of a deleted trigger or of a former recipient', async () => {
    primeCache([{ ...changeDigest, trigger_time: '2-09:00:00.000Z' } as unknown as BasicStoreEntityTrigger]);
    const toDate = '2026-01-12T08:00:00.000Z';
    const fromDate = '2026-01-05T08:00:00.000Z';
    scheduledJobs.set(toChangeDigestJobMember({ triggerId: 'deleted-digest', userId: analyst.id, fromDate, toDate }), Date.parse(toDate));
    scheduledJobs.set(toChangeDigestJobMember({ triggerId: 'change-digest-1', userId: 'former-recipient', fromDate, toDate }), Date.parse(toDate));
    await handleChangeDigestNotifications({} as AuthContext);
    await changeDigestQueue.idle();
    expect(buildChangeDigestDataMock).not.toHaveBeenCalled();
    expect(scheduledJobs.size).toBe(0);
  });

  it('forgets the digests whose period ended more than a week ago and the unreadable jobs', async () => {
    primeCache([]);
    const toDate = new Date(FROZEN.getTime() - CHANGE_DIGEST_MAX_DELAY_MS - 60000).toISOString();
    scheduledJobs.set(toChangeDigestJobMember({ triggerId: 'change-digest-1', userId: analyst.id, fromDate: toDate, toDate }), Date.parse(toDate));
    scheduledJobs.set('not-a-job', FROZEN.getTime());
    await handleChangeDigestNotifications({} as AuthContext);
    await changeDigestQueue.idle();
    expect(buildChangeDigestDataMock).not.toHaveBeenCalled();
    expect(scheduledJobs.size).toBe(0);
  });
});
