import { beforeEach, describe, expect, it, vi } from 'vitest';
import { buildDigestLines, deliverKnowledgeHealthDigest, sendKnowledgeHealthDigest } from '../../../../src/modules/curation/curation-health';
import { addNotification } from '../../../../src/modules/notification/notification-domain';
import { sendMail } from '../../../../src/database/smtp';
import type { BasicStoreEntityKnowledgeHealthSnapshot, CurationSettings } from '../../../../src/modules/curation/curation-types';

const deliveries = new Map<string, Set<string>>();
const pending: { snapshotId: string | null; retryAllowed: boolean } = { snapshotId: null, retryAllowed: true };

vi.mock('../../../../src/database/redis', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/database/redis')>()),
  redisCurationGetDigestDeliveries: vi.fn(async (snapshotId: string) => [...(deliveries.get(snapshotId) ?? [])]),
  redisCurationAddDigestDelivery: vi.fn(async (snapshotId: string, recipient: string) => {
    deliveries.set(snapshotId, (deliveries.get(snapshotId) ?? new Set()).add(recipient));
  }),
  redisCurationGetPendingDigest: vi.fn(async () => pending.snapshotId),
  redisCurationSetPendingDigest: vi.fn(async (snapshotId: string) => {
    pending.snapshotId = snapshotId;
  }),
  redisCurationClearPendingDigest: vi.fn(async () => {
    pending.snapshotId = null;
  }),
  redisCurationAcquireDigestRetry: vi.fn(async () => pending.retryAllowed),
}));
vi.mock('../../../../src/database/cache', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/database/cache')>()),
  getEntitiesListFromCache: vi.fn(async () => ['alice', 'bob', 'carol'].map((name) => ({
    id: `${name}-id`,
    user_email: `${name}@example.com`,
    account_status: 'Active',
    groups: [],
    organizations: [],
  }))),
  getEntityFromCache: vi.fn(async () => ({ platform_url: 'https://opencti.example.com' })),
}));
vi.mock('../../../../src/manager/notificationManager', () => ({ isNotificationRecipientActive: () => true }));
vi.mock('../../../../src/modules/notification/notification-domain', () => ({ addNotification: vi.fn() }));
vi.mock('../../../../src/database/smtp', () => ({ sendMail: vi.fn(), smtpComputeFrom: vi.fn(async () => 'opencti@example.com') }));
vi.mock('../../../../src/database/middleware', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/database/middleware')>()),
  patchAttribute: vi.fn(),
}));

const settings = { digest_enabled: true, digest_recipient_ids: ['alice-id', 'bob-id', 'carol-id'] } as unknown as CurationSettings;
const snapshot = {
  internal_id: 'snapshot-id',
  health_score: 72,
  score_trend: 3,
  health_metrics: {
    duplicate_estimate: 4,
    duplicate_rate: 0.02,
    curated_entities_count: 200,
    contradiction_count: 1,
    stale_count: 5,
    stale_share: 0.025,
    alias_coverage: 0.6,
    source_conflict_rate: 0.1,
    open_proposals_count: 9,
    accepted_count: 2,
    auto_applied_count: 1,
    rejected_count: 1,
    reverted_count: 0,
    merges_count: 2,
    unmerges_count: 0,
  },
} as unknown as BasicStoreEntityKnowledgeHealthSnapshot;
const newerSnapshot = { ...snapshot, internal_id: 'newer-snapshot-id' } as BasicStoreEntityKnowledgeHealthSnapshot;

type Notified = { user_id: string; notification_content: Array<{ events: Array<{ instance_id: string }> }> };
// The digest notifications stored in the platform, as the lookup of the notified recipients reads them.
const storedNotifications: Notified[] = [];

vi.mock('../../../../src/database/middleware-loader', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/database/middleware-loader')>()),
  storeLoadById: vi.fn(async (_context: unknown, _user: unknown, id: string) => (id === 'snapshot-id' ? snapshot : undefined)),
  fullEntitiesList: vi.fn(async () => storedNotifications),
}));

const notifiedUsers = () => vi.mocked(addNotification).mock.calls.map(([, , notification]) => (notification as Notified).user_id);
const notifiedSnapshots = () => vi.mocked(addNotification).mock.calls.map(([, , notification]) => (notification as Notified).notification_content[0].events[0].instance_id);
const failFor = (failing: string[]) => vi.mocked(addNotification).mockImplementation(async (_context, _user, notification) => {
  if (failing.includes((notification as Notified).user_id)) throw new Error('cannot notify');
  return notification as never;
});

describe('Knowledge Health weekly digest content', () => {
  it('counts the activity since the previous snapshot, or over the last 24 hours for the first snapshot', () => {
    const activity = 'proposals accepted, 1 auto-applied, 1 rejected, 0 reverted; 2 merges, 0 unmerges';
    expect(buildDigestLines(snapshot)).toContain(`Since the previous snapshot: 2 ${activity}`);
    const first = { ...snapshot, score_trend: null } as unknown as BasicStoreEntityKnowledgeHealthSnapshot;
    const lines = buildDigestLines(first);
    expect(lines).toContain(`During the last 24 hours: 2 ${activity}`);
    expect(lines[0]).toBe('Knowledge health score: 72 of 100');
  });
});

describe('Knowledge Health weekly digest', () => {
  beforeEach(() => {
    deliveries.clear();
    storedNotifications.length = 0;
    pending.snapshotId = null;
    pending.retryAllowed = true;
    vi.mocked(addNotification).mockReset();
    vi.mocked(sendMail).mockReset();
  });

  it('skips a recipient whose notification fails, and never notifies a recipient twice when sent again', async () => {
    failFor(['bob-id']);
    expect(await sendKnowledgeHealthDigest({} as never, settings, snapshot)).toEqual({ delivered: 2, undelivered: 1, emailPending: false });
    expect(notifiedUsers()).toEqual(['alice-id', 'bob-id', 'carol-id']);
    expect(sendMail).toHaveBeenCalledTimes(1);

    // Sent again for the same snapshot (a retry, a restart): only the recipient it missed is notified, no second email.
    vi.mocked(addNotification).mockClear();
    failFor([]);
    expect(await sendKnowledgeHealthDigest({} as never, settings, snapshot)).toEqual({ delivered: 3, undelivered: 0, emailPending: false });
    expect(notifiedUsers()).toEqual(['bob-id']);
    expect(sendMail).toHaveBeenCalledTimes(1);
  });

  it('never notifies a recipient twice when the delivery mark of its notification was lost', async () => {
    // Alice's notification exists, but the mark that remembers it was never written (Redis unavailable).
    storedNotifications.push(
      { user_id: 'alice-id', notification_content: [{ events: [{ instance_id: 'snapshot-id' }] }] },
      // A digest of another snapshot does not count as this one.
      { user_id: 'bob-id', notification_content: [{ events: [{ instance_id: 'newer-snapshot-id' }] }] },
    );
    failFor([]);
    expect(await sendKnowledgeHealthDigest({} as never, settings, snapshot)).toEqual({ delivered: 3, undelivered: 0, emailPending: false });
    expect(notifiedUsers()).toEqual(['bob-id', 'carol-id']);
  });

  it('still sends the email when no recipient could be notified, and keeps the notifications pending', async () => {
    vi.mocked(addNotification).mockRejectedValue(new Error('cannot notify'));
    expect(await deliverKnowledgeHealthDigest({} as never, settings, snapshot, true)).toBe(true);
    expect(sendMail).toHaveBeenCalledTimes(1);
    expect(pending.snapshotId).toBe('snapshot-id');

    // The retry notifies the recipients the notifications missed, and never sends the email twice.
    vi.mocked(addNotification).mockReset();
    failFor([]);
    expect(await deliverKnowledgeHealthDigest({} as never, settings, newerSnapshot, false)).toBe(false);
    expect(notifiedUsers()).toEqual(['alice-id', 'bob-id', 'carol-id']);
    expect(sendMail).toHaveBeenCalledTimes(1);
    expect(pending.snapshotId).toBeNull();
  });

  it('fails, to be sent again, when neither a notification nor the email reached anybody', async () => {
    vi.mocked(addNotification).mockRejectedValue(new Error('cannot notify'));
    vi.mocked(sendMail).mockRejectedValueOnce(new Error('smtp down'));
    await expect(sendKnowledgeHealthDigest({} as never, settings, snapshot)).rejects.toThrow('could not be delivered to any recipient');
    expect(sendMail).toHaveBeenCalledTimes(1);
  });

  it('keeps a digest that missed a recipient pending on its snapshot, and retries it for that recipient only', async () => {
    failFor(['bob-id']);
    expect(await deliverKnowledgeHealthDigest({} as never, settings, snapshot, true)).toBe(true);
    expect(pending.snapshotId).toBe('snapshot-id');

    // A later cycle, with a newer snapshot: the retry stays on the snapshot the digest was sent for.
    vi.mocked(addNotification).mockClear();
    failFor([]);
    expect(await deliverKnowledgeHealthDigest({} as never, settings, newerSnapshot, false)).toBe(false);
    expect(notifiedUsers()).toEqual(['bob-id']);
    expect(notifiedSnapshots()).toEqual(['snapshot-id']);
    expect(pending.snapshotId).toBeNull();
    expect(sendMail).toHaveBeenCalledTimes(1);

    // Every recipient has it: nothing is sent again.
    vi.mocked(addNotification).mockClear();
    expect(await deliverKnowledgeHealthDigest({} as never, settings, newerSnapshot, false)).toBe(false);
    expect(addNotification).not.toHaveBeenCalled();
  });

  it('keeps a digest whose email failed pending, and sends only the email again', async () => {
    failFor([]);
    vi.mocked(sendMail).mockRejectedValueOnce(new Error('smtp down'));
    expect(await deliverKnowledgeHealthDigest({} as never, settings, snapshot, true)).toBe(true);
    expect(pending.snapshotId).toBe('snapshot-id');

    vi.mocked(addNotification).mockClear();
    expect(await deliverKnowledgeHealthDigest({} as never, settings, newerSnapshot, false)).toBe(false);
    expect(addNotification).not.toHaveBeenCalled();
    expect(sendMail).toHaveBeenCalledTimes(2);
    expect(pending.snapshotId).toBeNull();
  });

  it('retries a pending digest at most once per retry interval', async () => {
    failFor(['bob-id']);
    await deliverKnowledgeHealthDigest({} as never, settings, snapshot, true);
    vi.mocked(addNotification).mockClear();
    pending.retryAllowed = false;
    expect(await deliverKnowledgeHealthDigest({} as never, settings, snapshot, false)).toBe(false);
    expect(addNotification).not.toHaveBeenCalled();
    expect(pending.snapshotId).toBe('snapshot-id');
  });

  it('drops a pending digest once the digest is disabled', async () => {
    pending.snapshotId = 'snapshot-id';
    const disabled = { ...settings, digest_enabled: false } as CurationSettings;
    expect(await deliverKnowledgeHealthDigest({} as never, disabled, snapshot, false)).toBe(false);
    expect(addNotification).not.toHaveBeenCalled();
    expect(pending.snapshotId).toBeNull();
  });
});
