import { afterEach, describe, expect, it } from 'vitest';
import { v4 as uuid } from 'uuid';
import {
  getClientBase,
  redisAddChangeDigestJobs,
  redisAreDigestDeliveriesConfirmed,
  redisCountChangeDigestJobAttempt,
  redisExpireChangeDigestJobs,
  redisGetChangeDigestJobAttempts,
  redisGetChangeDigestJobs,
  redisClaimDigestDelivery,
  redisConfirmDigestDelivery,
  redisIsChangeDigestJobDue,
  redisReleaseDigestDelivery,
  redisRemoveChangeDigestJob,
  redisRenewDigestDelivery,
  redisRescheduleChangeDigestJob,
} from '../../../../src/database/redis';

// Scores far in the future: the notification manager running with the tests only reads the jobs that are due
const FUTURE = Date.parse('2100-01-01T00:00:00.000Z');

describe('Change digest jobs in Redis', () => {
  const run = uuid();
  const member = (name: string) => `${run}|${name}`;
  const created: string[] = [];
  const add = async (jobs: Array<{ score: number; member: string }>) => {
    created.push(...jobs.map((job) => job.member));
    await redisAddChangeDigestJobs(jobs);
  };
  const scheduledOfRun = async (dueAt: number) => (await redisGetChangeDigestJobs(dueAt, 1000)).filter((job) => job.startsWith(run));

  afterEach(async () => {
    await Promise.all(created.splice(0).map((job) => redisRemoveChangeDigestJob(job)));
  });

  it('keeps the first schedule of a job and returns the due jobs oldest first', async () => {
    await add([{ score: FUTURE + 2000, member: member('b') }, { score: FUTURE + 1000, member: member('a') }, { score: FUTURE + 5000, member: member('later') }]);
    // NX: scheduling a waiting job again does not move it
    await add([{ score: FUTURE + 9000, member: member('a') }]);
    expect(await scheduledOfRun(FUTURE + 3000)).toEqual([member('a'), member('b')]);
    expect(await redisIsChangeDigestJobDue(member('a'), FUTURE + 3000)).toBe(true);
    expect(await redisIsChangeDigestJobDue(member('later'), FUTURE + 3000)).toBe(false);
    expect(await redisIsChangeDigestJobDue(member('unknown'), FUTURE + 3000)).toBe(false);
    await redisRemoveChangeDigestJob(member('a'));
    expect(await scheduledOfRun(FUTURE + 3000)).toEqual([member('b')]);
  });

  it('reschedules only a job still scheduled and forgets its attempts with it', async () => {
    await add([{ score: FUTURE + 1000, member: member('failing') }]);
    expect(await redisGetChangeDigestJobAttempts(member('failing'))).toBe(0);
    expect(await redisCountChangeDigestJobAttempt(member('failing'))).toBe(1);
    expect(await redisCountChangeDigestJobAttempt(member('failing'))).toBe(2);
    expect(await redisGetChangeDigestJobAttempts(member('failing'))).toBe(2);
    await redisRescheduleChangeDigestJob(member('failing'), FUTURE + 6000);
    expect(await redisIsChangeDigestJobDue(member('failing'), FUTURE + 3000)).toBe(false);
    expect(await redisIsChangeDigestJobDue(member('failing'), FUTURE + 6000)).toBe(true);
    // XX: a job removed meanwhile is not scheduled again
    created.push(member('removed'));
    await redisRescheduleChangeDigestJob(member('removed'), FUTURE + 6000);
    expect(await scheduledOfRun(FUTURE + 10000)).toEqual([member('failing')]);
    await redisRemoveChangeDigestJob(member('failing'));
    expect(await getClientBase().hget('change_digest_job_attempts', member('failing'))).toBeNull();
    expect(await redisCountChangeDigestJobAttempt(member('failing'))).toBe(1);
    await redisRemoveChangeDigestJob(member('failing'));
  });

  it('lets only the owner of a digest delivery claim renew or release it', async () => {
    const receipt = member('delivery|notifier-email');
    const uiReceipt = member('delivery|notifier-ui');
    expect(await redisClaimDigestDelivery(receipt, 'owner-a')).toBe('claimed');
    // Being sent by owner-a
    expect(await redisClaimDigestDelivery(receipt, 'owner-b')).toBe('claimed_by_another_owner');
    expect(await redisRenewDigestDelivery(receipt, 'owner-a')).toBe(true);
    expect(await redisRenewDigestDelivery(receipt, 'owner-b')).toBe(false);
    expect(await redisReleaseDigestDelivery(receipt, 'owner-b')).toBe(false);
    // The notifier of owner-a failed: the digest can be sent again
    expect(await redisReleaseDigestDelivery(receipt, 'owner-a')).toBe(true);
    expect(await redisClaimDigestDelivery(receipt, 'owner-b')).toBe('claimed');
    // The notifier of owner-b succeeded: never sent again, and the receipt cannot be released any more
    expect(await redisAreDigestDeliveriesConfirmed([receipt])).toBe(false);
    expect(await redisConfirmDigestDelivery(receipt, 'owner-b')).toBe('confirmed');
    expect(await redisReleaseDigestDelivery(receipt, 'owner-b')).toBe(false);
    expect(await redisClaimDigestDelivery(receipt, 'owner-c')).toBe('delivered');
    expect(await redisAreDigestDeliveriesConfirmed([receipt])).toBe(true);
    // Every notifier of the digest has to confirm it
    expect(await redisClaimDigestDelivery(uiReceipt, 'owner-c')).toBe('claimed');
    expect(await redisAreDigestDeliveriesConfirmed([receipt, uiReceipt])).toBe(false);
    expect(await redisReleaseDigestDelivery(uiReceipt, 'owner-c')).toBe(true);
    expect(await redisAreDigestDeliveriesConfirmed([receipt, uiReceipt])).toBe(false);
    await getClientBase().zrem('{digest_deliveries}:receipts', receipt);
  });

  it('records a delivery whose claim was lost, and tells whether another owner took it', async () => {
    const lost = member('lost|notifier-email');
    const taken = member('taken|notifier-email');
    // The claim of owner-a disappeared and nobody claimed the digest since
    expect(await redisClaimDigestDelivery(lost, 'owner-a')).toBe('claimed');
    await getClientBase().zrem('{digest_deliveries}:receipts', lost);
    await getClientBase().hdel('{digest_deliveries}:owners', lost);
    expect(await redisConfirmDigestDelivery(lost, 'owner-a')).toBe('claim_lost');
    expect(await redisClaimDigestDelivery(lost, 'owner-b')).toBe('delivered');
    // The claim of owner-a lapsed and owner-b took it: recorded, and owner-b cannot renew it any more
    expect(await redisClaimDigestDelivery(taken, 'owner-a')).toBe('claimed');
    await getClientBase().zadd('{digest_deliveries}:receipts', Date.now() - 1000, taken);
    expect(await redisClaimDigestDelivery(taken, 'owner-b')).toBe('claimed');
    expect(await redisConfirmDigestDelivery(taken, 'owner-a')).toBe('claim_taken');
    expect(await redisRenewDigestDelivery(taken, 'owner-b')).toBe(false);
    expect(await redisConfirmDigestDelivery(taken, 'owner-b')).toBe('claim_taken');
    expect(await redisAreDigestDeliveriesConfirmed([lost, taken])).toBe(true);
    await getClientBase().zrem('{digest_deliveries}:receipts', lost, taken);
  });

  it('expires the jobs scheduled strictly before a date', async () => {
    await add([{ score: FUTURE + 1000, member: member('old') }, { score: FUTURE + 2000, member: member('kept') }]);
    expect(await redisExpireChangeDigestJobs(FUTURE + 2000)).toBeGreaterThanOrEqual(1);
    expect(await scheduledOfRun(FUTURE + 10000)).toEqual([member('kept')]);
  });
});
