import { afterEach, describe, expect, it } from 'vitest';
import { v4 as uuid } from 'uuid';
import {
  getClientBase,
  redisAddChangeDigestJobs,
  redisCountChangeDigestJobFailure,
  redisExpireChangeDigestJobs,
  redisGetChangeDigestJobs,
  redisClaimDigestDelivery,
  redisConfirmDigestDelivery,
  redisIsChangeDigestJobDue,
  redisReleaseDigestDelivery,
  redisRemoveChangeDigestJob,
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

  it('reschedules only a job still scheduled and forgets its failed attempts with it', async () => {
    await add([{ score: FUTURE + 1000, member: member('failing') }]);
    expect(await redisCountChangeDigestJobFailure(member('failing'))).toBe(1);
    expect(await redisCountChangeDigestJobFailure(member('failing'))).toBe(2);
    await redisRescheduleChangeDigestJob(member('failing'), FUTURE + 6000);
    expect(await redisIsChangeDigestJobDue(member('failing'), FUTURE + 3000)).toBe(false);
    expect(await redisIsChangeDigestJobDue(member('failing'), FUTURE + 6000)).toBe(true);
    // XX: a job removed meanwhile is not scheduled again
    created.push(member('removed'));
    await redisRescheduleChangeDigestJob(member('removed'), FUTURE + 6000);
    expect(await scheduledOfRun(FUTURE + 10000)).toEqual([member('failing')]);
    await redisRemoveChangeDigestJob(member('failing'));
    expect(await getClientBase().hget('change_digest_job_attempts', member('failing'))).toBeNull();
    expect(await redisCountChangeDigestJobFailure(member('failing'))).toBe(1);
    await redisRemoveChangeDigestJob(member('failing'));
  });

  it('claims a digest delivery once, releases it after a failure and keeps it after a success', async () => {
    const receipt = member('delivery|notifier-email');
    expect(await redisClaimDigestDelivery(receipt)).toBe(true);
    // Being sent
    expect(await redisClaimDigestDelivery(receipt)).toBe(false);
    // The notifier failed: the digest can be sent again
    await redisReleaseDigestDelivery(receipt);
    expect(await redisClaimDigestDelivery(receipt)).toBe(true);
    // The notifier succeeded: never sent again
    await redisConfirmDigestDelivery(receipt);
    expect(await redisClaimDigestDelivery(receipt)).toBe(false);
    expect(await redisClaimDigestDelivery(member('delivery|notifier-ui'))).toBe(true);
    await redisReleaseDigestDelivery(receipt);
    await redisReleaseDigestDelivery(member('delivery|notifier-ui'));
  });

  it('expires the jobs scheduled strictly before a date', async () => {
    await add([{ score: FUTURE + 1000, member: member('old') }, { score: FUTURE + 2000, member: member('kept') }]);
    expect(await redisExpireChangeDigestJobs(FUTURE + 2000)).toBeGreaterThanOrEqual(1);
    expect(await scheduledOfRun(FUTURE + 10000)).toEqual([member('kept')]);
  });
});
