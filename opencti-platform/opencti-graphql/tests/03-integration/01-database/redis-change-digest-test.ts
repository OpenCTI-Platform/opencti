import { afterAll, describe, expect, it } from 'vitest';
import { v4 as uuid } from 'uuid';
import {
  redisAddChangeDigestJobs,
  redisAreDigestDeliveriesConfirmed,
  redisClaimDigestDelivery,
  redisConfirmDigestDelivery,
  redisCountChangeDigestJobAttempt,
  redisExpireChangeDigestJobs,
  redisGetChangeDigestJobAttempts,
  redisGetChangeDigestJobs,
  redisGetChangeDigestWatermarks,
  redisIsChangeDigestJobDue,
  redisReleaseDigestDelivery,
  redisRemoveChangeDigestJob,
  redisRenewDigestDelivery,
  redisRescheduleChangeDigestJob,
  redisSetChangeDigestWatermarks,
} from '../../../src/database/redis';

// Scored in 2100: the running notification manager never takes these jobs as due
const FAR_FUTURE = Date.UTC(2100, 0, 1);

describe('Redis change digest jobs', () => {
  const first = `test-digest-job-${uuid()}`;
  const second = `test-digest-job-${uuid()}`;
  const own = (members: string[]) => members.filter((member) => member === first || member === second);

  afterAll(async () => {
    await redisRemoveChangeDigestJob(first);
    await redisRemoveChangeDigestJob(second);
  });

  it('should keep the place of a job already waiting', async () => {
    await redisAddChangeDigestJobs([{ score: FAR_FUTURE, member: first }, { score: FAR_FUTURE + 10, member: second }]);
    await redisAddChangeDigestJobs([{ score: FAR_FUTURE + 5, member: first }]);
    expect(await redisIsChangeDigestJobDue(first, FAR_FUTURE)).toBe(true);
    expect(await redisIsChangeDigestJobDue(second, FAR_FUTURE + 5)).toBe(false);
    expect(await redisIsChangeDigestJobDue(`test-digest-job-${uuid()}`, FAR_FUTURE + 100)).toBe(false);
  });

  it('should list the due jobs, oldest first', async () => {
    expect(own(await redisGetChangeDigestJobs(FAR_FUTURE + 5, 100000))).toEqual([first]);
    expect(own(await redisGetChangeDigestJobs(FAR_FUTURE + 10, 100000))).toEqual([first, second]);
  });

  it('should count the attempts of a job', async () => {
    expect(await redisGetChangeDigestJobAttempts(second)).toBe(0);
    expect(await redisCountChangeDigestJobAttempt(second)).toBe(1);
    expect(await redisCountChangeDigestJobAttempt(second)).toBe(2);
    expect(await redisGetChangeDigestJobAttempts(second)).toBe(2);
  });

  it('should reschedule a job still scheduled, and never a removed one', async () => {
    await redisRescheduleChangeDigestJob(second, FAR_FUTURE + 20);
    expect(await redisIsChangeDigestJobDue(second, FAR_FUTURE + 10)).toBe(false);
    expect(await redisIsChangeDigestJobDue(second, FAR_FUTURE + 20)).toBe(true);
    const removed = `test-digest-job-${uuid()}`;
    await redisRescheduleChangeDigestJob(removed, FAR_FUTURE);
    expect(await redisIsChangeDigestJobDue(removed, FAR_FUTURE + 100)).toBe(false);
  });

  it('should remove a job with its attempts', async () => {
    await redisRemoveChangeDigestJob(second);
    expect(await redisIsChangeDigestJobDue(second, FAR_FUTURE + 100)).toBe(false);
    expect(await redisGetChangeDigestJobAttempts(second)).toBe(0);
  });

  it('should keep the jobs scored from the expiry date', async () => {
    expect(await redisExpireChangeDigestJobs(0)).toBe(0);
    expect(await redisIsChangeDigestJobDue(first, FAR_FUTURE)).toBe(true);
  });
});

describe('Redis digest deliveries', () => {
  const receipt = () => `test-digest-delivery-${uuid()}`;

  it('should give the claim to one owner until it is confirmed as delivered', async () => {
    const delivery = receipt();
    expect(await redisClaimDigestDelivery(delivery, 'owner-a')).toBe('claimed');
    expect(await redisClaimDigestDelivery(delivery, 'owner-b')).toBe('claimed_by_another_owner');
    expect(await redisRenewDigestDelivery(delivery, 'owner-b')).toBe(false);
    expect(await redisRenewDigestDelivery(delivery, 'owner-a')).toBe(true);
    expect(await redisAreDigestDeliveriesConfirmed([delivery])).toBe(false);
    expect(await redisConfirmDigestDelivery(delivery, 'owner-a')).toBe('confirmed');
    expect(await redisClaimDigestDelivery(delivery, 'owner-b')).toBe('delivered');
    expect(await redisAreDigestDeliveriesConfirmed([delivery])).toBe(true);
    expect(await redisAreDigestDeliveriesConfirmed([delivery, receipt()])).toBe(false);
  });

  it('should only let the owner release its claim', async () => {
    const delivery = receipt();
    expect(await redisClaimDigestDelivery(delivery, 'owner-a')).toBe('claimed');
    expect(await redisReleaseDigestDelivery(delivery, 'owner-b')).toBe(false);
    expect(await redisReleaseDigestDelivery(delivery, 'owner-a')).toBe(true);
    expect(await redisClaimDigestDelivery(delivery, 'owner-b')).toBe('claimed');
  });

  it('should tell a lost claim from a claim taken by another owner', async () => {
    expect(await redisConfirmDigestDelivery(receipt(), 'owner-a')).toBe('claim_lost');
    const taken = receipt();
    expect(await redisClaimDigestDelivery(taken, 'owner-b')).toBe('claimed');
    expect(await redisConfirmDigestDelivery(taken, 'owner-a')).toBe('claim_taken');
    expect(await redisClaimDigestDelivery(taken, 'owner-b')).toBe('delivered');
  });
});

describe('Redis change digest watermarks', () => {
  it('should return the watermarks of the given triggers and forget the others', async () => {
    const kept = `test-digest-trigger-${uuid()}`;
    const deleted = `test-digest-trigger-${uuid()}`;
    await redisSetChangeDigestWatermarks([[kept, '2026-01-05T09:00:00.000Z'], [deleted, '2026-01-06T09:00:00.000Z']]);
    await redisSetChangeDigestWatermarks([[kept, '2026-01-12T09:00:00.000Z']]);
    expect([...(await redisGetChangeDigestWatermarks([kept])).entries()]).toEqual([[kept, '2026-01-12T09:00:00.000Z']]);
    // Reading only the deleted trigger also forgets the kept one: nothing is left behind
    expect((await redisGetChangeDigestWatermarks([deleted])).size).toBe(0);
  });
});
