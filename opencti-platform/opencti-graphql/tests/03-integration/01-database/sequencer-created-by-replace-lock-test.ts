import { afterEach, describe, expect, it } from 'vitest';
import { createEntity, createRelation, deleteElementById, storeLoadByIdWithRefs } from '../../../src/database/middleware';
import { lockResources } from '../../../src/lock/master-lock';
import { ADMIN_USER, testContext } from '../../utils/testQuery';
import { ENTITY_TYPE_MALWARE } from '../../../src/schema/stixDomainObject';
import { ENTITY_TYPE_IDENTITY_ORGANIZATION } from '../../../src/modules/organization/organization-types';
import { RELATION_CREATED_BY } from '../../../src/schema/stixRefRelationship';
import { setCurrentBatchLock } from '../../../src/database/sequencer/sequencer-batch-lock';
import { isLockError } from '../../../src/database/sequencer/sequencer-multi-writer';
import { newEndpointShares, releaseEndpointShares } from '../../../src/database/sequencer/sequencer-endpoint-shares';
import type { AuthContext } from '../../../src/types/user';

// task 0040 multi_writer: a created-by already set to another author is replaced through a lock site of its own
// (replaceSingleRelationRef). Without the batch lock arguments it waited for the source's Redis lock (the full
// retry budget, then LOCK_ERROR) even when the applying batch was the holder: shared entities every source re-sends
// with its own author stalled the loop ~26 s per batch on mix600k (2026-11-19).
// The batch is played by a Redis lock on the source plus a current batch lock, as the sequencer loop holds them.

const applyingContext = (): AuthContext => ({ ...testContext, sequencer: { scope: 'applying' } } as AuthContext);

// A lock refused at once answers well under the retry budget (100 x 250 ms)
const FAST_MS = 10000;

const replaceUnderBatch = async (heldKeys: string[], input: Record<string, any>) => {
  const shares = newEndpointShares();
  setCurrentBatchLock({ heldKeys: new Set(heldKeys), signal: new AbortController().signal, noWait: true, shares });
  const start = Date.now();
  try {
    const result = await createRelation(applyingContext(), ADMIN_USER, input).then((relation) => ({ relation }), (error) => ({ error }));
    return { ...result, elapsed: Date.now() - start };
  } finally {
    setCurrentBatchLock(null);
    await releaseEndpointShares(shares);
  }
};

describe('Sequencer: created-by replacement under the batch lock (task 0040)', () => {
  const created: { id: string; type: string }[] = [];

  afterEach(async () => {
    setCurrentBatchLock(null);
    for (let i = created.length - 1; i >= 0; i -= 1) {
      await deleteElementById(testContext, ADMIN_USER, created[i].id, created[i].type).catch(() => {});
    }
    created.length = 0;
  });

  const setup = async (suffix: string) => {
    const first = await createEntity(testContext, ADMIN_USER, { name: `CB_LOCK_FIRST_${suffix}` }, ENTITY_TYPE_IDENTITY_ORGANIZATION);
    const second = await createEntity(testContext, ADMIN_USER, { name: `CB_LOCK_SECOND_${suffix}` }, ENTITY_TYPE_IDENTITY_ORGANIZATION);
    const malware = await createEntity(testContext, ADMIN_USER, { name: `CB_LOCK_MALWARE_${suffix}`, createdBy: first.internal_id }, ENTITY_TYPE_MALWARE);
    created.push({ id: first.internal_id, type: ENTITY_TYPE_IDENTITY_ORGANIZATION });
    created.push({ id: second.internal_id, type: ENTITY_TYPE_IDENTITY_ORGANIZATION });
    created.push({ id: malware.internal_id, type: ENTITY_TYPE_MALWARE });
    const input = { relationship_type: RELATION_CREATED_BY, fromId: malware.internal_id, toId: second.internal_id };
    return { first, second, malware, input };
  };

  it('should replace the author at once when the batch holds the source', async () => {
    const { second, malware, input } = await setup('HELD');
    // the batch locked the source in Redis and holds its key
    const batchLock = await lockResources([malware.internal_id]);
    try {
      const { error, elapsed } = await replaceUnderBatch([malware.internal_id], input) as { error?: unknown; elapsed: number };
      expect(error, 'the replacement is applied').toBeUndefined();
      expect(elapsed, 'no wait for its own batch lock').toBeLessThan(FAST_MS);
    } finally {
      await batchLock.unlock();
    }
    const reloaded = await storeLoadByIdWithRefs(testContext, ADMIN_USER, malware.internal_id) as Record<string, any>;
    expect(reloaded.createdBy?.internal_id).toBe(second.internal_id);
  });

  it('should refuse at once when another platform holds the source, so that the loop replans it', async () => {
    const { first, malware, input } = await setup('OTHER');
    // another platform's batch locked the source; this batch does not hold it
    const otherLock = await lockResources([malware.internal_id]);
    try {
      const { error, elapsed } = await replaceUnderBatch([], input) as { error?: unknown; elapsed: number };
      expect(isLockError(error), 'refused with LOCK_ERROR').toBe(true);
      expect(elapsed, 'refused without waiting the retry budget').toBeLessThan(FAST_MS);
    } finally {
      await otherLock.unlock();
    }
    const reloaded = await storeLoadByIdWithRefs(testContext, ADMIN_USER, malware.internal_id) as Record<string, any>;
    expect(reloaded.createdBy?.internal_id).toBe(first.internal_id);
  });
});
