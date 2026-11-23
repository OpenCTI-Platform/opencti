import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import { createEntity, deleteElementById, deleteRelationsByFromAndTo, mergeEntities } from '../../../src/database/middleware';
import { elFlushSequencerWrites, elRefreshIndices, engine, initDenormBuffer, resetDenormBuffer } from '../../../src/database/engine';
import { redisDenormBufferStore } from '../../../src/database/redis';
import { ES_INDEX_PREFIX } from '../../../src/database/utils';
import { ADMIN_USER, testContext } from '../../utils/testQuery';
import { ENTITY_TYPE_MALWARE } from '../../../src/schema/stixDomainObject';
import { ENTITY_TYPE_EXTERNAL_REFERENCE } from '../../../src/schema/stixMetaObject';
import { RELATION_EXTERNAL_REFERENCE } from '../../../src/schema/stixRefRelationship';
import { ABSTRACT_STIX_REF_RELATIONSHIP } from '../../../src/schema/general';
import { SequencerWriteBuffer, setCurrentWriteBuffer } from '../../../src/database/sequencer/sequencer-write-buffer';
import { SEQUENCER_CONFIG } from '../../../src/database/sequencer/sequencer-config';
import { internalLoadById } from '../../../src/database/middleware-loader';
import type { DenormBuffer } from '../../../src/database/sequencer/denorm-buffer';
import type { AuthContext } from '../../../src/types/user';

// task 0040 append buffer, engine side. On a node whose intake manager started the buffer, a batch flush
// (elFlushSequencerWrites) keeps the "to" side appends of the buffered relationship types (external-reference by
// default) in Redis instead of writing them, lands them before the other side-writes, writes them directly when the
// buffer refuses them (global cap), fails (Redis), is stopped or turned off; a removal or a merge edits the buffered
// appends without waiting, and an id a write in progress lands after its removal is erased by that writer. On a
// node without the buffer, appends are written directly and nothing touches Redis. The batch is played as the loop
// plays it: the intents apply under the applying scope with a current write buffer, then the loop flushes it.

// The search engine client every module shares: a hook can hold or fail one bulk
type BulkHook = (request: Record<string, any>) => Promise<void>;
const hooks: { beforeBulk?: BulkHook } = {};
const client = engine as unknown as Record<string, (...args: any[]) => Promise<any>>;
const originalBulk = client.bulk;
const isUpdateOf = (request: Record<string, any>, docId: string) => (request.body ?? []).some((line: Record<string, any>) => line?.update?._id === docId);
const isSideBulk = (request: Record<string, any>) => (request.body ?? []).some((line: Record<string, any>) => line?.update);

const applyingContext = (): AuthContext => ({ ...testContext, sequencer: { scope: 'applying' } } as AuthContext);
const wait = (ms: number) => new Promise((resolve) => {
  setTimeout(resolve, ms);
});

const reverseIdsOf = async (referenceId: string): Promise<string[]> => {
  await elRefreshIndices([`${ES_INDEX_PREFIX}*`]);
  const reference = await internalLoadById(testContext, ADMIN_USER, referenceId) as Record<string, any>;
  const ids = reference[`rel_${RELATION_EXTERNAL_REFERENCE}.internal_id`] ?? reference[`rel_${RELATION_EXTERNAL_REFERENCE}`]?.internal_id ?? [];
  return Array.isArray(ids) ? ids : [ids];
};

// One batch: the malware citing the reference is created by an intent, then the batch is flushed
const commitCitingMalware = async (name: string, referenceId: string) => {
  const writes = new SequencerWriteBuffer();
  setCurrentWriteBuffer(writes);
  let malware;
  try {
    malware = await createEntity(applyingContext(), ADMIN_USER, { name, externalReferences: [referenceId] }, ENTITY_TYPE_MALWARE);
  } finally {
    setCurrentWriteBuffer(null);
  }
  await elFlushSequencerWrites(testContext, ADMIN_USER, writes);
  return malware;
};

const removeCitation = (malwareId: string, referenceId: string) => deleteRelationsByFromAndTo(
  testContext,
  ADMIN_USER,
  malwareId,
  referenceId,
  RELATION_EXTERNAL_REFERENCE,
  ABSTRACT_STIX_REF_RELATIONSHIP,
);

const fixtures = (prefix: string) => {
  const created: { id: string; type: string }[] = [];
  const newReference = async (suffix: string) => {
    const reference = await createEntity(testContext, ADMIN_USER, { source_name: `${prefix}_${suffix}`, url: `https://denorm.buffer/${prefix}/${suffix}` }, ENTITY_TYPE_EXTERNAL_REFERENCE);
    created.push({ id: reference.internal_id, type: ENTITY_TYPE_EXTERNAL_REFERENCE });
    return reference;
  };
  const cite = async (suffix: string, referenceId: string) => {
    const malware = await commitCitingMalware(`${prefix}_MALWARE_${suffix}`, referenceId);
    created.push({ id: malware.internal_id, type: ENTITY_TYPE_MALWARE });
    return malware;
  };
  const cleanup = async (buffer?: DenormBuffer) => {
    for (let i = created.length - 1; i >= 0; i -= 1) {
      // what is still buffered for the document lands before it is deleted (an update of a deleted document fails)
      if (buffer) await buffer.flush([created[i].id]).catch(() => false);
      await deleteElementById(testContext, ADMIN_USER, created[i].id, created[i].type).catch(() => {});
    }
    created.length = 0;
  };
  return { created, newReference, cite, cleanup };
};

describe('Sequencer append buffer, node without the intake manager (task 0040)', () => {
  const { newReference, cite, cleanup } = fixtures('DENORM_NO_BUFFER');
  afterEach(async () => cleanup());

  it('should write the append at the batch commit and keep it out of Redis', async () => {
    const reference = await newReference('DIRECT');
    const malware = await cite('DIRECT', reference.internal_id);
    expect(await reverseIdsOf(reference.internal_id)).toEqual([malware.internal_id]);
    expect(await redisDenormBufferStore.pending([reference.internal_id])).toEqual([]);
    await removeCitation(malware.internal_id, reference.internal_id);
    expect(await reverseIdsOf(reference.internal_id)).toEqual([]);
  });
});

describe('Sequencer append buffer, engine side (task 0040)', () => {
  const saved = {
    denormBuffer: SEQUENCER_CONFIG.denormBuffer,
    relations: SEQUENCER_CONFIG.denormBufferRelations,
    periodMs: SEQUENCER_CONFIG.denormFlushPeriodMs,
  };
  const { created, newReference, cite, cleanup } = fixtures('DENORM_BUFFER');
  let buffer: DenormBuffer;
  let originalAdd: DenormBuffer['add'];
  let originalEdit: DenormBuffer['edit'];

  beforeAll(() => {
    SEQUENCER_CONFIG.denormBuffer = true;
    SEQUENCER_CONFIG.denormBufferRelations = [RELATION_EXTERNAL_REFERENCE];
    // the tests flush themselves: no periodic tick during a test
    SEQUENCER_CONFIG.denormFlushPeriodMs = 3600000;
    buffer = initDenormBuffer();
    buffer.start();
    originalAdd = buffer.add;
    originalEdit = buffer.edit;
    client.bulk = async (request: Record<string, any>, ...rest: any[]) => {
      if (hooks.beforeBulk) await hooks.beforeBulk(request);
      return originalBulk.call(engine, request, ...rest);
    };
  });
  afterAll(async () => {
    client.bulk = originalBulk;
    await resetDenormBuffer();
    SEQUENCER_CONFIG.denormBuffer = saved.denormBuffer;
    SEQUENCER_CONFIG.denormBufferRelations = saved.relations;
    SEQUENCER_CONFIG.denormFlushPeriodMs = saved.periodMs;
  });
  afterEach(async () => {
    hooks.beforeBulk = undefined;
    buffer.add = originalAdd;
    buffer.edit = originalEdit;
    SEQUENCER_CONFIG.denormBuffer = true;
    setCurrentWriteBuffer(null);
    buffer.start();
    await cleanup(buffer);
  });

  it('should keep the reference append out of the batch commit and write it once at the flush', async () => {
    const reference = await newReference('BUFFERED');
    const malware = await cite('BUFFERED', reference.internal_id);
    expect(await reverseIdsOf(reference.internal_id), 'not written at the batch commit').not.toContain(malware.internal_id);
    await buffer.flush([reference.internal_id]);
    expect(await reverseIdsOf(reference.internal_id), 'written once at the flush').toEqual([malware.internal_id]);
  });

  it('should write the append at the batch commit when the buffer refuses it (global cap)', async () => {
    const reference = await newReference('REFUSED');
    buffer.add = async () => false;
    const malware = await cite('REFUSED', reference.internal_id);
    expect(await reverseIdsOf(reference.internal_id)).toEqual([malware.internal_id]);
  });

  it('should write the append at the batch commit when the buffer fails (Redis down)', async () => {
    const reference = await newReference('FAILED');
    buffer.add = async () => {
      throw new Error('redis down');
    };
    const malware = await cite('FAILED', reference.internal_id);
    expect(await reverseIdsOf(reference.internal_id)).toEqual([malware.internal_id]);
  });

  it('should write the append at the batch commit when the buffer knob is off', async () => {
    const reference = await newReference('KNOB_OFF');
    SEQUENCER_CONFIG.denormBuffer = false;
    const malware = await cite('KNOB_OFF', reference.internal_id);
    expect(await reverseIdsOf(reference.internal_id)).toEqual([malware.internal_id]);
    expect(await redisDenormBufferStore.pending([reference.internal_id])).toEqual([]);
  });

  it('should write the append at the batch commit once the buffer is stopped (intake manager shutting down)', async () => {
    const reference = await newReference('STOPPED');
    await buffer.stop();
    const malware = await cite('STOPPED', reference.internal_id);
    expect(await reverseIdsOf(reference.internal_id)).toEqual([malware.internal_id]);
    expect(await redisDenormBufferStore.pending([reference.internal_id])).toEqual([]);
  });

  it('should land the append before the other side-writes, so that their failure does not lose it', async () => {
    const reference = await newReference('SIDE_FAILED');
    // the side bulk of the batch (the citing object's own array) fails once the relationship documents are indexed
    hooks.beforeBulk = async (request) => {
      if (isSideBulk(request)) throw new Error('side bulk failed');
    };
    const writes = new SequencerWriteBuffer();
    setCurrentWriteBuffer(writes);
    let malware;
    try {
      malware = await createEntity(applyingContext(), ADMIN_USER, { name: 'DENORM_BUFFER_MALWARE_SIDE_FAILED', externalReferences: [reference.internal_id] }, ENTITY_TYPE_MALWARE);
    } finally {
      setCurrentWriteBuffer(null);
    }
    created.push({ id: malware.internal_id, type: ENTITY_TYPE_MALWARE });
    await expect(elFlushSequencerWrites(testContext, ADMIN_USER, writes)).rejects.toThrow();
    hooks.beforeBulk = undefined;
    // the retry of the batch finds the relationship existing and appends nothing: the buffer holds it
    expect(await redisDenormBufferStore.pending([reference.internal_id])).toEqual([reference.internal_id]);
    await buffer.flush([reference.internal_id]);
    expect(await reverseIdsOf(reference.internal_id)).toEqual([malware.internal_id]);
  });

  it('should drop the pending append at the removal of the relation, so that the flush does not bring the id back', async () => {
    const reference = await newReference('REMOVED');
    const malware = await cite('REMOVED', reference.internal_id);
    expect(await redisDenormBufferStore.pending([reference.internal_id]), 'the append is buffered').toEqual([reference.internal_id]);
    await removeCitation(malware.internal_id, reference.internal_id);
    // the periodic flush comes after the removal: nothing may be left for it to append
    await buffer.flush([reference.internal_id]);
    expect(await reverseIdsOf(reference.internal_id)).toEqual([]);
  });

  it('should rename the pending append when a merge replaces the cited object, so that no deleted id is left', async () => {
    const reference = await newReference('MERGED');
    const source = await cite('MERGED', reference.internal_id);
    expect(await redisDenormBufferStore.pending([reference.internal_id]), 'the append is buffered').toEqual([reference.internal_id]);
    const target = await createEntity(testContext, ADMIN_USER, { name: 'DENORM_BUFFER_MALWARE_MERGE_TARGET' }, ENTITY_TYPE_MALWARE);
    created.push({ id: target.internal_id, type: ENTITY_TYPE_MALWARE });
    await mergeEntities(testContext, ADMIN_USER, target.internal_id, [source.internal_id]);
    await buffer.flush([reference.internal_id]);
    expect(await reverseIdsOf(reference.internal_id)).toEqual([target.internal_id]);
  });

  it('should not make a removal wait for a write in progress, and erase the id that write lands after it', async () => {
    const reference = await newReference('IN_FLIGHT');
    const malware = await cite('IN_FLIGHT', reference.internal_id);
    // the flush of the reference is held in its ES write, its document locked
    let release: () => void = () => {};
    const released = new Promise<void>((resolve) => {
      release = resolve;
    });
    let reachWrite: () => void = () => {};
    const writeReached = new Promise<void>((resolve) => {
      reachWrite = resolve;
    });
    let held = false;
    hooks.beforeBulk = async (request) => {
      if (held || !isUpdateOf(request, reference.internal_id)) return;
      held = true;
      reachWrite();
      await released;
    };
    const flushing = buffer.flush([reference.internal_id]);
    await writeReached;
    let removed = false;
    const removal = removeCitation(malware.internal_id, reference.internal_id).then(() => {
      removed = true;
    });
    await Promise.race([removal, wait(10000)]);
    expect(removed, 'the removal does not wait for the write in progress').toBe(true);
    release();
    await flushing;
    hooks.beforeBulk = undefined;
    expect(await reverseIdsOf(reference.internal_id), 'the removed id the write landed is erased').toEqual([]);
  });

  it('should go on with the removal when the buffer edit fails (Redis down)', async () => {
    const reference = await newReference('EDIT_FAILED');
    const malware = await cite('EDIT_FAILED', reference.internal_id);
    buffer.edit = async () => {
      throw new Error('redis down');
    };
    await removeCitation(malware.internal_id, reference.internal_id);
    buffer.edit = originalEdit;
    // accepted gap (PR note): the removed id comes back with the flush
    await buffer.flush([reference.internal_id]);
    expect(await reverseIdsOf(reference.internal_id)).toEqual([malware.internal_id]);
  });
});
