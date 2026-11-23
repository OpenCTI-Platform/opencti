import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import { createEntity, deleteElementById, deleteRelationsByFromAndTo, mergeEntities } from '../../../src/database/middleware';
import { elFlushSequencerWrites, elRefreshIndices, engine, initDenormBuffer } from '../../../src/database/engine';
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

// task 0040 append buffer, engine side, on a node whose intake manager initialized the buffer: a batch flush
// (elFlushSequencerWrites) keeps the "to" side appends of the buffered relationship types (external-reference by
// default) in Redis instead of writing them, lands them before the other side-writes, writes them directly when the
// buffer refuses them (global cap) or fails (Redis), and a removal on a document with pending appends, or with a
// write of them in progress, lands them first. The batch is played as the loop plays it: the intents apply under
// the applying scope with a current write buffer, then the loop flushes that buffer.

// The search engine client every module shares: a hook can hold or fail one bulk
type BulkHook = (request: Record<string, any>) => Promise<void>;
const hooks: { beforeBulk?: BulkHook } = {};
const client = engine as unknown as Record<string, (...args: any[]) => Promise<any>>;
const originalBulk = client.bulk;
const isUpdateOf = (request: Record<string, any>, docId: string) => (request.body ?? []).some((line: Record<string, any>) => line?.update?._id === docId);
const isSideBulk = (request: Record<string, any>) => (request.body ?? []).some((line: Record<string, any>) => line?.update);

const applyingContext = (): AuthContext => ({ ...testContext, sequencer: { scope: 'applying' } } as AuthContext);

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

describe('Sequencer append buffer, engine side (task 0040)', () => {
  const saved = { denormBuffer: SEQUENCER_CONFIG.denormBuffer, relations: SEQUENCER_CONFIG.denormBufferRelations };
  const created: { id: string; type: string }[] = [];
  let buffer: DenormBuffer;
  let originalAdd: DenormBuffer['add'];

  beforeAll(() => {
    SEQUENCER_CONFIG.denormBuffer = true;
    SEQUENCER_CONFIG.denormBufferRelations = [RELATION_EXTERNAL_REFERENCE];
    buffer = initDenormBuffer();
    originalAdd = buffer.add;
    client.bulk = async (request: Record<string, any>, ...rest: any[]) => {
      if (hooks.beforeBulk) await hooks.beforeBulk(request);
      return originalBulk.call(engine, request, ...rest);
    };
  });
  afterAll(() => {
    client.bulk = originalBulk;
    SEQUENCER_CONFIG.denormBuffer = saved.denormBuffer;
    SEQUENCER_CONFIG.denormBufferRelations = saved.relations;
  });
  afterEach(async () => {
    hooks.beforeBulk = undefined;
    buffer.add = originalAdd;
    setCurrentWriteBuffer(null);
    for (let i = created.length - 1; i >= 0; i -= 1) {
      await buffer.flushFirst([created[i].id]).catch(() => {});
      await deleteElementById(testContext, ADMIN_USER, created[i].id, created[i].type).catch(() => {});
    }
    created.length = 0;
  });

  const newReference = async (suffix: string) => {
    const reference = await createEntity(testContext, ADMIN_USER, { source_name: `DENORM_BUFFER_${suffix}`, url: `https://denorm.buffer/${suffix}` }, ENTITY_TYPE_EXTERNAL_REFERENCE);
    created.push({ id: reference.internal_id, type: ENTITY_TYPE_EXTERNAL_REFERENCE });
    return reference;
  };
  const cite = async (suffix: string, referenceId: string) => {
    const malware = await commitCitingMalware(`DENORM_BUFFER_MALWARE_${suffix}`, referenceId);
    created.push({ id: malware.internal_id, type: ENTITY_TYPE_MALWARE });
    return malware;
  };

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

  it('should flush the pending append before removing the relation, so that no stale id is left', async () => {
    const reference = await newReference('REMOVED');
    const malware = await cite('REMOVED', reference.internal_id);
    expect(await redisDenormBufferStore.pending([reference.internal_id]), 'the append is buffered').toEqual([reference.internal_id]);
    await deleteRelationsByFromAndTo(testContext, ADMIN_USER, malware.internal_id, reference.internal_id, RELATION_EXTERNAL_REFERENCE, ABSTRACT_STIX_REF_RELATIONSHIP);
    // the periodic flush comes after the removal: nothing may be left for it to append
    await buffer.flush([reference.internal_id]);
    expect(await reverseIdsOf(reference.internal_id)).toEqual([]);
  });

  it('should flush the pending append before a merge renames the cited id, so that no deleted id is left', async () => {
    const reference = await newReference('MERGED');
    const source = await cite('MERGED', reference.internal_id);
    expect(await redisDenormBufferStore.pending([reference.internal_id]), 'the append is buffered').toEqual([reference.internal_id]);
    const target = await createEntity(testContext, ADMIN_USER, { name: 'DENORM_BUFFER_MALWARE_MERGE_TARGET' }, ENTITY_TYPE_MALWARE);
    created.push({ id: target.internal_id, type: ENTITY_TYPE_MALWARE });
    await mergeEntities(testContext, ADMIN_USER, target.internal_id, [source.internal_id]);
    await buffer.flush([reference.internal_id]);
    expect(await reverseIdsOf(reference.internal_id)).toEqual([target.internal_id]);
  });

  it('should make a removal wait for a write of the append in progress, so that the append lands before it', async () => {
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
    // only the flush's own write is held: a removal that did not wait would land the appends itself and pass
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
    const removal = deleteRelationsByFromAndTo(testContext, ADMIN_USER, malware.internal_id, reference.internal_id, RELATION_EXTERNAL_REFERENCE, ABSTRACT_STIX_REF_RELATIONSHIP)
      .then(() => {
        removed = true;
      });
    await new Promise((resolve) => {
      setTimeout(resolve, 1000);
    });
    expect(removed, 'the removal waits for the write in progress').toBe(false);
    release();
    await Promise.all([flushing, removal]);
    hooks.beforeBulk = undefined;
    expect(await reverseIdsOf(reference.internal_id)).toEqual([]);
  });
});
