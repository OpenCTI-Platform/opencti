import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import { createEntity, deleteElementById, deleteRelationsByFromAndTo, mergeEntities } from '../../../src/database/middleware';
import { elFlushSequencerWrites, elRefreshIndices, getDenormBuffer } from '../../../src/database/engine';
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

// task 0040 append buffer, engine side: a batch flush (elFlushSequencerWrites) keeps the "to" side appends of the
// buffered relationship types (external-reference by default) in Redis instead of writing them, writes them
// directly when the buffer refuses them (global cap) or fails (Redis), and a removal on a document with pending
// appends flushes them first. The batch is played as the loop plays it: the intents apply under the applying scope
// with a current write buffer, then the loop flushes that buffer.

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
    buffer = getDenormBuffer() as DenormBuffer;
    originalAdd = buffer.add;
  });
  afterAll(() => {
    SEQUENCER_CONFIG.denormBuffer = saved.denormBuffer;
    SEQUENCER_CONFIG.denormBufferRelations = saved.relations;
  });
  afterEach(async () => {
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

  it('should flush the pending append before removing the relation, so that no stale id is left', async () => {
    const reference = await newReference('REMOVED');
    const malware = await cite('REMOVED', reference.internal_id);
    await deleteRelationsByFromAndTo(testContext, ADMIN_USER, malware.internal_id, reference.internal_id, RELATION_EXTERNAL_REFERENCE, ABSTRACT_STIX_REF_RELATIONSHIP);
    // the periodic flush comes after the removal: nothing may be left for it to append
    await buffer.flush([reference.internal_id]);
    expect(await reverseIdsOf(reference.internal_id)).toEqual([]);
  });

  it('should flush the pending append before a merge renames the cited id, so that no deleted id is left', async () => {
    const reference = await newReference('MERGED');
    const source = await cite('MERGED', reference.internal_id);
    const target = await createEntity(testContext, ADMIN_USER, { name: 'DENORM_BUFFER_MALWARE_MERGE_TARGET' }, ENTITY_TYPE_MALWARE);
    created.push({ id: target.internal_id, type: ENTITY_TYPE_MALWARE });
    await mergeEntities(testContext, ADMIN_USER, target.internal_id, [source.internal_id]);
    await buffer.flush([reference.internal_id]);
    expect(await reverseIdsOf(reference.internal_id)).toEqual([target.internal_id]);
  });
});
