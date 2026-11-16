import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import { createEntity, createRelation, deleteElementById, mergeEntities } from '../../../src/database/middleware';
import { fullRelationsList, internalFindByIds } from '../../../src/database/middleware-loader';
import { elRefreshIndices, engine } from '../../../src/database/engine';
import { ES_INDEX_PREFIX } from '../../../src/database/utils';
import { ADMIN_USER, testContext } from '../../utils/testQuery';
import { ENTITY_TYPE_ATTACK_PATTERN, ENTITY_TYPE_MALWARE } from '../../../src/schema/stixDomainObject';
import { RELATION_USES } from '../../../src/schema/stixCoreRelationship';
import { setCurrentBatchLock } from '../../../src/database/sequencer/sequencer-batch-lock';
import { SEQUENCER_CONFIG } from '../../../src/database/sequencer/sequencer-config';
import { isLockError } from '../../../src/database/sequencer/sequencer-multi-writer';
import { newEndpointShares, releaseEndpointShares } from '../../../src/database/sequencer/sequencer-endpoint-shares';
import type { AuthContext } from '../../../src/types/user';

// task 0040 defect 1: with several platforms writing (multi_writer), a relation whose endpoint another platform
// merges away can be written after the merge read the source's dependencies: the merge moves what it read and
// deletes the source, the relation is lost with it or left on the deleted source (0-6 dangling per mix285k run,
// always the Software `Windows` merge). The other platform is played by a relation applied under a batch lock
// that holds its endpoints, as the sequencer loop does (computeBatchLockKeys); this platform by a plain merge.
// The interleaving is driven at the search engine client, the one object every module shares: the merge's
// reads and writes are told apart by their index and the ids they carry.

type Hook = (request: Record<string, any>, serialized: string) => Promise<void>;
const hooks: { beforeSearch?: Hook; beforeBulk?: Hook; afterBulk?: Hook } = {};
const client = engine as unknown as Record<string, (...args: any[]) => Promise<any>>;
const originals = { search: client.search, bulk: client.bulk };

const isRelationshipSearch = (request: Record<string, any>) => String(request.index).includes('stix_core_relationships')
  && !String(request.index).includes('stix_domain_objects');
const isDeleteOf = (request: Record<string, any>, id: string) => (request.body ?? [])
  .some((line: Record<string, any>) => line?.delete?._id === id);
const isRelationIndexFrom = (request: Record<string, any>, fromId: string) => (request.body ?? [])
  .some((line: Record<string, any>) => line?.entity_type === RELATION_USES && JSON.stringify(line.connections ?? []).includes(fromId));
const timeout = (ms: number) => new Promise<void>((resolve) => {
  setTimeout(resolve, ms);
});

const applyingContext = (): AuthContext => ({ ...testContext, sequencer: { scope: 'applying' } } as AuthContext);

// The relation as another platform applies it: under its batch lock, the endpoints in the held keys and not
// locked in Redis (multi_writer narrowed set), any other key tried once, its shares released at the batch end
const applyAsOtherPlatform = async (heldKeys: string[], input: Record<string, any>) => {
  const shares = newEndpointShares();
  setCurrentBatchLock({ heldKeys: new Set(heldKeys), signal: new AbortController().signal, noWait: true, shares });
  try {
    return await createRelation(applyingContext(), ADMIN_USER, input);
  } finally {
    setCurrentBatchLock(null);
    await releaseEndpointShares(shares);
  }
};

// A refused relation starts a new cycle in the loop: replayed once the merge is over, from its input ids
const applyOrReplan = async (heldKeys: string[], input: Record<string, any>, mergeDone: () => Promise<unknown>) => {
  try {
    return await applyAsOtherPlatform(heldKeys, input);
  } catch (err) {
    if (!isLockError(err)) throw err;
    await mergeDone();
    return applyAsOtherPlatform([], input);
  }
};

describe('Sequencer multi_writer: relation concurrent with a merge of its endpoint (task 0040 defect 1)', () => {
  const savedMultiWriter = SEQUENCER_CONFIG.multiWriter;
  const created: { id: string; type: string }[] = [];

  beforeAll(() => {
    SEQUENCER_CONFIG.multiWriter = true;
    client.search = async (request: Record<string, any>, ...rest: any[]) => {
      if (hooks.beforeSearch) await hooks.beforeSearch(request, JSON.stringify(request));
      return originals.search.call(engine, request, ...rest);
    };
    client.bulk = async (request: Record<string, any>, ...rest: any[]) => {
      if (hooks.beforeBulk) await hooks.beforeBulk(request, '');
      const result = await originals.bulk.call(engine, request, ...rest);
      if (hooks.afterBulk) await hooks.afterBulk(request, '');
      return result;
    };
  });
  afterAll(() => {
    client.search = originals.search;
    client.bulk = originals.bulk;
    SEQUENCER_CONFIG.multiWriter = savedMultiWriter;
  });
  afterEach(async () => {
    hooks.beforeSearch = undefined;
    hooks.beforeBulk = undefined;
    hooks.afterBulk = undefined;
    setCurrentBatchLock(null);
    for (let i = created.length - 1; i >= 0; i -= 1) {
      await deleteElementById(testContext, ADMIN_USER, created[i].id, created[i].type).catch(() => {});
    }
    created.length = 0;
  });

  const setup = async (suffix: string) => {
    const target = await createEntity(testContext, ADMIN_USER, { name: `DEFECT1_TARGET_${suffix}` }, ENTITY_TYPE_MALWARE);
    const source = await createEntity(testContext, ADMIN_USER, { name: `DEFECT1_SOURCE_${suffix}` }, ENTITY_TYPE_MALWARE);
    const attackPattern = await createEntity(testContext, ADMIN_USER, { name: `DEFECT1_AP_${suffix}` }, ENTITY_TYPE_ATTACK_PATTERN);
    created.push({ id: attackPattern.internal_id, type: ENTITY_TYPE_ATTACK_PATTERN });
    created.push({ id: source.internal_id, type: ENTITY_TYPE_MALWARE });
    created.push({ id: target.internal_id, type: ENTITY_TYPE_MALWARE });
    // the bundle refers to the source by its standard id, the batch holds it with the internal ids it resolved to
    const input = { relationship_type: RELATION_USES, fromId: source.standard_id, toId: attackPattern.standard_id };
    const heldKeys = [source.standard_id, source.internal_id, attackPattern.standard_id, attackPattern.internal_id];
    return { target, source, attackPattern, input, heldKeys };
  };

  // The asserted relation exists exactly once, from the merge target: not lost with the source, not left on it
  const expectRelationOnTarget = async (attackPatternId: string, targetId: string) => {
    await elRefreshIndices([`${ES_INDEX_PREFIX}*`]);
    const relations = await fullRelationsList(testContext, ADMIN_USER, RELATION_USES, { toId: attackPatternId, baseData: true });
    relations.forEach((relation) => created.push({ id: relation.internal_id, type: RELATION_USES }));
    const fromIds = relations.map((relation) => relation.fromId);
    const existing = await internalFindByIds(testContext, ADMIN_USER, fromIds, { baseData: true }) as { internal_id: string }[];
    const existingIds = new Set(existing.map((element) => element.internal_id));
    expect(fromIds.filter((id) => !existingIds.has(id)), 'relations from a deleted entity').toEqual([]);
    expect(fromIds, 'the relation, once, from the merge target').toEqual([targetId]);
  };

  it('should keep a relation written between the merge dependency read and the source deletion', async () => {
    const { target, source, attackPattern, input, heldKeys } = await setup('WINDOW');
    // the other platform writes when the merge reads the target's dependencies: the source's are read already
    let merged: Promise<unknown> = Promise.resolve();
    let relation: Promise<unknown> | undefined;
    hooks.beforeSearch = async (request, serialized) => {
      if (relation || !isRelationshipSearch(request) || !serialized.includes(target.internal_id)) return;
      relation = applyOrReplan(heldKeys, input, () => merged);
      // the fix may refuse the relation (replayed after the merge) or make it wait: never block the merge on it
      await Promise.race([relation, timeout(3000)]);
    };
    merged = mergeEntities(testContext, ADMIN_USER, target.internal_id, [source.internal_id]);
    await merged;
    hooks.beforeSearch = undefined;
    expect(relation, 'the merge read the target dependencies').toBeDefined();
    await relation;
    await expectRelationOnTarget(attackPattern.internal_id, target.internal_id);
  });

  it('should not leave a relation resolved before the merge and written after the source deletion on the deleted source', async () => {
    const { target, source, attackPattern, input, heldKeys } = await setup('LATE_WRITE');
    // the other platform resolved the source before the merge started; its write waits for the source deletion
    // (or 3 s, if the merge waits for the relation)
    let releaseWrite: () => void = () => {};
    const writeReleased = new Promise<void>((resolve) => {
      releaseWrite = resolve;
    });
    let reachWrite: () => void = () => {};
    const writeReached = new Promise<void>((resolve) => {
      reachWrite = resolve;
    });
    let deleted = false;
    hooks.beforeBulk = async (request) => {
      if (!isRelationIndexFrom(request, source.internal_id)) return;
      reachWrite();
      await Promise.race([writeReleased, timeout(3000)]);
    };
    hooks.afterBulk = async (request) => {
      if (!isDeleteOf(request, source.internal_id)) return;
      deleted = true;
      releaseWrite();
    };
    let merged: Promise<unknown> = Promise.resolve();
    const relation = applyOrReplan(heldKeys, input, () => merged);
    await Promise.race([writeReached, relation]);
    merged = mergeEntities(testContext, ADMIN_USER, target.internal_id, [source.internal_id]);
    await merged;
    hooks.beforeBulk = undefined;
    hooks.afterBulk = undefined;
    expect(deleted, 'the merge deleted the source').toBe(true);
    await relation;
    await expectRelationOnTarget(attackPattern.internal_id, target.internal_id);
  });
});
