import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { SequencerIdentityMap } from '../../../src/database/sequencer/sequencer-identity-map';
import { SEQUENCER_CONFIG } from '../../../src/database/sequencer/sequencer-config';
import { sequencerMetrics } from '../../../src/database/sequencer/sequencer-metrics';

// Oracle for the MRU shortcut of the identity map lookup: the same map with the lookup as of
// b48f3c0250 (delete + set on every hit) put back, driven by the same random operations, must
// keep the same LRU order (byInternalId key order) and answer the same after every operation.

// ---- reference: lookup before the rewrite, verbatim ----
function oldLookup(this: any, id: string) {
  if (SEQUENCER_CONFIG.writtenIndex) {
    const writtenInternalId = this.writtenIndex.get(id);
    const writtenEntry = writtenInternalId ? this.written.get(writtenInternalId) : undefined;
    if (writtenEntry) {
      sequencerMetrics.mapEvent('written_hit');
      return writtenEntry;
    }
  }
  const internalId = this.idIndex.get(id);
  if (!internalId) return undefined;
  const entry = this.byInternalId.get(internalId);
  if (!entry) return undefined;
  if (entry.expiresAt < Date.now()) {
    this.removeEntry(internalId);
    sequencerMetrics.mapEvent('evict');
    return undefined;
  }
  // LRU touch
  this.byInternalId.delete(internalId);
  this.byInternalId.set(internalId, entry);
  return entry;
}

const lcg = (seed: number) => {
  let s = seed;
  return () => {
    s = (s * 1103515245 + 12345) & 0x7fffffff;
    return s / 0x7fffffff;
  };
};

const element = (k: number) => ({
  internal_id: `int${k}`,
  standard_id: `malware--s${k}`,
  x_opencti_stix_ids: [`malware--x${k}`],
  entity_type: 'Malware',
  parent_types: ['Stix-Domain-Object', 'Stix-Core-Object'],
});

const saved = { size: SEQUENCER_CONFIG.identityMapSize, ttl: SEQUENCER_CONFIG.identityMapTtlS, written: SEQUENCER_CONFIG.writtenIndex };

describe('sequencer identity map LRU oracle (MRU shortcut)', () => {
  beforeAll(() => {
    SEQUENCER_CONFIG.identityMapTtlS = 10;
  });
  afterAll(() => {
    SEQUENCER_CONFIG.identityMapSize = saved.size;
    SEQUENCER_CONFIG.identityMapTtlS = saved.ttl;
    SEQUENCER_CONFIG.writtenIndex = saved.written;
    vi.restoreAllMocks();
  });

  it('keeps the LRU order of the former lookup under random lookups, stores, evictions, expiries and clears', () => {
    let now = 1_000_000;
    vi.spyOn(Date, 'now').mockImplementation(() => now);
    let lookups = 0;
    let evictions = 0;
    for (let seed = 1; seed <= 300; seed += 1) {
      const rnd = lcg(seed);
      SEQUENCER_CONFIG.identityMapSize = rnd() < 0.1 ? 0 : 1 + Math.floor(rnd() * 8);
      SEQUENCER_CONFIG.writtenIndex = rnd() < 0.5;
      const reference = new SequencerIdentityMap();
      (reference as any).lookup = oldLookup;
      const current = new SequencerIdentityMap();
      const maps = [reference, current];
      const id = () => {
        const k = Math.floor(rnd() * 12);
        const r = rnd();
        if (r < 0.3) return `int${k}`;
        if (r < 0.6) return `malware--s${k}`;
        if (r < 0.9) return `malware--x${k}`;
        return `missing--${k}`;
      };
      for (let step = 0; step < 300; step += 1) {
        const r = rnd();
        const answers: unknown[] = maps.map(() => null);
        if (r < 0.45) {
          // the loop resolves an id several times in a row (hasBare, peekBare, resolveInternalId)
          const target = id();
          const repeat = 1 + Math.floor(rnd() * 3);
          maps.forEach((map, i) => {
            const seen = [];
            for (let t = 0; t < repeat; t += 1) seen.push(map.resolveInternalId(target), map.hasBare(target), map.hasWithRefs(target), map.peekBare(target)?.internal_id);
            answers[i] = seen;
          });
          lookups += repeat;
        } else if (r < 0.6) {
          const elements = Array.from({ length: 1 + Math.floor(rnd() * 3) }, () => element(Math.floor(rnd() * 12)));
          maps.forEach((map) => map.ingestBare(elements.map((e) => ({ ...e }))));
        } else if (r < 0.68) {
          const e = element(Math.floor(rnd() * 12));
          maps.forEach((map) => map.ingestWithRefs({ ...e }));
        } else if (r < 0.75) {
          const e = element(Math.floor(rnd() * 12));
          const basis = rnd() < 0.5;
          maps.forEach((map) => map.ingestWritten({ ...e }, basis));
        } else if (r < 0.85) {
          const ids = [id(), id()];
          const reason = rnd() < 0.5 ? 'write' : 'invalidate';
          maps.forEach((map) => map.evict(ids, reason));
          evictions += 1;
        } else if (r < 0.9) {
          const ids = [id(), id()];
          maps.forEach((map) => map.markAbsent(ids, null));
        } else if (r < 0.93) {
          maps.forEach((map) => map.clear());
        } else if (r < 0.96) {
          maps.forEach((map) => map.clearWritten());
        } else {
          now += rnd() < 0.5 ? 4000 : 11000; // some entries expire at their next lookup
        }
        expect(answers[1], `seed ${seed} step ${step}`).toEqual(answers[0]);
        expect([...(current as any).byInternalId.keys()], `seed ${seed} step ${step}`).toEqual([...(reference as any).byInternalId.keys()]);
        expect([...(current as any).idIndex.entries()], `seed ${seed} step ${step}`).toEqual([...(reference as any).idIndex.entries()]);
        expect(current.size()).toBe(reference.size());
      }
    }
    expect(lookups).toBeGreaterThan(10000);
    expect(evictions).toBeGreaterThan(1000);
  });

  it('forgets the most recent entry when it leaves the map (evict, expiry, clear, size bound)', () => {
    let now = 1_000_000;
    vi.spyOn(Date, 'now').mockImplementation(() => now);
    SEQUENCER_CONFIG.identityMapSize = 3;
    SEQUENCER_CONFIG.writtenIndex = false;
    const map = new SequencerIdentityMap();
    const keys = () => [...(map as any).byInternalId.keys()];
    map.ingestBare([element(1), element(2)]);
    expect(map.resolveInternalId('malware--s1')).toBe('int1');
    expect(keys()).toEqual(['int2', 'int1']);
    // the most recent one evicted then stored again: a later touch of another entry still re-inserts
    map.evict(['int1'], 'write');
    map.ingestBare([element(1)]);
    map.resolveInternalId('int2');
    expect(keys()).toEqual(['int1', 'int2']);
    // expired at lookup: removed, the next store and touch keep the order right
    now += 11000;
    expect(map.resolveInternalId('int2')).toBeNull();
    expect(map.resolveInternalId('int1')).toBeNull();
    map.ingestBare([element(3), element(4)]);
    map.resolveInternalId('int3');
    expect(keys()).toEqual(['int4', 'int3']);
    map.clear();
    map.ingestBare([element(5)]);
    map.ingestBare([element(6)]);
    map.resolveInternalId('int5');
    expect(keys()).toEqual(['int6', 'int5']);
    // size 0: the stored entry evicts itself at once
    SEQUENCER_CONFIG.identityMapSize = 0;
    map.ingestBare([element(7)]);
    expect(keys()).toEqual([]);
    SEQUENCER_CONFIG.identityMapSize = 3;
    map.ingestBare([element(8), element(9)]);
    map.resolveInternalId('int8');
    expect(keys()).toEqual(['int9', 'int8']);
  });
});
