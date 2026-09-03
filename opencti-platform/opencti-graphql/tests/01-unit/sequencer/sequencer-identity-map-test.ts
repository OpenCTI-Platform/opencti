import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { SequencerIdentityMap } from '../../../src/database/sequencer/sequencer-identity-map';
import { SEQUENCER_CONFIG } from '../../../src/database/sequencer/sequencer-config';
import { executionContext } from '../../../src/utils/access';
import type { AuthUser } from '../../../src/types/user';

const bypassUser = {
  id: 'user1',
  internal_id: 'user1',
  capabilities: [{ name: 'BYPASS' }],
  origin: {},
} as unknown as AuthUser;

const element = (internalId: string, standardId: string, type = 'Malware', extra: Record<string, any> = {}) => ({
  internal_id: internalId,
  standard_id: standardId,
  entity_type: type,
  parent_types: ['Stix-Domain-Object', 'Stix-Core-Object'],
  ...extra,
});

const savedSize = SEQUENCER_CONFIG.identityMapSize;
const savedTtl = SEQUENCER_CONFIG.identityMapTtlS;
const savedMode = SEQUENCER_CONFIG.mode;

describe('sequencer identity map (plan 0009 C3/C5)', () => {
  beforeAll(() => {
    SEQUENCER_CONFIG.mode = 'batch';
    SEQUENCER_CONFIG.identityMapSize = 100;
    SEQUENCER_CONFIG.identityMapTtlS = 600;
  });
  afterAll(() => {
    SEQUENCER_CONFIG.mode = savedMode;
    SEQUENCER_CONFIG.identityMapSize = savedSize;
    SEQUENCER_CONFIG.identityMapTtlS = savedTtl;
  });

  it('serves an element by any of its instance ids', async () => {
    const map = new SequencerIdentityMap();
    map.ingestBare([element('int1', 'malware--aaa', 'Malware', { x_opencti_stix_ids: ['malware--bbb'] })]);
    const ctx = executionContext('test');
    const byStandard = await map.serveBare(ctx, bypassUser, ['malware--aaa'], {});
    const byStix = await map.serveBare(ctx, bypassUser, ['malware--bbb'], {});
    const byInternal = await map.serveBare(ctx, bypassUser, ['int1'], {});
    expect(byStandard?.hits.map((h) => h.internal_id)).toEqual(['int1']);
    expect(byStix?.hits.map((h) => h.internal_id)).toEqual(['int1']);
    expect(byInternal?.hits.map((h) => h.internal_id)).toEqual(['int1']);
    expect(byInternal?.misses).toEqual([]);
  });

  it('reports unknown ids as misses and filters by requested type', async () => {
    const map = new SequencerIdentityMap();
    map.ingestBare([element('int1', 'malware--aaa')]);
    const ctx = executionContext('test');
    const unknown = await map.serveBare(ctx, bypassUser, ['whatever--zzz'], {});
    expect(unknown?.hits).toEqual([]);
    expect(unknown?.misses).toEqual(['whatever--zzz']);
    const wrongType = await map.serveBare(ctx, bypassUser, ['malware--aaa'], { type: 'Indicator' });
    expect(wrongType?.misses).toEqual(['malware--aaa']);
    const parentType = await map.serveBare(ctx, bypassUser, ['malware--aaa'], { type: 'Stix-Domain-Object' });
    expect(parentType?.hits.length).toBe(1);
  });

  it('refuses ineligible opts and non-batch mode', async () => {
    const map = new SequencerIdentityMap();
    map.ingestBare([element('int1', 'malware--aaa')]);
    const ctx = executionContext('test');
    expect(await map.serveBare(ctx, bypassUser, ['malware--aaa'], { withoutRels: false })).toBeNull();
    expect(await map.serveBare(ctx, bypassUser, ['malware--aaa'], { relCount: true })).toBeNull();
    SEQUENCER_CONFIG.mode = 'passthrough';
    expect(await map.serveBare(ctx, bypassUser, ['malware--aaa'], {})).toBeNull();
    SEQUENCER_CONFIG.mode = 'batch';
  });

  it('eviction by any id removes the element and all its keys', async () => {
    const map = new SequencerIdentityMap();
    map.ingestBare([element('int1', 'malware--aaa', 'Malware', { x_opencti_stix_ids: ['malware--bbb'] })]);
    map.evict(['malware--bbb']);
    const ctx = executionContext('test');
    const after = await map.serveBare(ctx, bypassUser, ['int1', 'malware--aaa'], {});
    expect(after?.hits).toEqual([]);
    expect(after?.misses).toEqual(['int1', 'malware--aaa']);
    expect(map.size()).toBe(0);
  });

  it('bounds the size LRU-style', () => {
    SEQUENCER_CONFIG.identityMapSize = 3;
    const map = new SequencerIdentityMap();
    map.ingestBare([element('a', 's--a'), element('b', 's--b'), element('c', 's--c')]);
    expect(map.hasBare('s--a')).toBe(true); // touches a: b is now the oldest
    map.ingestBare([element('d', 's--d')]);
    expect(map.size()).toBe(3);
    expect(map.hasBare('s--b')).toBe(false);
    expect(map.hasBare('s--a')).toBe(true);
    SEQUENCER_CONFIG.identityMapSize = 100;
  });

  it('expires entries after the TTL', () => {
    SEQUENCER_CONFIG.identityMapTtlS = -1; // already expired on ingest
    const map = new SequencerIdentityMap();
    map.ingestBare([element('int1', 'malware--aaa')]);
    expect(map.hasBare('malware--aaa')).toBe(false);
    SEQUENCER_CONFIG.identityMapTtlS = 600;
  });

  it('serves the with-refs level only for entries loaded with refs', async () => {
    const map = new SequencerIdentityMap();
    const bare = element('int1', 'malware--aaa');
    map.ingestBare([bare]);
    const ctx = executionContext('test');
    const before = await map.serveWithRefs(ctx, bypassUser, ['malware--aaa'], {});
    expect(before?.misses).toEqual(['malware--aaa']);
    map.ingestWithRefs({ ...bare, objectMarking: [{ internal_id: 'm1' }] });
    const after = await map.serveWithRefs(ctx, bypassUser, ['malware--aaa'], {});
    expect(after?.hits.length).toBe(1);
    expect(after?.hits[0].objectMarking?.[0]?.internal_id).toBe('m1');
  });

  // s10.3 rung 1: per-batch negative cache
  it('serves known-absent ids as neither hit nor miss (no ES trip)', async () => {
    const map = new SequencerIdentityMap();
    map.markAbsent(['malware--gone'], null);
    const ctx = executionContext('test');
    const served = await map.serveBare(ctx, bypassUser, ['malware--gone'], { type: 'Malware' });
    expect(served?.hits).toEqual([]);
    expect(served?.misses).toEqual([]);
  });

  it('typed absence only answers queries narrower than the probe', async () => {
    const map = new SequencerIdentityMap();
    map.markAbsent(['ref--gone'], ['External-Reference', 'Label']);
    const ctx = executionContext('test');
    const subset = await map.serveBare(ctx, bypassUser, ['ref--gone'], { type: 'External-Reference' });
    expect(subset?.misses).toEqual([]);
    const outside = await map.serveBare(ctx, bypassUser, ['ref--gone'], { type: 'Tool' });
    expect(outside?.misses).toEqual(['ref--gone']);
    const untypedQuery = await map.serveBare(ctx, bypassUser, ['ref--gone'], {});
    expect(untypedQuery?.misses).toEqual(['ref--gone']);
  });

  it('presence always wins over absence, and ingest revokes it', async () => {
    const map = new SequencerIdentityMap();
    map.ingestBare([element('int1', 'malware--aaa')]);
    map.markAbsent(['malware--aaa'], null); // no-op: the element is present
    const ctx = executionContext('test');
    const served = await map.serveBare(ctx, bypassUser, ['malware--aaa'], {});
    expect(served?.hits.map((h) => h.internal_id)).toEqual(['int1']);
    // absent first, then created within the batch (apply result ingested)
    map.markAbsent(['malware--new'], null);
    expect(map.isKnownAbsent('malware--new', null)).toBe(true);
    map.ingestBare([element('int2', 'malware--new')]);
    expect(map.isKnownAbsent('malware--new', null)).toBe(false);
    const after = await map.serveBare(ctx, bypassUser, ['malware--new'], {});
    expect(after?.hits.map((h) => h.internal_id)).toEqual(['int2']);
  });

  it('clearAbsent restores the miss behavior at batch boundaries', async () => {
    const map = new SequencerIdentityMap();
    map.markAbsent(['malware--gone'], null);
    map.clearAbsent();
    const ctx = executionContext('test');
    const served = await map.serveBare(ctx, bypassUser, ['malware--gone'], {});
    expect(served?.misses).toEqual(['malware--gone']);
  });
});
