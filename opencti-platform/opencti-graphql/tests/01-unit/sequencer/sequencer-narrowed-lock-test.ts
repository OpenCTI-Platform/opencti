import { beforeEach, describe, expect, it, vi } from 'vitest';
import { computeBatchLockKeys, computeOwnLockKeys } from '../../../src/database/sequencer/sequencer-batch-lock';
import { creatableNestedIds, lockErrorKeys } from '../../../src/database/sequencer/sequencer-multi-writer';
import { generateStandardId } from '../../../src/schema/identifier';
import { idLabel } from '../../../src/schema/schema-labels';
import { ENTITY_TYPE_EXTERNAL_REFERENCE, ENTITY_TYPE_KILL_CHAIN_PHASE } from '../../../src/schema/stixMetaObject';

// Several platforms writing (multi_writer step 2): a batch locks in Redis what it writes as its
// own; what it only reads or appends to (referenced meta objects, relation endpoints) stays held
// without a lock across platforms. A key an apply-time lock site needs beyond the batch lock is
// tried once: refused, the group starts a new cycle with that key locked up front.

describe('own lock keys of a batch', () => {
  const instance = new Map<string, string[]>([
    ['malware--m', ['int-m', 'malware--m', 'malware--m-stix']],
    ['identity--org', ['int-org', 'identity--org']],
  ]);
  const peek = (id: string) => instance.get(id) ?? null;
  const relationOwn = (leader: { input: Record<string, any> }) => (leader.input.fromId === 'malware--m' ? ['relationship--uses-std'] : null);
  const noCreatable = () => [];

  it('should lock an entity and its resolved target, not what it references', () => {
    const groups = [{
      leader: { kind: 'entity', candidateIds: ['malware--m'], referencedIds: ['identity--org', 'marking-definition--tlp'], input: {} },
      absorbed: [{ referencedIds: ['external-reference--e'] }],
    }];
    const own = new Set(computeOwnLockKeys(groups, peek, relationOwn, noCreatable));
    expect([...own].sort()).toEqual(['int-m', 'malware--m', 'malware--m-stix']);
    // the full set the batch holds keeps every key, the apply-time lock sites stay no-ops on them
    const held = new Set(computeBatchLockKeys(groups, peek, () => null));
    ['identity--org', 'int-org', 'marking-definition--tlp', 'external-reference--e', 'malware--m'].forEach((k) => expect(held.has(k)).toBe(true));
  });

  it('should lock a relation by its own ids, never its endpoints', () => {
    const groups = [{
      leader: { kind: 'relation', candidateIds: ['malware--m', 'identity--org', 'relationship--stix'], referencedIds: ['malware--m', 'identity--org'], input: { fromId: 'malware--m', toId: 'identity--org' } },
      absorbed: [],
    }];
    expect(computeOwnLockKeys(groups, peek, relationOwn, noCreatable).sort()).toEqual(['relationship--stix', 'relationship--uses-std']);
  });

  it('should lock what an apply may create from its input, and the keys refused in an earlier cycle', () => {
    const groups = [{
      leader: { kind: 'entity', candidateIds: ['malware--m'], referencedIds: [], input: { objectLabel: ['apt'] }, extraLockKeys: ['relationship--refused'] },
      absorbed: [{ referencedIds: [], extraLockKeys: ['int-other'] }],
    }];
    const own = computeOwnLockKeys(groups, peek, relationOwn, (input) => (input.objectLabel ? ['label--apt'] : []));
    ['label--apt', 'relationship--refused', 'int-other', 'malware--m'].forEach((k) => expect(own).toContain(k));
  });
});

describe('meta objects an apply may create', () => {
  it('should count a label given by its value, not by its id', () => {
    expect(creatableNestedIds({ objectLabel: ['apt', 'label--8f4c2b52-6f4b-5c4a-9d3e-111111111111'] })).toEqual([idLabel('apt')]);
  });

  it('should count external references and kill chain phases given as objects, not as ids', () => {
    const reference = { source_name: 'mitre-attack', url: 'https://attack.mitre.org/techniques/T1059', external_id: 'T1059' };
    const phase = { kill_chain_name: 'mitre-attack', phase_name: 'execution' };
    const ids = creatableNestedIds({
      externalReferences: [reference, 'external-reference--existing'],
      killChainPhases: [phase, 'kill-chain-phase--existing'],
    });
    expect(ids).toEqual([generateStandardId(ENTITY_TYPE_EXTERNAL_REFERENCE, reference), generateStandardId(ENTITY_TYPE_KILL_CHAIN_PHASE, phase)]);
  });

  it('should count nothing on an input without nested meta objects or with an underspecified one', () => {
    expect(creatableNestedIds({ name: 'm', createdBy: 'identity--org' })).toEqual([]);
    expect(creatableNestedIds({ killChainPhases: [{}] })).toEqual([]);
  });
});

describe('lock errors', () => {
  it('should give the keys a lock site was refused', () => {
    expect(lockErrorKeys({ extensions: { code: 'LOCK_ERROR', data: { participantIds: ['relationship--r', 'int-m'] } } })).toEqual(['relationship--r', 'int-m']);
    expect(lockErrorKeys({ data: { participantIds: ['int-m', '', 3] } })).toEqual(['int-m']);
    expect(lockErrorKeys(new Error('Unexpected error value: { ... LOCK_ERROR ... }'))).toEqual([]);
  });
});

describe('apply-time lock sites under a multi-writer batch', () => {
  beforeEach(() => {
    vi.resetModules();
    vi.clearAllMocks();
  });

  const loadMasterLock = async (lockResource: any) => {
    vi.doMock('../../../src/database/redis', () => ({ lockResource }));
    vi.doMock('../../../src/config/conf', async (importOriginal) => {
      const actual = await importOriginal<typeof import('../../../src/config/conf')>();
      return { ...actual, booleanConf: vi.fn(() => false) };
    });
    return import('../../../src/lock/master-lock');
  };

  it('should try a key outside the batch lock once, never wait for it', async () => {
    const lockResource = vi.fn().mockResolvedValue({ unlock: vi.fn() });
    const { lockResources } = await loadMasterLock(lockResource);
    const sequencer = { heldKeys: new Set(['int-m']), signal: new AbortController().signal, noWait: true };
    await lockResources(['int-m', 'relationship--r'], { draftId: '', sequencer });
    expect(lockResource).toHaveBeenCalledWith(['relationship--r'], { draftId: '', retryCount: 0 });
  });

  it('should keep the lock options of a single writer and take no lock on held keys', async () => {
    const lockResource = vi.fn().mockResolvedValue({ unlock: vi.fn() });
    const { lockResources } = await loadMasterLock(lockResource);
    const signal = new AbortController().signal;
    await lockResources(['int-m', 'relationship--r'], { draftId: '', sequencer: { heldKeys: new Set(['int-m']), signal } });
    expect(lockResource).toHaveBeenCalledWith(['relationship--r'], { draftId: '' });
    lockResource.mockClear();
    const held = await lockResources(['int-m'], { sequencer: { heldKeys: new Set(['int-m']), signal, noWait: true } });
    expect(lockResource).not.toHaveBeenCalled();
    expect(held.operation).toEqual('sequencer-batch');
  });
});
