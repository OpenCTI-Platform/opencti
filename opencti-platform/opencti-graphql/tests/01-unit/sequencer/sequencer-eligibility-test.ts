import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { isSequencerEligible, sequencerScopedContext, stripMemberRefMarks } from '../../../src/database/sequencer/sequencer-eligibility';
import { SEQUENCER_CONFIG } from '../../../src/database/sequencer/sequencer-config';
import type { AuthContext, AuthUser } from '../../../src/types/user';

const workerUser = (origin: Record<string, any> = {}) => ({
  id: 'user1',
  origin: { call_retry_number: '0', applicant_id: 'connector1', socket: 'query', ...origin },
} as unknown as AuthUser);

const ctx = (extra: Record<string, any> = {}) => ({ ...extra } as unknown as AuthContext);

describe('sequencer eligibility (plan 0009 B1 bypass matrix)', () => {
  beforeAll(() => {
    SEQUENCER_CONFIG.enabled = true;
  });
  afterAll(() => {
    SEQUENCER_CONFIG.enabled = false;
  });

  it('accepts a worker-origin STIX entity create', () => {
    expect(isSequencerEligible(ctx(), workerUser(), 'Malware', {})).toBe(true);
  });
  it('accepts a worker-origin STIX relationship create', () => {
    expect(isSequencerEligible(ctx(), workerUser(), 'uses', {})).toBe(true);
  });
  it('accepts retry attempts (header present, any value)', () => {
    expect(isSequencerEligible(ctx(), workerUser({ call_retry_number: '2' }), 'Malware', {})).toBe(true);
  });
  it('rejects when the flag is off', () => {
    SEQUENCER_CONFIG.enabled = false;
    expect(isSequencerEligible(ctx(), workerUser(), 'Malware', {})).toBe(false);
    SEQUENCER_CONFIG.enabled = true;
  });
  it('rejects non-worker origin (no retry header)', () => {
    expect(isSequencerEligible(ctx(), workerUser({ call_retry_number: undefined }), 'Malware', {})).toBe(false);
  });
  it('rejects internal object types', () => {
    expect(isSequencerEligible(ctx(), workerUser(), 'Work', {})).toBe(false);
  });
  it('rejects draft context', () => {
    expect(isSequencerEligible(ctx({ draft_context: 'draft1' }), workerUser(), 'Malware', {})).toBe(false);
  });
  it('rejects rule engine writes', () => {
    expect(isSequencerEligible(ctx(), workerUser(), 'Malware', { fromRule: 'rule1' })).toBe(false);
  });
  it('rejects internal origin (managers)', () => {
    expect(isSequencerEligible(ctx(), workerUser({ socket: 'internal' }), 'Malware', {})).toBe(false);
  });
  it('rejects calls made under a held lock', () => {
    expect(isSequencerEligible(ctx(), workerUser(), 'uses', { locks: ['lock1'] })).toBe(false);
  });
  it('rejects restore calls', () => {
    expect(isSequencerEligible(ctx(), workerUser(), 'Malware', { restore: true })).toBe(false);
  });
  it('rejects re-entrant calls (loop applying) and denylisted scopes', () => {
    const applying = sequencerScopedContext(ctx(), 'applying');
    const bypass = sequencerScopedContext(ctx(), 'bypass');
    expect(isSequencerEligible(applying, workerUser(), 'Malware', {})).toBe(false);
    expect(isSequencerEligible(bypass, workerUser(), 'Malware', {})).toBe(false);
  });
  it('scoped context does not leak into the original', () => {
    const base = ctx();
    sequencerScopedContext(base, 'bypass');
    expect(base.sequencer).toBeUndefined();
  });
});

describe('member ref marks (plan 0009 s9.8.3, option B suffix transport)', () => {
  it('strips ||M|| marks in place everywhere and collects the ids', () => {
    const input = {
      stix_id: 'report--r1',
      createdBy: 'identity--ext',
      objects: ['malware--m1||M||', 'identity--ext2', 'relationship--r9||M||'],
      objectMarking: ['marking-definition--tlp'],
      fromId: 'malware--m1||M||',
      nested: { granted_refs: ['identity--org1||M||'] },
    };
    const collected = new Set<string>();
    stripMemberRefMarks(input, collected);
    expect(input.objects).toEqual(['malware--m1', 'identity--ext2', 'relationship--r9']);
    expect(input.fromId).toBe('malware--m1');
    expect(input.nested.granted_refs).toEqual(['identity--org1']);
    expect(input.createdBy).toBe('identity--ext');
    expect(input.stix_id).toBe('report--r1');
    expect(Array.from(collected).sort()).toEqual(['identity--org1', 'malware--m1', 'relationship--r9']);
  });

  it('is a no-op on unannotated input (no marks, empty set)', () => {
    const input = { stix_id: 'malware--a', createdBy: 'identity--b', name: 'clean' };
    const collected = new Set<string>();
    stripMemberRefMarks(input, collected);
    expect(input).toEqual({ stix_id: 'malware--a', createdBy: 'identity--b', name: 'clean' });
    expect(collected.size).toBe(0);
  });

  it('never produces an empty id (a bare mark is left untouched)', () => {
    const input = { weird: '||M||' };
    const collected = new Set<string>();
    stripMemberRefMarks(input, collected);
    expect(input.weird).toBe('||M||');
    expect(collected.size).toBe(0);
  });
});
