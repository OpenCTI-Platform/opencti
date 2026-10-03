import { afterEach, describe, expect, it, vi } from 'vitest';
import type { AuthContext, AuthUser } from '../../../../src/types/user';
import type { LandscapeDiffAggregates, LandscapeDiffEntitySummary } from '../../../../src/modules/timeMachine/timeMachine-types';

// The landscape diff and the STIX loading are canned: the composition of the digest is under test.
const computeLandscapeDiffMock = vi.fn();
vi.mock('../../../../src/modules/timeMachine/landscapeDiff-domain', () => ({
  computeLandscapeDiff: (...args: unknown[]) => computeLandscapeDiffMock(...args),
}));
const stixLoadByIdsMock = vi.fn();
vi.mock('../../../../src/database/middleware', () => ({
  stixLoadByIds: (...args: unknown[]) => stixLoadByIdsMock(...args),
}));

import { buildChangeDigestData } from '../../../../src/modules/timeMachine/timeMachine-changeDigest';
import { STIX_EXT_OCTI } from '../../../../src/types/stix-2-1-extensions';

const summary = (id: string, input: Partial<LandscapeDiffEntitySummary> = {}): LandscapeDiffEntitySummary => ({
  entity_id: id,
  entity_type: 'Intrusion-Set',
  name: id,
  created_in_period: false,
  revoked_in_period: false,
  attributes_changed: 0,
  relationships_added: 1,
  relationships_removed: 0,
  relationships_revoked: 0,
  confidence_before: null,
  confidence_after: null,
  score_before: null,
  score_after: null,
  change_score: 2,
  ...input,
});

const aggregates = {
  entities_in_scope: 3,
  entities_changed: 3,
  new_relationships: 3,
  removed_relationships: 0,
  revocations: 0,
  new_techniques: [],
  new_techniques_count: 0,
  new_malware: [],
  new_malware_count: 0,
  new_tools: [],
  new_tools_count: 0,
  new_infrastructure_count: 0,
} as unknown as LandscapeDiffAggregates;

const stix = (id: string) => ({ id: `intrusion-set--${id}`, extensions: { [STIX_EXT_OCTI]: { id } } });
const trigger = { internal_id: 'change-digest-1', name: 'Weekly landscape', filters: null, scope_entity_types: ['Intrusion-Set'] };
const context = {} as AuthContext;
const user = { id: 'analyst-1' } as AuthUser;

describe('buildChangeDigestData', () => {
  afterEach(() => {
    vi.clearAllMocks();
  });

  it('puts the overall summary on the first line actually emitted', async () => {
    computeLandscapeDiffMock.mockResolvedValue({ aggregates, entities: [summary('a'), summary('b'), summary('c')], total: 3, truncated: false });
    // The first changed entity is not readable anymore by the recipient
    stixLoadByIdsMock.mockResolvedValue([stix('b'), stix('c')]);
    const data = await buildChangeDigestData(context, user, trigger, '2026-01-05T09:00:00.000Z', '2026-01-12T09:00:00.000Z');
    expect(data).toHaveLength(2);
    expect(data[0].instance.id).toBe('intrusion-set--b');
    expect(data[0].message).toContain(' | `3` of `3` entities changed');
    expect(data[0].message).toContain('`1` other changed entities not listed');
    expect(data[0].message).not.toContain('partial result');
    expect(data[1].message).toBe('`1` new relationship(s)');
  });

  it('flags the summary as partial when the filter set exceeds the digest limits', async () => {
    computeLandscapeDiffMock.mockResolvedValue({ aggregates, entities: [summary('a')], total: 1, truncated: true });
    stixLoadByIdsMock.mockResolvedValue([stix('a')]);
    const data = await buildChangeDigestData(context, user, trigger, '2026-01-05T09:00:00.000Z', '2026-01-12T09:00:00.000Z');
    expect(data).toHaveLength(1);
    expect(data[0].message).toContain('partial result: the filter set exceeds the limits of a change digest');
  });

  it('sends nothing when nothing changed', async () => {
    computeLandscapeDiffMock.mockResolvedValue({ aggregates: { ...aggregates, entities_changed: 0 }, entities: [], total: 3, truncated: false });
    const data = await buildChangeDigestData(context, user, trigger, '2026-01-05T09:00:00.000Z', '2026-01-12T09:00:00.000Z');
    expect(data).toEqual([]);
    expect(stixLoadByIdsMock).not.toHaveBeenCalled();
  });
});
