import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { AuthContext, AuthUser } from '../../../../src/types/user';
import type { LandscapeDiffAggregates, LandscapeDiffEntitySummary } from '../../../../src/modules/timeMachine/timeMachine-types';

// The landscape diff, the access check and the STIX loading are canned: the composition of the digest is under test.
const computeLandscapeDiffMock = vi.fn();
const isLandscapeResultAccessibleMock = vi.fn();
vi.mock('../../../../src/modules/timeMachine/landscapeDiff-domain', () => ({
  computeLandscapeDiff: (...args: unknown[]) => computeLandscapeDiffMock(...args),
  isLandscapeResultAccessible: (...args: unknown[]) => isLandscapeResultAccessibleMock(...args),
}));
const stixLoadByIdsMock = vi.fn();
vi.mock('../../../../src/database/middleware', () => ({
  stixLoadByIds: (...args: unknown[]) => stixLoadByIdsMock(...args),
}));

import { buildChangeDigestData } from '../../../../src/modules/timeMachine/timeMachine-changeDigest';
import { resolveChangeDigestLocale } from '../../../../src/modules/timeMachine/timeMachine-changeDigest-messages';
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
  relationships_confidence_changed: 0,
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

const computation = (ids: string[], input: Partial<LandscapeDiffAggregates> = {}) => ({
  aggregates: { ...aggregates, entities_in_scope: ids.length, entities_changed: ids.length, new_relationships: ids.length, ...input },
  entities: ids.map((id) => summary(id)),
  total: ids.length,
  truncated: false,
  contributors: ids,
});

describe('buildChangeDigestData', () => {
  beforeEach(() => {
    isLandscapeResultAccessibleMock.mockResolvedValue(true);
  });
  afterEach(() => {
    vi.clearAllMocks();
  });

  it('puts the overall summary on the first line', async () => {
    computeLandscapeDiffMock.mockResolvedValue(computation(['a', 'b', 'c']));
    stixLoadByIdsMock.mockResolvedValue([stix('a'), stix('b'), stix('c')]);
    const data = await buildChangeDigestData(context, user, trigger, '2026-01-05T09:00:00.000Z', '2026-01-12T09:00:00.000Z');
    expect(data).toHaveLength(3);
    expect(data[0].instance.id).toBe('intrusion-set--a');
    expect(data[0].message).toBe('`1` new relationship | `3` of `3` entities changed, `3` new relationships, `0` removed relationships, and `0` revocations');
    expect(data[1].message).toBe('`1` new relationship');
    expect(isLandscapeResultAccessibleMock).toHaveBeenCalledWith(context, user, ['a', 'b', 'c'], expect.anything(), expect.anything());
  });

  it('writes the digest in the language of the recipient', async () => {
    computeLandscapeDiffMock.mockResolvedValue(computation(['a']));
    stixLoadByIdsMock.mockResolvedValue([stix('a')]);
    const data = await buildChangeDigestData(context, user, trigger, '2026-01-05T09:00:00.000Z', '2026-01-12T09:00:00.000Z', resolveChangeDigestLocale('fr-fr'));
    expect(data[0].message).toBe('`1` nouvelle relation | `1` entité modifiée sur `1`, `1` nouvelle relation, `0` relation supprimée et `0` révocation');
  });

  it('computes the digest again when a listed entity is not readable anymore, so its counts never leak', async () => {
    // The first changed entity is reclassified between the computation and the emission
    computeLandscapeDiffMock.mockResolvedValueOnce(computation(['a', 'b', 'c'])).mockResolvedValueOnce(computation(['b', 'c']));
    stixLoadByIdsMock.mockResolvedValueOnce([stix('b'), stix('c')]).mockResolvedValueOnce([stix('b'), stix('c')]);
    const data = await buildChangeDigestData(context, user, trigger, '2026-01-05T09:00:00.000Z', '2026-01-12T09:00:00.000Z');
    expect(computeLandscapeDiffMock).toHaveBeenCalledTimes(2);
    expect(data).toHaveLength(2);
    expect(data[0].instance.id).toBe('intrusion-set--b');
    expect(data[0].message).toContain(' | `2` of `2` entities changed');
    expect(data[0].message).not.toContain('`3`');
  });

  it('computes the digest again when an element counted in the summary is not accessible anymore', async () => {
    computeLandscapeDiffMock.mockResolvedValueOnce(computation(['a', 'b'], { new_relationships: 5 })).mockResolvedValueOnce(computation(['a', 'b']));
    stixLoadByIdsMock.mockResolvedValue([stix('a'), stix('b')]);
    isLandscapeResultAccessibleMock.mockResolvedValueOnce(false).mockResolvedValueOnce(true);
    const data = await buildChangeDigestData(context, user, trigger, '2026-01-05T09:00:00.000Z', '2026-01-12T09:00:00.000Z');
    expect(computeLandscapeDiffMock).toHaveBeenCalledTimes(2);
    expect(data[0].message).toContain('`2` new relationships, `0` removed relationships');
    expect(data[0].message).not.toContain('`5`');
  });

  it('skips the digest of the period when access keeps changing', async () => {
    computeLandscapeDiffMock.mockResolvedValue(computation(['a', 'b']));
    stixLoadByIdsMock.mockResolvedValue([stix('a'), stix('b')]);
    isLandscapeResultAccessibleMock.mockResolvedValue(false);
    const data = await buildChangeDigestData(context, user, trigger, '2026-01-05T09:00:00.000Z', '2026-01-12T09:00:00.000Z');
    expect(computeLandscapeDiffMock).toHaveBeenCalledTimes(2);
    expect(data).toEqual([]);
  });

  it('flags the summary as partial when the filter set exceeds the digest limits', async () => {
    computeLandscapeDiffMock.mockResolvedValue({ ...computation(['a']), truncated: true });
    stixLoadByIdsMock.mockResolvedValue([stix('a')]);
    const data = await buildChangeDigestData(context, user, trigger, '2026-01-05T09:00:00.000Z', '2026-01-12T09:00:00.000Z');
    expect(data).toHaveLength(1);
    expect(data[0].message).toContain('partial result: the filter set exceeds the limits of a change digest');
  });

  it('sends nothing when nothing changed', async () => {
    computeLandscapeDiffMock.mockResolvedValue({ ...computation([]), aggregates: { ...aggregates, entities_changed: 0 } });
    const data = await buildChangeDigestData(context, user, trigger, '2026-01-05T09:00:00.000Z', '2026-01-12T09:00:00.000Z');
    expect(data).toEqual([]);
    expect(stixLoadByIdsMock).not.toHaveBeenCalled();
    expect(isLandscapeResultAccessibleMock).not.toHaveBeenCalled();
  });
});
