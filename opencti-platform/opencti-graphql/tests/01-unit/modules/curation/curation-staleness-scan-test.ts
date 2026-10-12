import { beforeEach, describe, expect, it, vi } from 'vitest';
import { runStalenessScan } from '../../../../src/modules/curation/curation-scan';
import { persistProposalDraft } from '../../../../src/modules/curation/curation-proposals';
import { redisSetManagerEventState } from '../../../../src/database/redis';
import { DEFAULT_CURATION_SETTINGS } from '../../../../src/modules/curation/curation-defaults';
import { type CurationSettings, DETECTOR_STALENESS, EVIDENCE_DECAYED_INDICATOR, EVIDENCE_STALENESS, type ProposalDraft } from '../../../../src/modules/curation/curation-types';
import { ENTITY_TYPE_INDICATOR } from '../../../../src/modules/indicator/indicator-types';

const decayRule = { decay_revoke_score: 20 };
const indicator = (id: string, updatedAt: string, score: number) => ({
  internal_id: id,
  entity_type: ENTITY_TYPE_INDICATOR,
  name: id,
  updated_at: updatedAt,
  revoked: false,
  x_opencti_score: score,
  decay_applied_rule: decayRule,
});

// Inactive and decayed, inactive only, decayed only (updated last week).
const both = indicator('indicator-both', '2024-01-01T00:00:00.000Z', 10);
const inactive = indicator('indicator-inactive', '2024-01-01T00:00:00.000Z', 80);
const decayed = indicator('indicator-decayed', new Date(Date.now() - 7 * 24 * 3600 * 1000).toISOString(), 10);

vi.mock('../../../../src/database/middleware-loader', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/database/middleware-loader')>()),
  pageEntitiesConnection: vi.fn(async (_context: unknown, _user: unknown, _types: string[], opts: { filters: { filters: Array<{ key: string[] }> } }) => {
    const isDecayPage = opts.filters.filters.some(({ key }) => key[0] === 'decay_base_score');
    const nodes = isDecayPage ? [both, decayed] : [both, inactive];
    return { edges: nodes.map((node) => ({ node })), pageInfo: { hasNextPage: false } };
  }),
  fullRelationsList: vi.fn(async () => []),
}));

vi.mock('../../../../src/database/redis', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/database/redis')>()),
  redisGetManagerEventState: vi.fn(async () => null),
  redisSetManagerEventState: vi.fn(async () => undefined),
}));

vi.mock('../../../../src/modules/curation/curation-proposals', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../../../../src/modules/curation/curation-proposals')>()),
  persistProposalDraft: vi.fn(async () => ({ created: true, suppressed: false })),
}));

const settings: CurationSettings = { ...DEFAULT_CURATION_SETTINGS, curation_enabled: true, enabled_detectors: [DETECTOR_STALENESS], curated_entity_types: [] };

const committedCursors = () => vi.mocked(redisSetManagerEventState).mock.calls
  .map(([key]) => key as string)
  .filter((key) => key.startsWith('curation_scan_rotation_') && !key.startsWith('curation_scan_rotation_attempts_'));
const draftsBySubject = () => new Map(vi.mocked(persistProposalDraft).mock.calls.map(([, , draft]) => [(draft as ProposalDraft).subjects[0].id, draft as ProposalDraft]));
const evidenceTypes = (draft?: ProposalDraft) => draft?.evidence.map((item) => item.evidence_type);

describe('staleness scan', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('gives an indicator found by its decay alone no evidence of inactivity, and an inactive decayed one both', async () => {
    await runStalenessScan({} as never, settings);
    const drafts = draftsBySubject();
    expect(drafts.size).toBe(3);
    expect(evidenceTypes(drafts.get('indicator-decayed'))).toEqual([EVIDENCE_DECAYED_INDICATOR]);
    expect(evidenceTypes(drafts.get('indicator-inactive'))).toEqual([EVIDENCE_STALENESS]);
    expect(evidenceTypes(drafts.get('indicator-both'))).toEqual([EVIDENCE_STALENESS, EVIDENCE_DECAYED_INDICATOR]);
    // The confidence of a decay alone is that of its evidence, not raised by an inactivity that was not found.
    expect(drafts.get('indicator-decayed')?.confidence).toBeCloseTo(0.6);
    expect(drafts.get('indicator-both')?.confidence).toBeGreaterThan(0.6);
    expect(committedCursors()).not.toHaveLength(0);
  });

  it('attempts every draft when one cannot be persisted, then leaves the cursors of the page, so the next scan reads it again', async () => {
    vi.mocked(persistProposalDraft).mockRejectedValueOnce(new Error('Search engine unavailable'));
    await runStalenessScan({} as never, settings);
    expect(persistProposalDraft).toHaveBeenCalledTimes(3);
    expect(committedCursors()).toHaveLength(0);
  });
});
