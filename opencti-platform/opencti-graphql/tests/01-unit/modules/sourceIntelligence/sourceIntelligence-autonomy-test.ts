import { describe, expect, it } from 'vitest';
import '../../../../src/modules/index';
import { selectAutonomousCandidates } from '../../../../src/modules/sourceIntelligence/sourceIntelligence-recommendations';
import { DEFAULT_SOURCE_INTELLIGENCE_SETTINGS, type SourceIntelligenceSettings } from '../../../../src/modules/sourceIntelligence/sourceIntelligence-settings';
import type { BasicStoreEntitySourceRecommendation, RecommendationKindValue } from '../../../../src/modules/sourceIntelligence/sourceIntelligence-types';

const recommendation = (id: string, kind: string, status: string, proposedAt: string, fingerprint = `fingerprint-${id}`) => ({
  internal_id: id,
  recommendation_kind: kind,
  recommendation_status: status,
  proposed_at: proposedAt,
  fingerprint,
}) as unknown as BasicStoreEntitySourceRecommendation;

const settingsWith = (kinds: RecommendationKindValue[], maxPerRun: number): SourceIntelligenceSettings => ({
  ...DEFAULT_SOURCE_INTELLIGENCE_SETTINGS,
  autonomy: { ...DEFAULT_SOURCE_INTELLIGENCE_SETTINGS.autonomy, auto_apply_kinds: kinds, max_auto_actions_per_run: maxPerRun },
});

const ids = (recommendations: BasicStoreEntitySourceRecommendation[]) => recommendations.map((r) => r.internal_id);

describe('Source intelligence autonomy policy', () => {
  const backlog = [
    recommendation('decay-new', 'add_decay_rule', 'proposed', '2026-09-20T00:00:00.000Z'),
    recommendation('connector-old', 'add_connector', 'proposed', '2026-09-01T00:00:00.000Z'),
    recommendation('confidence', 'lower_confidence', 'proposed', '2026-09-02T00:00:00.000Z'),
    recommendation('decay-old', 'add_decay_rule', 'proposed', '2026-09-10T00:00:00.000Z'),
  ];

  it('should apply the oldest proposals of the allowed kinds within one cap across every kind', () => {
    const selected = selectAutonomousCandidates(backlog, settingsWith(['add_decay_rule', 'add_connector'], 2));
    expect(ids(selected)).toEqual(['connector-old', 'decay-old']);
  });

  it('should take the proposals left over by the cap on the next run', () => {
    const settings = settingsWith(['add_decay_rule', 'add_connector'], 2);
    const appliedIds = new Set(ids(selectAutonomousCandidates(backlog, settings)));
    const nextRun = backlog.map((r) => (appliedIds.has(r.internal_id) ? recommendation(r.internal_id, r.recommendation_kind, 'applied', r.proposed_at as string) : r));
    expect(ids(selectAutonomousCandidates(nextRun, settings))).toEqual(['decay-new']);
  });

  it('should never retry failed, dismissed, reverted or applied recommendations', () => {
    const settled = ['failed', 'dismissed', 'reverted', 'applied'].map((status, index) => recommendation(`settled-${status}`, 'add_decay_rule', status, `2026-08-0${index + 1}T00:00:00.000Z`));
    expect(selectAutonomousCandidates(settled, settingsWith(['add_decay_rule'], 10))).toEqual([]);
  });

  it('should never apply again automatically a change someone reverted', () => {
    const history = [
      recommendation('decay-reverted', 'add_decay_rule', 'reverted', '2026-08-01T00:00:00.000Z', 'decay-source-1'),
      recommendation('decay-again', 'add_decay_rule', 'proposed', '2026-09-01T00:00:00.000Z', 'decay-source-1'),
      recommendation('decay-reverting', 'add_decay_rule', 'reverting', '2026-08-02T00:00:00.000Z', 'decay-source-2'),
      recommendation('decay-other', 'add_decay_rule', 'proposed', '2026-09-02T00:00:00.000Z', 'decay-source-3'),
    ];
    expect(ids(selectAutonomousCandidates(history, settingsWith(['add_decay_rule'], 10)))).toEqual(['decay-other']);
  });

  it('should apply nothing without allowed kinds or with a zero cap', () => {
    expect(selectAutonomousCandidates(backlog, settingsWith([], 10))).toEqual([]);
    expect(selectAutonomousCandidates(backlog, settingsWith(['add_decay_rule'], 0))).toEqual([]);
  });
});
