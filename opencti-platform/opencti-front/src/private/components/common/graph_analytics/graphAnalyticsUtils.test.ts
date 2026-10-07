import { describe, expect, it, vi } from 'vitest';
import {
  buildGraphTopHubsChart,
  collectPathElementIds,
  formatGraphClusterLabel,
  formatSimilarityScore,
  GRAPH_FEATURE_FAMILY_LABELS,
  isGraphSimilarEntityType,
  reportPayloadErrors,
  resolveGraphAnalyticsState,
  similarityScoreSeverity,
  trimLeadingEmptyPeriods,
} from './graphAnalyticsUtils';

const { notifyError } = vi.hoisted(() => ({ notifyError: vi.fn() }));
vi.mock('../../../../relay/environment', () => ({
  commitMutation: vi.fn(),
  defaultCommitMutation: {},
  MESSAGING$: { notifyError },
}));

describe('graphAnalyticsUtils', () => {
  const translate = (message: string, options?: { values?: Record<string, string | number> }) => Object.entries(options?.values ?? {})
    .reduce((text, [key, value]) => text.replace(`{${key}}`, String(value)), message);

  it('names a cluster after its first accessible representative, never after its identifier', () => {
    const representatives = [{ representative: { main: 'update-cdn-sync.com' } }, { representative: { main: 'cdn-sync-update.net' } }];
    expect(formatGraphClusterLabel(translate, { cluster_kind: 'infrastructure', representatives })).toBe('Infrastructure cluster around update-cdn-sync.com');
    expect(formatGraphClusterLabel(translate, { cluster_kind: 'campaign', representatives })).toBe('Campaign cluster around update-cdn-sync.com');
    expect(formatGraphClusterLabel(translate, { cluster_kind: 'infrastructure', representatives: [] })).toBe('Infrastructure cluster');
    expect(formatGraphClusterLabel(translate, { cluster_kind: 'unknown', representatives: null })).toBe('Cluster');
  });

  it('gives the analytics status one state', () => {
    const idle = { manager_enabled: true, pending_entities: 0, full_pass_in_progress: false, last_full_pass_completed_at: '2026-10-04T00:10:00Z' };
    expect(resolveGraphAnalyticsState(idle)).toBe('up_to_date');
    expect(resolveGraphAnalyticsState({ ...idle, manager_enabled: false, pending_entities: 4 })).toBe('disabled');
    expect(resolveGraphAnalyticsState({ ...idle, pending_entities: 4 })).toBe('analysing');
    expect(resolveGraphAnalyticsState({ ...idle, full_pass_in_progress: true })).toBe('analysing');
    expect(resolveGraphAnalyticsState({ ...idle, last_full_pass_completed_at: null })).toBe('not_analysed');
    expect(resolveGraphAnalyticsState({ ...idle, last_full_pass_completed_at: null, analytics_process_last_run_at: '2026-10-04T00:10:00Z' })).toBe('up_to_date');
    // a pass stopped at its entity cap analysed the platform, although no pass reached the last entity yet
    expect(resolveGraphAnalyticsState({ ...idle, last_full_pass_completed_at: null, last_full_pass_ended_at: '2026-10-04T00:10:00Z' })).toBe('up_to_date');
  });

  it('formats scores as bounded percentages', () => {
    expect(formatSimilarityScore(0.4567)).toBe('46%');
    expect(formatSimilarityScore(1)).toBe('100%');
    expect(formatSimilarityScore(1.7)).toBe('100%');
    expect(formatSimilarityScore(-0.2)).toBe('0%');
    expect(formatSimilarityScore(null)).toBe('0%');
    expect(formatSimilarityScore(Number.NaN)).toBe('0%');
  });

  it('highlights strong matches without using risk colors', () => {
    expect(similarityScoreSeverity(0.1)).toBe('neutral');
    expect(similarityScoreSeverity(0.49)).toBe('neutral');
    expect(similarityScoreSeverity(0.5)).toBe('info');
    expect(similarityScoreSeverity(0.9)).toBe('info');
  });

  it('starts growth series one period before the first member of any series', () => {
    const point = (value: number) => ({ date: `d${value}`, value });
    const [first, second] = trimLeadingEmptyPeriods([
      [point(0), point(0), point(0), point(2), point(3)],
      [point(0), point(0), point(1), point(1), point(1)],
    ]);
    expect(first.map((p) => p.value)).toEqual([0, 0, 2, 3]);
    expect(second.map((p) => p.value)).toEqual([0, 1, 1, 1]);
    expect(trimLeadingEmptyPeriods([[point(4), point(5)]])[0].map((p) => p.value)).toEqual([4, 5]);
    expect(trimLeadingEmptyPeriods([[point(0), point(0)]])[0]).toHaveLength(2);
    expect(trimLeadingEmptyPeriods([])).toEqual([]);
  });

  it('knows which entity types carry a similarity profile', () => {
    expect(isGraphSimilarEntityType('Intrusion-Set')).toBe(true);
    expect(isGraphSimilarEntityType('Domain-Name')).toBe(true);
    expect(isGraphSimilarEntityType('Report')).toBe(true);
    expect(isGraphSimilarEntityType('Attack-Pattern')).toBe(false);
    expect(isGraphSimilarEntityType('StixFile')).toBe(false);
  });

  it('labels every evidence family returned by the platform', () => {
    ['techniques', 'tools', 'malware', 'infrastructure', 'victims', 'certificates', 'asn', 'registrar', 'nameservers', 'hosting', 'reports', 'objects']
      .forEach((family) => expect(GRAPH_FEATURE_FAMILY_LABELS[family]).toBeTruthy());
  });

  it('reports payload errors so failed actions stop before success handling', () => {
    expect(reportPayloadErrors(null)).toBe(false);
    expect(reportPayloadErrors([])).toBe(false);
    expect(notifyError).not.toHaveBeenCalled();
    expect(reportPayloadErrors([{ message: 'Graph cluster not found' }])).toBe(true);
    expect(notifyError).toHaveBeenCalledWith('Graph cluster not found');
  });

  it('collects the entities and relationships of paths without duplicates', () => {
    const ids = collectPathElementIds([
      { node_ids: ['a', 'b', 'c'], relationship_ids: ['r1', 'r2'] },
      { node_ids: ['a', 'd', 'c'], relationship_ids: ['r3', 'r4'] },
    ]);
    expect(ids).toEqual(['a', 'b', 'c', 'r1', 'r2', 'd', 'r3', 'r4']);
    expect(collectPathElementIds([])).toEqual([]);
  });

  it('draws the top hubs in ranking order, without entities that have no relationship', () => {
    const node = (id: string, degree: number | null) => ({
      id,
      entity_type: 'Intrusion-Set',
      representative: { main: `name ${id}` },
      x_opencti_graph_metrics: degree === null ? null : { degree },
    });
    const { series, redirectionUtils } = buildGraphTopHubsChart([node('a', 12), node('b', 3), node('c', 0), node('d', null)], 'Graph degree');
    expect(series).toEqual([{ name: 'Graph degree', data: [{ x: 'name a', y: 12 }, { x: 'name b', y: 3 }] }]);
    expect(redirectionUtils).toEqual([{ id: 'a', entity_type: 'Intrusion-Set' }, { id: 'b', entity_type: 'Intrusion-Set' }]);
    expect(buildGraphTopHubsChart([], 'Graph degree').redirectionUtils).toEqual([]);
  });
});
