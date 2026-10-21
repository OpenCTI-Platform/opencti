import { describe, expect, it } from 'vitest';
import {
  buildHubCoverageSearchUrl,
  buildOverlapHeatmapSeries,
  buildTrendSerie,
  criterionPriority,
  escapeHtml,
  findSourceWidgetMetric,
  formatCost,
  formatCount,
  formatHours,
  formatMetric,
  formatRatio,
  formatScore,
  oneClickDeployBlocker,
  parseJsonObject,
  periodStartDate,
  recommendationActionCapability,
  scoreLevel,
  sourceEditCostLink,
  sourceWidgetMetricsFor,
} from './sourceIntelligenceUtils';

describe('Source intelligence links and priorities', () => {
  it('should search the XTM Hub integrations covering a collection gap', () => {
    const url = new URL(buildHubCoverageSearchUrl('https://hub.example.com/', 'platform-1', {
      object_types: ['Malware', 'Indicator'],
      sectors: ['Retail, consumer goods'],
      regions: [],
    }));
    expect(url.origin + url.pathname).toEqual('https://hub.example.com/redirect/opencti_integrations');
    expect(url.searchParams.get('platform_id')).toEqual('platform-1');
    expect(url.searchParams.get('objectType')).toEqual('Indicator,Malware');
    // Free-text values keep their commas
    expect(JSON.parse(url.searchParams.get('sector') as string)).toEqual(['Retail, consumer goods']);
    expect(url.searchParams.has('region')).toBe(false);
  });

  it('should rank a criterion against the other criteria of its PIR', () => {
    expect(criterionPriority(3, [1, 2, 3])).toEqual('high');
    expect(criterionPriority(2, [1, 2, 3])).toEqual('medium');
    expect(criterionPriority(1, [1, 2, 3])).toEqual('low');
    // Criteria of equal weight have no priority to show
    expect(criterionPriority(1, [1, 1])).toBeNull();
    expect(criterionPriority(1, [])).toBeNull();
  });

  it('should open the cost editor of a source', () => {
    expect(sourceEditCostLink('source-1')).toEqual('/dashboard/integrations/sources/source/source-1?edit=cost');
  });
});

describe('Source widget metrics', () => {
  it('should not plot a signed metric as the parts of a donut', () => {
    expect(sourceWidgetMetricsFor('donut').map((metric) => metric.key)).not.toContain('lead_time_hours');
    expect(sourceWidgetMetricsFor('horizontal-bar').map((metric) => metric.key)).toContain('lead_time_hours');
    // A donut saved with a signed metric plots the default metric, like an unknown one
    expect(findSourceWidgetMetric('lead_time_hours', 'donut').key).toEqual('value_score');
    expect(findSourceWidgetMetric('lead_time_hours', 'horizontal-bar').key).toEqual('lead_time_hours');
    expect(findSourceWidgetMetric('noise_count', 'donut').key).toEqual('noise_count');
    expect(findSourceWidgetMetric('unknown_metric').key).toEqual('value_score');
    // Nor as the size of a bubble, while it stays available on the bubble axes
    expect(sourceWidgetMetricsFor('bubble-size').map((metric) => metric.key)).not.toContain('lead_time_hours');
    expect(sourceWidgetMetricsFor('bubble').map((metric) => metric.key)).toContain('lead_time_hours');
  });
});

describe('Source intelligence utils', () => {
  describe('formatters', () => {
    it('should format ratios as percents', () => {
      expect(formatRatio(0.1234)).toEqual('12.3 %');
      expect(formatRatio(1)).toEqual('100.0 %');
      expect(formatRatio(null)).toEqual('-');
      expect(formatRatio(Number.NaN)).toEqual('-');
    });

    it('should format hours and switch to days after two days', () => {
      expect(formatHours(5.25)).toEqual('5.3 h');
      expect(formatHours(-3)).toEqual('-3.0 h');
      expect(formatHours(72)).toEqual('3.0 d');
      expect(formatHours(-96)).toEqual('-4.0 d');
      expect(formatHours(undefined)).toEqual('-');
    });

    it('should format scores, counts and costs', () => {
      expect(formatScore(67.6)).toEqual('68');
      expect(formatCount(950)).toEqual('950');
      expect(formatCount(12500)).toEqual('12.5K');
      expect(formatCount(3400000)).toEqual('3.4M');
      expect(formatCost(0.01234, 'EUR')).toEqual('0.0123 EUR');
      expect(formatCost(12.5, 'USD')).toEqual('12.50 USD');
      expect(formatCost(1500, null)).toEqual('1500');
    });

    it('should format a metric according to its type', () => {
      expect(formatMetric(0.5, 'ratio')).toEqual('50.0 %');
      expect(formatMetric(12, 'hours')).toEqual('12.0 h');
      expect(formatMetric(2, 'cost', 'EUR')).toEqual('2.00 EUR');
      expect(formatMetric(42.4, 'score')).toEqual('42');
      expect(formatMetric(1200, 'count')).toEqual('1.2K');
    });
  });

  describe('scoreLevel()', () => {
    it('should classify ratios and scores', () => {
      expect(scoreLevel(0.9)).toEqual('good');
      expect(scoreLevel(0.5)).toEqual('average');
      expect(scoreLevel(0.1)).toEqual('poor');
      expect(scoreLevel(80, { scale: 100 })).toEqual('good');
      expect(scoreLevel(null)).toEqual('unknown');
    });

    it('should invert the level when lower is better', () => {
      expect(scoreLevel(0.9, { higherIsBetter: false })).toEqual('poor');
      expect(scoreLevel(0.05, { higherIsBetter: false })).toEqual('good');
    });
  });

  describe('escapeHtml()', () => {
    it('should neutralize markup coming from source names', () => {
      expect(escapeHtml('<img src=x onerror="alert(1)">')).toEqual('&lt;img src=x onerror=&quot;alert(1)&quot;&gt;');
      expect(escapeHtml("Feed & 'Co'")).toEqual('Feed &amp; &#39;Co&#39;');
      expect(escapeHtml(null)).toEqual('');
      expect(escapeHtml(42)).toEqual('42');
    });
  });

  describe('parseJsonObject()', () => {
    it('should parse objects and ignore anything else', () => {
      expect(parseJsonObject('{"a":1}')).toEqual({ a: 1 });
      expect(parseJsonObject('[1,2]')).toEqual({});
      expect(parseJsonObject('not json')).toEqual({});
      expect(parseJsonObject(null)).toEqual({});
    });
  });

  describe('buildOverlapHeatmapSeries()', () => {
    const sources = [{ id: 'a', name: 'Source A' }, { id: 'b', name: 'Source B' }, { id: 'c', name: 'Source C' }];

    it('should build an asymmetric matrix with an empty diagonal', () => {
      const series = buildOverlapHeatmapSeries(sources, [
        { source_a: 'a', source_b: 'b', shared_count: 50, share_a: 0.5, share_b: 0.25, jaccard: 0.2 },
      ]);
      // Rows are reversed: the heatmap draws the first serie at the bottom
      expect(series.map((serie) => serie.name)).toEqual(['Source C', 'Source B', 'Source A']);
      const rowA = series.find((serie) => serie.name === 'Source A');
      const rowB = series.find((serie) => serie.name === 'Source B');
      expect(rowA?.data).toEqual([
        { x: 'Source A', y: null, sharedCount: 0, measured: true },
        { x: 'Source B', y: 50, sharedCount: 50, measured: true },
        { x: 'Source C', y: 0, sharedCount: 0, measured: true },
      ]);
      expect(rowB?.data[0]).toEqual({ x: 'Source A', y: 25, sharedCount: 50, measured: true });
    });

    it('should leave a pair not measured empty instead of reading it as no overlap', () => {
      const series = buildOverlapHeatmapSeries(sources, [
        { source_a: 'a', source_b: 'b', shared_count: 50, share_a: 0.5, share_b: 0.25, jaccard: 0.2, measured: true },
        { source_a: 'b', source_b: 'c', shared_count: 0, share_a: 0, share_b: 0, jaccard: 0, measured: false },
      ]);
      const rowB = series.find((serie) => serie.name === 'Source B');
      const rowC = series.find((serie) => serie.name === 'Source C');
      expect(rowB?.data[2]).toEqual({ x: 'Source C', y: null, sharedCount: 0, measured: false });
      expect(rowC?.data[1]).toEqual({ x: 'Source B', y: null, sharedCount: 0, measured: false });
      // A pair absent from the cells is a measured zero
      expect(rowC?.data[0]).toEqual({ x: 'Source A', y: 0, sharedCount: 0, measured: true });
    });
  });

  describe('buildTrendSerie()', () => {
    it('should keep one point per day with the live scorecard last and ratios in percents', () => {
      const serie = buildTrendSerie([
        { scorecard_date: '2026-10-02', is_live: true, accuracy: 0.9 },
        { scorecard_date: '2026-10-01', is_live: false, accuracy: 0.5 },
        { scorecard_date: '2026-10-02', is_live: false, accuracy: 0.8 },
        { scorecard_date: '2026-09-30', is_live: false, accuracy: null },
      ], 'accuracy', 'ratio');
      expect(serie).toEqual([
        { x: '2026-10-01T00:00:00.000Z', y: 50 },
        { x: '2026-10-02T00:00:00.000Z', y: 90 },
      ]);
    });

    it('should keep raw values for counts', () => {
      expect(buildTrendSerie([{ scorecard_date: '2026-10-01', is_live: false, volume_total: 12 }], 'volume_total', 'count'))
        .toEqual([{ x: '2026-10-01T00:00:00.000Z', y: 12 }]);
    });
  });

  describe('periodStartDate()', () => {
    it('should compute the start of the period', () => {
      const now = new Date('2026-10-31T00:00:00.000Z').getTime();
      expect(periodStartDate('LAST_30_DAYS', now)).toEqual('2026-10-01T00:00:00.000Z');
      expect(periodStartDate('LAST_7_DAYS', now)).toEqual('2026-10-24T00:00:00.000Z');
    });
  });

  describe('recommendationActionCapability', () => {
    it('should require the capability of the change each kind and target makes', () => {
      expect(recommendationActionCapability('raise_confidence', {})).toBe('SETTINGS_SETACCESSES');
      expect(recommendationActionCapability('lower_confidence', {})).toBe('SETTINGS_SETACCESSES');
      expect(recommendationActionCapability('quarantine', { target: 'connector_user' })).toBe('SETTINGS_SETACCESSES');
      expect(recommendationActionCapability('quarantine', { target: 'ingestion_feed' })).toBe('INGESTION_SETINGESTIONS');
      expect(recommendationActionCapability('add_decay_rule', {})).toBe('SETTINGS_SETCUSTOMIZATION');
      expect(recommendationActionCapability('add_deny_list', {})).toBe('SETTINGS_SETCUSTOMIZATION');
      expect(recommendationActionCapability('retire', { target: 'ingestion_feed' })).toBe('INGESTION_SETINGESTIONS');
      expect(recommendationActionCapability('retire', { target: 'connector' })).toBe('MODULES_MODMANAGE');
      expect(recommendationActionCapability('change_schedule', { target: 'ingestion_feed' })).toBe('INGESTION_SETINGESTIONS');
      expect(recommendationActionCapability('change_schedule', { target: 'connector' })).toBe('MODULES_MODMANAGE');
      expect(recommendationActionCapability('add_connector', {})).toBe('MODULES_MODMANAGE');
    });
  });
});

describe('oneClickDeployBlocker', () => {
  const deployable = { inLocalCatalog: true, managerSupported: true, canDeploy: true, hasRegisteredManager: true, settingsCollectable: true };

  it('should offer the one-click deployment when nothing prevents it', () => {
    expect(oneClickDeployBlocker(deployable)).toBeNull();
    expect(oneClickDeployBlocker({ ...deployable, hasRegisteredManager: null })).toBeNull();
  });

  it('should say why the one-click deployment is not offered, the catalog first', () => {
    expect(oneClickDeployBlocker({ ...deployable, inLocalCatalog: false, canDeploy: false })).toContain('not in the local catalog');
    expect(oneClickDeployBlocker({ ...deployable, managerSupported: false })).toContain('XTM Composer cannot run this connector');
    expect(oneClickDeployBlocker({ ...deployable, canDeploy: false })).toContain('capability to manage connectors');
    expect(oneClickDeployBlocker({ ...deployable, hasRegisteredManager: false })).toContain('No connector manager is registered');
    expect(oneClickDeployBlocker({ ...deployable, settingsCollectable: false })).toContain('set on its catalog page');
  });
});
