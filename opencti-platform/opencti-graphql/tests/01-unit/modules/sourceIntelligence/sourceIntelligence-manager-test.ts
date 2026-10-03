import { describe, expect, it } from 'vitest';
import '../../../../src/modules/index';
import { isFullComputationDue } from '../../../../src/manager/sourceIntelligenceManager';
import { buildIntelligenceRoiManifest, SCORECARD_METRICS } from '../../../../src/modules/sourceIntelligence/sourceIntelligence-widgets';
import { SCORECARD_NUMERIC_ATTRIBUTES } from '../../../../src/modules/sourceIntelligence/sourceIntelligence';

const settings = { recompute_hour_utc: 2 };

describe('Source intelligence manager scheduling', () => {
  it('should compute immediately when no full computation ever ran', () => {
    expect(isFullComputationDue({}, settings, Date.UTC(2026, 9, 3, 0, 30))).toBe(true);
  });

  it('should compute once a day after the configured hour', () => {
    const state = { last_full_run_day: '2026-10-02', last_full_run_start: '2026-10-02T02:00:00.000Z' };
    expect(isFullComputationDue(state, settings, Date.UTC(2026, 9, 3, 1, 59))).toBe(false);
    expect(isFullComputationDue(state, settings, Date.UTC(2026, 9, 3, 2, 0))).toBe(true);
    expect(isFullComputationDue({ ...state, last_full_run_day: '2026-10-03' }, settings, Date.UTC(2026, 9, 3, 10, 0))).toBe(false);
  });

  it('should honor a recomputation request made after the last run started', () => {
    const state = {
      last_full_run_day: '2026-10-03',
      last_full_run_start: '2026-10-03T02:00:00.000Z',
      recompute_requested_at: '2026-10-03T09:00:00.000Z',
    };
    expect(isFullComputationDue(state, settings, Date.UTC(2026, 9, 3, 10, 0))).toBe(true);
    expect(isFullComputationDue({ ...state, last_full_run_start: '2026-10-03T09:01:00.000Z' }, settings, Date.UTC(2026, 9, 3, 10, 0))).toBe(false);
  });
});

describe('Source intelligence dashboard widgets', () => {
  it('should only expose scorecard metrics that are stored on the scorecards', () => {
    const stored = new Set(SCORECARD_NUMERIC_ATTRIBUTES.map((attribute) => attribute.name));
    SCORECARD_METRICS.forEach((metric) => expect(stored.has(metric.key)).toBe(true));
  });

  it('should build the Intelligence ROI dashboard on the sources perspective', () => {
    const manifest = JSON.parse(Buffer.from(buildIntelligenceRoiManifest(), 'base64').toString('utf-8'));
    type ManifestWidget = { id: string; type: string; perspective: string; layout: { i: string }; dataSelection: Array<{ attribute: string; perspective: string }> };
    const widgets = Object.values(manifest.widgets) as ManifestWidget[];
    expect(widgets.length).toBeGreaterThanOrEqual(8);
    const metricKeys = new Set(SCORECARD_METRICS.map((metric) => metric.key));
    widgets.forEach((widget) => {
      expect(widget.perspective).toEqual('sources');
      expect(widget.layout.i).toEqual(widget.id);
      widget.dataSelection.forEach((selection) => {
        expect(selection.perspective).toEqual('sources');
        expect(metricKeys.has(selection.attribute as never)).toBe(true);
      });
    });
    expect(widgets.map((widget) => widget.type)).toEqual(expect.arrayContaining(['number', 'bubble', 'horizontal-bar', 'donut', 'list', 'line']));
    expect(manifest.config.relativeDate).toEqual('months-3');
  });
});
