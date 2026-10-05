import { describe, expect, it } from 'vitest';
import { SOURCE_WIDGET_METRICS } from '../../integrations/sources/sourceIntelligenceUtils';
import { metricAxisTitle, numberWidgetMetricKey, periodFromRange, toAggregation } from './sourcesWidgetUtils';

const NOW = new Date('2026-10-03T12:00:00.000Z').getTime();
const daysAgo = (days: number) => new Date(NOW - days * 24 * 3600 * 1000).toISOString();

describe('Sources widget utils', () => {
  it('should give every axis title its unit', () => {
    const t = (message: string, options?: { values?: Record<string, string | number> }) => message.replace(/\{(\w+)\}/g, (_, key) => String(options?.values?.[key] ?? ''));
    expect(metricAxisTitle(t, { label: 'Accuracy', type: 'ratio' })).toEqual('Accuracy (%)');
    expect(metricAxisTitle(t, { label: 'Impact score', type: 'score' })).toEqual('Impact score (0 to 100)');
    expect(metricAxisTitle(t, { label: 'Lead time (hours)', type: 'hours' })).toEqual('Lead time (hours)');
    expect(metricAxisTitle(t, { label: 'Volume', type: 'count' })).toEqual('Volume');
  });

  describe('periodFromRange', () => {
    it('should use the reference window without a time range', () => {
      expect(periodFromRange(null, null, NOW)).toBe('LAST_30_DAYS');
      expect(periodFromRange(undefined, daysAgo(1), NOW)).toBe('LAST_30_DAYS');
    });

    it('should pick the window covering the dashboard time range', () => {
      expect(periodFromRange(daysAgo(1), null, NOW)).toBe('LAST_7_DAYS');
      expect(periodFromRange(daysAgo(7), null, NOW)).toBe('LAST_7_DAYS');
      expect(periodFromRange(daysAgo(14), null, NOW)).toBe('LAST_30_DAYS');
      expect(periodFromRange(daysAgo(31), null, NOW)).toBe('LAST_30_DAYS');
      expect(periodFromRange(daysAgo(60), null, NOW)).toBe('LAST_90_DAYS');
      expect(periodFromRange(daysAgo(365), null, NOW)).toBe('LAST_90_DAYS');
    });

    it('should measure the range between the start and the end dates', () => {
      expect(periodFromRange(daysAgo(40), daysAgo(35), NOW)).toBe('LAST_7_DAYS');
      expect(periodFromRange(daysAgo(100), daysAgo(80), NOW)).toBe('LAST_30_DAYS');
    });

    it('should fall back to the reference window on an invalid range', () => {
      expect(periodFromRange('not a date', null, NOW)).toBe('LAST_30_DAYS');
      expect(periodFromRange(daysAgo(1), daysAgo(5), NOW)).toBe('LAST_30_DAYS');
      expect(periodFromRange(daysAgo(5), daysAgo(5), NOW)).toBe('LAST_30_DAYS');
    });
  });

  describe('toAggregation', () => {
    it('should keep a supported aggregation', () => {
      expect(toAggregation('sum', 'avg')).toBe('sum');
      expect(toAggregation('min', 'avg')).toBe('min');
      expect(toAggregation('max', 'avg')).toBe('max');
    });

    it('should fall back on an unknown or missing aggregation', () => {
      expect(toAggregation('median', 'avg')).toBe('avg');
      expect(toAggregation(null, 'sum')).toBe('sum');
      expect(toAggregation(undefined, 'max')).toBe('max');
    });
  });

  describe('numberWidgetMetricKey', () => {
    it('should query the selected metric of an aggregated number', () => {
      expect(numberWidgetMetricKey({ attribute: 'relevance', sort_mode: 'avg' })).toBe('relevance');
      expect(numberWidgetMetricKey({ attribute: 'accuracy', sort_mode: 'max' })).toBe('accuracy');
    });

    it('should query a Community Edition metric for a count, whatever metric the widget was saved with', () => {
      const key = numberWidgetMetricKey({ attribute: 'relevance', sort_mode: 'count' });
      expect(key).not.toBe('relevance');
      expect(SOURCE_WIDGET_METRICS.find((metric) => metric.key === key)?.enterprise).toBe(false);
    });
  });
});
