import { describe, expect, it } from 'vitest';
import { testRenderHook } from '../tests/test-render';
import useDistributionGraphData from './useDistributionGraphData';

describe('Hook: useDistributionGraphData', () => {
  const data = [{ label: 'True_positive', value: 2 }, { label: 'Pending', value: 5 }];

  it('should name the hunt values a widget breaks down on in every chart', () => {
    const { hook } = testRenderHook(() => useDistributionGraphData());
    const { buildWidgetLabelsOption, buildWidgetWordCloudOption, buildWidgetProps } = hook.result.current;
    expect(buildWidgetLabelsOption(data, 'verdict')).toEqual(['True positive', 'Pending']);
    expect(buildWidgetWordCloudOption(data, 'verdict').map(({ text }) => text)).toEqual(['True positive', 'Pending']);
    const { series } = buildWidgetProps(data, { attribute: 'verdict' }, 'Number of runs');
    expect(series[0].data.map(({ x }) => x)).toEqual(['True positive', 'Pending']);
  });

  it('should keep the values of the other attributes as returned', () => {
    const { hook } = testRenderHook(() => useDistributionGraphData());
    expect(hook.result.current.buildWidgetLabelsOption(data, 'incident_type')).toEqual(['True_positive', 'Pending']);
  });
});
