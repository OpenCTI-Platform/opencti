import { describe, expect, it } from 'vitest';
import { huntHitsTickAmount, huntPlatformSeries, huntVerdictData } from './HuntStatistics';
import type { Theme } from '../../../components/Theme';

describe('hunt statistics series', () => {
  const t = (key: string) => `t:${key}`;
  const statistics = {
    runs_per_platform: [{ label: 'Splunk prod', value: 3 }, { label: '', value: 1 }],
    verdict_distribution: [{ label: 'true_positive', value: 1 }, { label: 'benign', value: 4 }, { label: 'pending', value: 2 }, { label: 'inconclusive', value: 0 }],
  } as unknown as Parameters<typeof huntPlatformSeries>[0];

  it('should name the platforms the reader cannot see instead of showing an identifier', () => {
    const [series] = huntPlatformSeries(statistics, t) as unknown as { data: { x: string; y: number }[] }[];
    expect(series.data.map((point) => point.x)).toEqual(['Splunk prod', 't:Unavailable security platform']);
  });

  it('should colour each verdict slice with the tone of its chip', () => {
    const theme = { palette: { error: { main: 'error' }, success: { main: 'success' }, warn: { main: 'warn' }, text: { secondary: 'neutral' } } } as unknown as Theme;
    expect(huntVerdictData(statistics, t, theme).map((slice) => [slice.label, slice.entity?.color])).toEqual([
      ['t:True positive', 'error'],
      ['t:Benign', 'success'],
      ['t:Pending', 'neutral'],
    ]);
    // Pending is a mid grey in both themes, never the white or black of the text
    const palette = { ...theme.palette, common: { grey: 'dark-grey', lightGrey: 'light-grey' } };
    const pending = (mode: string) => huntVerdictData(statistics, t, { palette: { ...palette, mode } } as unknown as Theme)
      .find((slice) => slice.label === 't:Pending')?.entity?.color;
    expect(pending('dark')).toBe('dark-grey');
    expect(pending('light')).toBe('light-grey');
  });

  it('should label a daily series of more than two weeks once a week', () => {
    expect(huntHitsTickAmount(7)).toBeUndefined();
    expect(huntHitsTickAmount(14)).toBeUndefined();
    expect(huntHitsTickAmount(31)).toBe(5);
  });
});
