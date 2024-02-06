import Chart from '@components/common/charts/Chart';
import React from 'react';
import { useTheme } from '@mui/styles';
import { ApexOptions } from 'apexcharts';
import { heatMapOptions } from '../../utils/Charts';
import { useFormatter } from '../i18n';
import type { Theme } from '../Theme';

const darkColors = [
  '#001e3c',
  '#023362',
  '#02407a',
  '#045198',
  '#0561b4',
  '#0b75d9',
  '#2986e7',
  '#3a95f3',
  '#4da3ff',
  '#76bbff',
  '#9eccff',
];

const lightColors = [
  '#f3f6f9',
  '#76bbff',
  '#4da3ff',
  '#3a95f3',
  '#2986e7',
  '#0b75d9',
  '#0561b4',
  '#02407a',
  '#023362',
  '#001e3c',
  '#021428',
];

interface WidgetMultiHeatMapProps {
  data: any[]
  minValue: number
  maxValue: number
  isStacked?: boolean
  withExport?: boolean
  readonly?: boolean
}

const WidgetMultiHeatMap = ({
  data,
  minValue,
  maxValue,
  isStacked = false,
  withExport = false,
  readonly = false,
}: WidgetMultiHeatMapProps) => {
  const theme = useTheme<Theme>();
  const { fsd } = useFormatter();

  const interval = Math.trunc((maxValue - minValue) / 9);
  const colorRanges = Array(10)
    .fill(0)
    .map((_, i) => ({
      from:
        minValue + (i + 1) * interval - interval === 0
          ? 1
          : minValue + (i + 1) * interval - interval,
      to: minValue + (i + 1) * interval,
      color:
        theme.palette.mode === 'dark'
          ? darkColors[i + 1]
          : lightColors[i + 1],
    }));
  colorRanges.push({
    from: 0,
    to: 0,
    color:
      theme.palette.mode === 'dark' ? darkColors[0] : lightColors[0],
  });

  return (
    <Chart
      options={heatMapOptions(
        theme,
        true,
        fsd,
        undefined,
        undefined,
        isStacked,
        colorRanges,
      ) as ApexOptions}
      series={data}
      type="heatmap"
      width="100%"
      height="100%"
      withExportPopover={withExport}
      isReadOnly={readonly}
    />
  );
};

export default WidgetMultiHeatMap;
