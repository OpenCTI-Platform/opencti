import React, { useMemo } from 'react';
import { useTheme } from '@mui/styles';
import type { ApexOptions } from 'apexcharts';
import Chart from '@components/common/charts/Chart';
import type { Theme } from '../../../../components/Theme';
import { useFormatter } from '../../../../components/i18n';
import { lineChartOptions } from '../../../../utils/Charts';
import { simpleNumberFormat } from '../../../../utils/Number';

// The first and last date labels are centred on the first and last points: without room they are cut by the plot edge
const EDGE_LABEL_PADDING = 32;

interface GraphClustersGrowthChartProps {
  series: ApexAxisChartSeries;
  interval: string;
  hasLegend?: boolean;
}

/**
 * Cumulative members of clusters over time. Drawn as lines: an area closes on the axis after its last point,
 * which reads as a drop of the cluster size.
 */
const GraphClustersGrowthChart = ({ series, interval, hasLegend = true }: GraphClustersGrowthChartProps) => {
  const theme = useTheme<Theme>();
  const { fsd, mtdy, yd } = useFormatter();
  const options = useMemo(() => {
    let formatter = fsd;
    if (interval === 'month' || interval === 'quarter') formatter = mtdy;
    if (interval === 'year') formatter = yd;
    const isTimeSeries = ['day', 'week'].includes(interval);
    const base = lineChartOptions(theme, isTimeSeries, formatter, simpleNumberFormat, isTimeSeries ? undefined : 'dataPoints', false, hasLegend) as ApexOptions;
    return { ...base, grid: { ...base.grid, padding: { left: EDGE_LABEL_PADDING, right: EDGE_LABEL_PADDING } } };
  }, [theme, interval, hasLegend]);
  return <Chart options={options} series={series} type="line" width="100%" height="100%" />;
};

export default GraphClustersGrowthChart;
