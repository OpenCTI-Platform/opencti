import Chart, { OpenCTIChartProps } from '@components/common/charts/Chart';
import React, { useMemo } from 'react';
import { useTheme } from '@mui/styles';
import { ApexOptions } from 'apexcharts';
import { polarAreaChartOptions } from '../../utils/Charts';
import type { Theme } from '../Theme';
import useDistributionGraphData, { buildDistributionBuckets, DistributionQueryData } from '../../utils/hooks/useDistributionGraphData';
import { useNavigate } from 'react-router';
import type { WidgetDrilldown } from '../../utils/widget/drilldown/useWidgetDrilldown';

interface WidgetPolarAreaProps {
  data: DistributionQueryData;
  groupBy: string;
  onMounted?: OpenCTIChartProps['onMounted'];
  drilldown?: WidgetDrilldown;
}

const WidgetPolarArea = ({
  data,
  groupBy,
  onMounted,
  drilldown,
}: WidgetPolarAreaProps) => {
  const theme = useTheme<Theme>();
  const { buildWidgetLabelsOption, buildWidgetColorsOptions } = useDistributionGraphData();

  const navigate = useNavigate();
  /**
   * Memoized alongside the chart options: a fresh descriptor on every render
   * would rebuild the whole chart config.
   */
  const chartDrilldown = useMemo(
    () => (drilldown ? { ...drilldown, navigate, buckets: buildDistributionBuckets(data) } : undefined),
    [drilldown, navigate, data],
  );

  // `.map`, not `.flatMap`: dropping the empty buckets would shift every
  // following slice against the labels and the drill-down buckets, which are
  // both built with a full map. Same alignment invariant as Task 13.
  const chartData = useMemo(() => data.map((n) => (n ? (n.value ?? 0) : 0)), [data]);

  const options: ApexOptions = useMemo(() => {
    const labels = buildWidgetLabelsOption(data, groupBy);
    const colors = buildWidgetColorsOptions(data, groupBy);

    return polarAreaChartOptions(
      theme,
      labels,
      undefined,
      'bottom',
      colors,
      chartDrilldown,
    ) as ApexOptions;
  }, [data, groupBy, theme, chartDrilldown]);

  return (
    <Chart
      options={options}
      series={chartData}
      type="polarArea"
      width="100%"
      height="100%"
      onMounted={onMounted}
    />
  );
};

export default WidgetPolarArea;
