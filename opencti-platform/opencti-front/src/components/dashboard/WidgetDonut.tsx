import Chart, { OpenCTIChartProps } from '@components/common/charts/Chart';
import React, { useMemo } from 'react';
import { useTheme } from '@mui/styles';
import type { ApexOptions } from 'apexcharts';
import { donutChartOptions } from '../../utils/Charts';
import type { Theme } from '../Theme';
import useDistributionGraphData, { buildDistributionBuckets } from '../../utils/hooks/useDistributionGraphData';
import { useNavigate } from 'react-router';
import type { WidgetDrilldown } from '../../utils/widget/drilldown/useWidgetDrilldown';

interface WidgetDonutProps {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  data: readonly any[];
  groupBy: string;
  onMounted?: OpenCTIChartProps['onMounted'];
  drilldown?: WidgetDrilldown;
}

const WidgetDonut = ({
  data,
  groupBy,
  onMounted,
  drilldown,
}: WidgetDonutProps) => {
  const theme = useTheme<Theme>();
  const { buildWidgetLabelsOption } = useDistributionGraphData();

  const navigate = useNavigate();
  /**
   * Memoized alongside the chart options: a fresh descriptor on every render
   * would rebuild the whole chart config.
   */
  const chartDrilldown = useMemo(
    () => (drilldown ? { ...drilldown, navigate, buckets: buildDistributionBuckets(data) } : undefined),
    [drilldown, navigate, data],
  );

  const chartData = useMemo(() => data.map((n) => n.value), [data]);

  const options: ApexOptions = useMemo(() => {
    const labels = buildWidgetLabelsOption(data, groupBy);
    let chartColors: (string | undefined)[] = [];
    if (data.at(0)?.entity?.color) {
      chartColors = data.map((n) => (theme.palette.mode === 'light' && n.entity?.color === '#ffffff'
        ? '#000000'
        : n.entity?.color));
    }
    if (data.at(0)?.entity?.x_opencti_color) {
      chartColors = data.map((n) => (theme.palette.mode === 'light' && n.entity?.x_opencti_color === '#ffffff'
        ? '#000000'
        : n.entity?.x_opencti_color));
    }
    if (data.at(0)?.entity?.template?.color) {
      chartColors = data.map((n) => (theme.palette.mode === 'light' && n.entity?.template.color === '#ffffff'
        ? '#000000'
        : n.entity?.template.color));
    }

    return donutChartOptions(
      theme,
      labels,
      'bottom',
      false,
      chartColors.filter((o): o is string => !!o),
      true,
      true,
      true,
      true,
      70,
      true,
      chartDrilldown,
    ) as ApexOptions;
  }, [data, groupBy, theme, chartDrilldown]);

  return (
    <Chart
      options={options}
      series={chartData}
      type="donut"
      width="100%"
      height="100%"
      onMounted={onMounted}
    />
  );
};

export default WidgetDonut;
