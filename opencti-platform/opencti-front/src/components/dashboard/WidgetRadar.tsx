import Chart, { OpenCTIChartProps } from '@components/common/charts/Chart';
import React, { useMemo } from 'react';
import { useTheme } from '@mui/styles';
import { ApexOptions } from 'apexcharts';
import { radarChartOptions } from '../../utils/Charts';
import { useFormatter } from '../i18n';
import type { Theme } from '../Theme';
import useDistributionGraphData, { buildDistributionBuckets } from '../../utils/hooks/useDistributionGraphData';
import { useNavigate } from 'react-router';
import type { WidgetDrilldown } from '../../utils/widget/drilldown/useWidgetDrilldown';
import { simpleNumberFormat } from '../../utils/Number';

interface WidgetRadarProps {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  data: readonly any[];
  label: string;
  groupBy: string;
  onMounted?: OpenCTIChartProps['onMounted'];
  drilldown?: WidgetDrilldown;
}

const WidgetRadar = ({
  data,
  label,
  groupBy,
  onMounted,
  drilldown,
}: WidgetRadarProps) => {
  const theme = useTheme<Theme>();
  const { t_i18n } = useFormatter();
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

  const chartData = useMemo(() => [{
    name: label || t_i18n('Number of relationships'),
    data: data.map((n) => n.value),
  }], [data, label]);

  const options = useMemo<ApexOptions>(() => {
    const labels = buildWidgetLabelsOption(data, groupBy);
    // @ts-expect-error fixed when Charts in tsx
    return radarChartOptions(
      theme,
      labels,
      simpleNumberFormat,
      [],
      true,
      undefined,
      undefined,
      undefined,
      chartDrilldown,
    ) as ApexOptions;
  }, [data, groupBy, theme, chartDrilldown]);

  return (
    <Chart
      options={options}
      series={chartData}
      type="radar"
      width="100%"
      height="100%"
      onMounted={onMounted}
    />
  );
};

export default WidgetRadar;
