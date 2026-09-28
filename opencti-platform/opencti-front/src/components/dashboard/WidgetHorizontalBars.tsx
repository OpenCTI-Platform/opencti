import Chart, { OpenCTIChartProps } from '@components/common/charts/Chart';
import React, { useMemo } from 'react';
import { useTheme } from '@mui/styles';
import { useNavigate } from 'react-router';
import { ApexOptions } from 'apexcharts';
import { horizontalBarsChartOptions } from '../../utils/Charts';
import { simpleNumberFormat } from '../../utils/Number';
import type { Theme } from '../Theme';
import { dateFormat, timestamp } from '../../utils/Time';
import type { DrilldownBucket } from '../../utils/widget/drilldown/widgetDrilldown-types';
import type { WidgetDrilldown } from '../../utils/widget/drilldown/useWidgetDrilldown';

interface WidgetHorizontalBarsProps {
  series: ApexAxisChartSeries;
  distributed?: boolean;
  stacked?: boolean;
  total?: boolean;
  legend?: boolean;
  categories?: string[];
  /**
   * One entry per bucket, `null` where the bucket resolves to no entity.
   * The gaps are what keeps the array aligned with the bars ApexCharts reports
   * by index — see `buildDistributionRedirectionUtils`.
   */
  redirectionUtils?: ({
    id?: string;
    entity_type?: string;
  } | null)[];
  stackType?: string;
  onMounted?: OpenCTIChartProps['onMounted'];
  drilldown?: WidgetDrilldown;
  /**
   * The drill-down buckets, aligned with the bars by index. Unlike the other
   * distribution widgets this one never sees the raw query nodes, so the
   * container has to hand them over -- `buildWidgetProps` returns them.
   */
  drilldownBuckets?: (DrilldownBucket | null)[];
}

const WidgetHorizontalBars = ({
  series,
  distributed,
  stacked,
  total,
  legend,
  categories,
  redirectionUtils,
  stackType,
  onMounted,
  drilldown,
  drilldownBuckets,
}: WidgetHorizontalBarsProps) => {
  const theme = useTheme<Theme>();
  const navigate = useNavigate();

  const chartDrilldown = useMemo(
    () => (drilldown ? { ...drilldown, navigate, buckets: drilldownBuckets ?? [] } : undefined),
    [drilldown, navigate, drilldownBuckets],
  );

  const options: ApexOptions = useMemo(() => {
    const getFormattedValue = (value: string | number) => {
      if (typeof value === 'number') {
        return simpleNumberFormat(value);
      }
      const newTimestamp = parseInt(value, 10);
      if (!Number.isNaN(newTimestamp)) {
        const convertedDate = timestamp(newTimestamp);
        const date = dateFormat(convertedDate);
        if (date) return date;
      }
      return value;
    };

    return horizontalBarsChartOptions(
      theme,
      true,
      simpleNumberFormat,
      getFormattedValue,
      distributed,
      navigate,
      redirectionUtils,
      stacked,
      total,
      categories,
      legend,
      stackType,
      chartDrilldown,
    ) as ApexOptions;
  }, [
    theme,
    categories,
    distributed,
    legend,
    redirectionUtils,
    stacked,
    stackType,
    total,
    chartDrilldown,
  ]);

  return (
    <Chart
      options={options}
      series={series}
      type="bar"
      width="100%"
      height="100%"
      onMounted={onMounted}
    />
  );
};

export default WidgetHorizontalBars;
