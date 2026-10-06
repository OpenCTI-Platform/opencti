import { useTheme } from '@mui/styles';
import Chart, { OpenCTIChartProps } from '@components/common/charts/Chart';
import { ApexOptions } from 'apexcharts';
import React, { useMemo } from 'react';
import type { Theme } from '../Theme';
import { useFormatter } from '../i18n';
import { areaChartOptions } from '../../utils/Charts';
import { simpleNumberFormat } from '../../utils/Number';
import { useNavigate } from 'react-router';
import type { WidgetDrilldown } from '../../utils/widget/drilldown/useWidgetDrilldown';

interface WidgetMultiAreasProps {
  series: ApexAxisChartSeries;
  interval?: string | null;
  isStacked?: boolean;
  hasLegend?: boolean;
  onMounted?: OpenCTIChartProps['onMounted'];
  drilldown?: WidgetDrilldown;
}

const WidgetMultiAreas = ({
  series,
  interval,
  isStacked = false,
  hasLegend = false,
  onMounted,
  drilldown,
}: WidgetMultiAreasProps) => {
  const theme = useTheme<Theme>();
  const { fsd, mtdy, yd } = useFormatter();

  /**
 * The chart options are memoized, so the navigate-carrying descriptor must be
 * too: a fresh object on every render would rebuild the whole chart config.
 */
  const navigate = useNavigate();
  const chartDrilldown = useMemo(
    () => (drilldown ? { ...drilldown, navigate } : undefined),
    [drilldown, navigate],
  );

  const options: ApexOptions = useMemo(() => {
    let formatter = fsd;
    if (interval === 'month' || interval === 'quarter') {
      formatter = mtdy;
    }
    if (interval === 'year') {
      formatter = yd;
    }

    return areaChartOptions(
      theme,
      !interval || ['day', 'week'].includes(interval),
      formatter,
      simpleNumberFormat,
      interval && !['day', 'week'].includes(interval) ? 'dataPoints' : undefined,
      isStacked,
      hasLegend,
      chartDrilldown,
    ) as ApexOptions;
  }, [theme, interval, isStacked, hasLegend, chartDrilldown]);

  return (
    <Chart
      options={options}
      series={series}
      type="area"
      width="100%"
      height="100%"
      onMounted={onMounted}
    />
  );
};

export default WidgetMultiAreas;
