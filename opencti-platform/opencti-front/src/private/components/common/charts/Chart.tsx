import { useMemo } from 'react';
import ApexChart, { Props as ApexProps } from 'react-apexcharts';
import ApexCharts from 'apexcharts';

export interface OpenCTIChartProps extends ApexProps {
  onMounted?: (chart: ApexCharts) => void;
}

const Chart = ({
  options,
  series,
  type,
  width,
  height,
  onMounted,
}: OpenCTIChartProps) => {
  // Add in config a callback on 'mounted event' to retrieve chart context.
  // This context is used to export in different format.
  const apexOptions: ApexProps['options'] = useMemo(() => ({
    ...options,
    chart: {
      ...options?.chart,
      events: {
        ...options?.chart?.events,
        mounted: onMounted,
      },
    },
  }), [options]);

  return (
    <ApexChart
      options={apexOptions}
      series={series}
      type={type}
      width={width}
      height={height}
    />
  );
};

export default Chart;
