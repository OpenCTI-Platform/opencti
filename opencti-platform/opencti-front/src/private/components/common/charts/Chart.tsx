import React, { useMemo, useState } from 'react';
import ApexChart, { Props as ApexProps } from 'react-apexcharts';
import ApexCharts from 'apexcharts';
import ChartExportPopover from './ChartExportPopover';

interface OpenCTIChartProps extends ApexProps {
  withExportPopover?: boolean;
  isReadOnly?: boolean;
}

const Chart = ({
  options,
  series,
  type,
  width,
  height,
  withExportPopover,
  isReadOnly,
}: OpenCTIChartProps) => {
  const [chart, setChart] = useState<ApexCharts>();

  // Add in config a callback on 'mounted event' to retrieve chart context.
  // This context is used to export in different format.
  const apexOptions: ApexProps['options'] = useMemo(() => ({
    ...options,
    chart: {
      ...options?.chart,
      events: {
        ...options?.chart?.events,
        mounted(c) {
          setChart(c);
        },
      },
    },
  }), [options]);

  return (
    <>
      <ApexChart
        options={apexOptions}
        series={series}
        type={type}
        width={width}
        height={height}
      />
      {withExportPopover === true && (
        <ChartExportPopover
          chart={chart}
          series={series}
          isReadOnly={isReadOnly}
        />
      )}
    </>
  );
};

export default Chart;
