import React, { useRef } from 'react';
import ApexChart, { Props } from 'react-apexcharts';
import type ReactApexChart from 'react-apexcharts';
import ExportPopover from './ExportPopover';

interface OpenCTIChartProps extends Props {
  withExportPopover?: boolean
}

const Chart = ({ options, series, type, width, height, withExportPopover }: OpenCTIChartProps) => {
  const chartRef = useRef<ReactApexChart>(null);
  return <>
        <ApexChart ref={chartRef} options={options} series={series} type={type} width={width} height={height}/>
        { withExportPopover === true && <ExportPopover chartRef={chartRef} chartData={series}/> }
    </>;
};

export default Chart;
