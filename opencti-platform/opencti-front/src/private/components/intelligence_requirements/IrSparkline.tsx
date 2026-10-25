import React from 'react';
import type { ApexOptions } from 'apexcharts';
import { useTheme } from '@mui/material/styles';
import Chart from '@components/common/charts/Chart';
import type { Theme } from '../../../components/Theme';

// Entities entering the requirement per day, drawn as a small area line.

interface IrSparklineProps {
  points: readonly { readonly value: number }[];
  width?: number | string;
  height?: number;
}

const IrSparkline = ({ points, width = 120, height = 32 }: IrSparklineProps) => {
  const theme = useTheme<Theme>();
  const options: ApexOptions = {
    chart: { type: 'area', sparkline: { enabled: true }, animations: { enabled: false } },
    stroke: { curve: 'straight', width: 1.5 },
    fill: { type: 'gradient', gradient: { shadeIntensity: 1, opacityFrom: 0.35, opacityTo: 0, stops: [0, 100] } },
    colors: [theme.palette.primary.main],
    tooltip: { enabled: false },
  };
  return <Chart type="area" options={options} series={[{ name: 'entered', data: points.map((p) => p.value) }]} width={width} height={height} />;
};

export default IrSparkline;
