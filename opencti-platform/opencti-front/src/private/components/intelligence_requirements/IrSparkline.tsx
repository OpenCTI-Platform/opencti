import React from 'react';
import type { ApexOptions } from 'apexcharts';
import { useTheme } from '@mui/material/styles';
import Chart from '@components/common/charts/Chart';
import type { Theme } from '../../../components/Theme';

// Entities entering the requirement per day, drawn as a small smoothed line with a dot per day (the last one larger).

interface IrSparklineProps {
  points: readonly { readonly value: number }[];
  width?: number | string;
  height?: number;
}

const IrSparkline = ({ points, width = 120, height = 32 }: IrSparklineProps) => {
  const theme = useTheme<Theme>();
  const color = theme.palette.primary.main ?? '#0fbcff';
  const last = points.length - 1;
  const options: ApexOptions = {
    chart: { type: 'line', sparkline: { enabled: true }, animations: { enabled: false } },
    stroke: { curve: 'smooth', width: 2 },
    colors: [color],
    markers: {
      size: 3,
      strokeWidth: 0,
      hover: { size: 4 },
      discrete: last >= 0 ? [{ seriesIndex: 0, dataPointIndex: last, size: 4.5, fillColor: color, strokeColor: color }] : [],
    },
    // A few pixels of margin so that the dots at both ends are not cut
    grid: { padding: { top: 5, bottom: 5, left: 5, right: 5 } },
    tooltip: { enabled: false },
  };
  return <Chart type="line" options={options} series={[{ name: 'entered', data: points.map((p) => p.value) }]} width={width} height={height} />;
};

export default IrSparkline;
