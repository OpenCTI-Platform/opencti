import Chart from '@components/common/charts/Chart';
import React from 'react';
import { useTheme } from '@mui/material/styles';
import type { Theme } from '../../../../components/Theme';

interface PirRadialScoreProps {
  value: number
}

const PirRadialScore = ({ value }: PirRadialScoreProps) => {
  const theme = useTheme<Theme>();

  return (
    <Chart
      options={{
        plotOptions: {
          radialBar: {
            startAngle: -100,
            endAngle: 100,
            offsetX: -17,
            offsetY: -10,
            hollow: {
              size: '35%',
            },
            track: {
              show: true,
              background: theme.palette.background.accent,
            },
            dataLabels: {
              name: {
                show: false,
              },
              value: {
                color: theme.palette.text?.primary,
                offsetY: 4,
                formatter: (val: number) => `${val}`,
              },
            },
          },
        },
        colors: ['#8ac926'],
        fill: {
          type: 'gradient',
          gradient: {
            shade: 'dark',
            type: 'horizontal',
            gradientToColors: ['#f3722c'],
            stops: [0, 100],
          },
        },
        stroke: {
          lineCap: 'round',
        },
      }}
      series={[value]}
      type="radialBar"
      width="80px"
      height="80px"
    />
  );
};

export default PirRadialScore;
