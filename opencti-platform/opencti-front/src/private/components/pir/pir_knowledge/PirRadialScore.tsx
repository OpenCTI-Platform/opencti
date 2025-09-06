/*
Copyright (c) 2021-2025 Filigran SAS

This file is part of the OpenCTI Enterprise Edition ("EE") and is
licensed under the OpenCTI Enterprise Edition License (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

https://github.com/OpenCTI-Platform/opencti/blob/master/LICENSE

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
*/

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
