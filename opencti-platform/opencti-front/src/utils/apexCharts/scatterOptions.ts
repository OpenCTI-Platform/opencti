import { ApexOptions } from 'apexcharts';
import { daysAgo, now } from '../Time';
import { colors } from '../Charts';
import type { Theme } from '../../components/Theme';
import type { ApexChartEvents, ApexChartLabels } from './apex';

export interface ScatterChartOptionsArgs {
  theme: Theme,
  background?: string
  dataPointMouseEnter?: ApexChartEvents['dataPointMouseEnter']
  dataPointMouseLeave?: ApexChartEvents['dataPointMouseLeave']
  labelsFormatter?: ApexChartLabels['formatter']
}

export const scatterChartOptions = ({
  theme,
  background,
  dataPointMouseEnter,
  dataPointMouseLeave,
  labelsFormatter,
}: ScatterChartOptionsArgs): ApexOptions => ({
  chart: {
    type: 'scatter',
    background,
    toolbar: {
      show: false,
    },
    events: {
      dataPointMouseEnter,
      dataPointMouseLeave,
    },
    foreColor: theme.palette.text?.secondary,
    width: '100%',
    height: '100%',
    zoom: {
      enabled: false,
    },
  },
  theme: {
    mode: theme.palette.mode,
  },
  dataLabels: {
    enabled: true,
    offsetY: 1,
    background: {
      enabled: false,
    },
    style: {
      colors: ['#000000'],
    },
    formatter: labelsFormatter,
  },
  colors: [
    theme.palette.primary.main,
    ...colors(theme.palette.mode === 'dark' ? 400 : 600),
  ],
  states: {
    hover: {
      filter: {
        type: 'lighten',
      },
    },
  },
  grid: {
    show: false,
  },
  legend: {
    show: false,
  },
  tooltip: {
    enabled: false,
  },
  xaxis: {
    type: 'datetime',
    min: new Date(daysAgo(7)).getTime(),
    max: new Date(now()).getTime(),
    labels: {
      show: false,
    },
    axisBorder: {
      show: false,
    },
    axisTicks: {
      show: false,
    },
  },
  yaxis: {
    show: false,
    min: 0,
    max: 100,
  },
  markers: {
    size: 10,
    strokeWidth: 0,
  },
});
