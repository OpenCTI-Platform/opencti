import { ApexOptions } from 'apexcharts';
import { daysAgo, now } from '../Time';
import { colors } from '../Charts';
import type { Theme } from '../../components/Theme';
import type { ApexChartEvents, ApexChartLabels } from './apex';

type MarkerShape = NonNullable<NonNullable<ApexOptions['markers']>['shape']>;

export interface ScatterChartOptionsArgs {
  theme: Theme;
  background?: string;
  dataPointMouseEnter?: ApexChartEvents['dataPointMouseEnter'];
  dataPointMouseLeave?: ApexChartEvents['dataPointMouseLeave'];
  dataPointSelection?: ApexChartEvents['dataPointSelection'];
  labelsFormatter?: ApexChartLabels['formatter'];
  // Days back from now the x axis starts at (default 7).
  days?: number;
  // One size and one shape per series, in series order (default: one size, circles).
  markerSizes?: number[];
  markerShapes?: MarkerShape;
  // Readable axes: the y axis is the PIR score (0-100), the x axis the date.
  showAxes?: boolean;
  yTitle?: string;
}

export const scatterChartOptions = ({
  theme,
  background,
  dataPointMouseEnter,
  dataPointMouseLeave,
  dataPointSelection,
  labelsFormatter,
  days = 7,
  markerSizes,
  markerShapes,
  showAxes = false,
  yTitle,
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
      dataPointSelection,
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
    show: showAxes,
    borderColor: theme.palette.divider,
    strokeDashArray: 3,
    xaxis: { lines: { show: false } },
    yaxis: { lines: { show: showAxes } },
  },
  legend: {
    show: false,
  },
  tooltip: {
    enabled: false,
  },
  xaxis: {
    type: 'datetime',
    min: new Date(daysAgo(days)).getTime(),
    max: new Date(now()).getTime(),
    labels: {
      show: showAxes,
      datetimeUTC: false,
    },
    axisBorder: {
      show: showAxes,
    },
    axisTicks: {
      show: false,
    },
  },
  yaxis: {
    show: showAxes,
    min: 0,
    max: 100,
    tickAmount: 4,
    title: yTitle ? { text: yTitle } : undefined,
  },
  markers: {
    size: markerSizes && markerSizes.length > 0 ? markerSizes : 10,
    shape: markerShapes,
    strokeWidth: showAxes ? 1 : 0,
    strokeColors: background,
  },
});
