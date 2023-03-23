import * as C from '@mui/material/colors';
import { resolveLink } from './Entity';

const colors = (temp) => [
  C.red[temp],
  C.purple[temp],
  C.pink[temp],
  C.deepPurple[temp],
  C.indigo[temp],
  C.blue[temp],
  C.cyan[temp],
  C.blueGrey[temp],
  C.lightBlue[temp],
  C.green[temp],
  C.teal[temp],
  C.lightGreen[temp],
  C.amber[temp],
  C.deepOrange[temp],
  C.lime[temp],
  C.yellow[temp],
  C.brown[temp],
  C.orange[temp],
  C.grey[temp],
];

export const lineChartOptions = (
  theme,
  isTimeSeries = false,
  xFormatter = null,
  yFormatter = null,
  tickAmount = undefined,
  dataLabels = false,
  legend = false,
) => ({
  chart: {
    type: 'line',
    background: 'transparent',
    toolbar: {
      show: false,
    },
    foreColor: theme.palette.text.secondary,
  },
  theme: {
    mode: theme.palette.mode,
  },
  dataLabels: {
    enabled: dataLabels,
  },
  colors: [
    theme.palette.primary.main,
    ...colors(theme.palette.mode === 'dark' ? 400 : 600),
  ],
  states: {
    hover: {
      filter: {
        type: 'lighten',
        value: 0.05,
      },
    },
  },
  grid: {
    borderColor:
      theme.palette.mode === 'dark'
        ? 'rgba(255, 255, 255, .1)'
        : 'rgba(0, 0, 0, .1)',
    strokeDashArray: 3,
  },
  legend: {
    show: legend,
    itemMargin: {
      horizontal: 5,
      vertical: 20,
    },
  },
  stroke: {
    curve: 'smooth',
    width: 2,
  },
  tooltip: {
    theme: theme.palette.mode,
  },
  xaxis: {
    type: isTimeSeries ? 'datetime' : 'category',
    tickAmount,
    tickPlacement: 'on',
    labels: {
      formatter: (value) => (xFormatter ? xFormatter(value) : value),
      style: {
        fontSize: '12px',
        fontFamily: '"IBM Plex Sans", sans-serif',
      },
    },
    axisBorder: {
      show: false,
    },
  },
  yaxis: {
    labels: {
      formatter: (value) => (yFormatter ? yFormatter(value) : value),
      style: {
        fontSize: '14px',
        fontFamily: '"IBM Plex Sans", sans-serif',
      },
    },
    axisBorder: {
      show: false,
    },
  },
});

export const areaChartOptions = (
  theme,
  isTimeSeries = false,
  xFormatter = null,
  yFormatter = null,
  tickAmount = undefined,
  isStacked = false,
  legend = false,
) => ({
  chart: {
    type: 'area',
    background: 'transparent',
    toolbar: {
      show: false,
    },
    foreColor: theme.palette.text.secondary,
    stacked: isStacked,
  },
  theme: {
    mode: theme.palette.mode,
  },
  dataLabels: {
    enabled: false,
  },
  stroke: {
    curve: 'smooth',
    width: 2,
  },
  colors: [
    theme.palette.primary.main,
    ...colors(theme.palette.mode === 'dark' ? 400 : 600),
  ],
  states: {
    hover: {
      filter: {
        type: 'lighten',
        value: 0.05,
      },
    },
  },
  grid: {
    borderColor:
      theme.palette.mode === 'dark'
        ? 'rgba(255, 255, 255, .1)'
        : 'rgba(0, 0, 0, .1)',
    strokeDashArray: 3,
  },
  legend: {
    show: legend,
    itemMargin: {
      horizontal: 5,
      vertical: 20,
    },
  },
  tooltip: {
    theme: theme.palette.mode,
  },
  fill: {
    type: 'gradient',
    gradient: {
      shade: theme.palette.mode,
      shadeIntensity: 1,
      opacityFrom: 0.7,
      opacityTo: 0.1,
      gradientToColors: [
        theme.palette.primary.main,
        theme.palette.primary.main,
      ],
    },
  },
  xaxis: {
    type: isTimeSeries ? 'datetime' : 'category',
    tickAmount,
    tickPlacement: 'on',
    labels: {
      formatter: (value) => (xFormatter ? xFormatter(value) : value),
      style: {
        fontSize: '12px',
        fontFamily: '"IBM Plex Sans", sans-serif',
      },
    },
    axisBorder: {
      show: false,
    },
  },
  yaxis: {
    labels: {
      formatter: (value) => (yFormatter ? yFormatter(value) : value),
      style: {
        fontSize: '14px',
        fontFamily: '"IBM Plex Sans", sans-serif',
      },
    },
    axisBorder: {
      show: false,
    },
  },
});

export const verticalBarsChartOptions = (
  theme,
  xFormatter = null,
  yFormatter = null,
  distributed = false,
  isTimeSeries = false,
  isStacked = false,
  legend = false,
) => ({
  chart: {
    type: 'bar',
    background: 'transparent',
    toolbar: {
      show: false,
    },
    foreColor: theme.palette.text.secondary,
    stacked: isStacked,
  },
  theme: {
    mode: theme.palette.mode,
  },
  dataLabels: {
    enabled: false,
  },
  colors: [
    theme.palette.primary.main,
    ...colors(theme.palette.mode === 'dark' ? 400 : 600),
  ],
  states: {
    hover: {
      filter: {
        type: 'lighten',
        value: 0.05,
      },
    },
  },
  grid: {
    borderColor:
      theme.palette.mode === 'dark'
        ? 'rgba(255, 255, 255, .1)'
        : 'rgba(0, 0, 0, .1)',
    strokeDashArray: 3,
  },
  legend: {
    show: legend,
    itemMargin: {
      horizontal: 5,
      vertical: 20,
    },
  },
  tooltip: {
    theme: theme.palette.mode,
  },
  xaxis: {
    type: isTimeSeries ? 'datetime' : 'category',
    tickPlacement: 'on',
    labels: {
      formatter: (value) => (xFormatter ? xFormatter(value) : value),
      style: {
        fontSize: '12px',
        fontFamily: '"IBM Plex Sans", sans-serif',
      },
    },
    axisBorder: {
      show: false,
    },
  },
  yaxis: {
    labels: {
      formatter: (value) => (yFormatter ? yFormatter(value) : value),
      style: {
        fontFamily: '"IBM Plex Sans", sans-serif',
      },
    },
    axisBorder: {
      show: false,
    },
  },
  plotOptions: {
    bar: {
      horizontal: false,
      barHeight: '30%',
      borderRadius: 5,
      borderRadiusApplication: 'end',
      borderRadiusWhenStacked: 'last',
      distributed,
    },
  },
});

export const horizontalBarsChartOptions = (
  theme,
  adjustTicks = false,
  xFormatter = null,
  yFormatter = null,
  distributed = false,
  navigate = undefined,
  redirectionUtils = null,
  stacked = false,
  total = false,
  categories = null,
  legend = false,
) => ({
  chart: {
    type: 'bar',
    background: 'transparent',
    toolbar: {
      show: false,
    },
    foreColor: theme.palette.text.secondary,
    stacked,
    events: {
      mouseMove: (event, chartContext, config) => {
        if (redirectionUtils
          && config.dataPointIndex >= 0
          && ((config.seriesIndex > 0
            && redirectionUtils[config.dataPointIndex].series?.[config.seriesIndex - 1]
          )
            || !(config.seriesIndex > 0)
          )
        ) { // for clickable parts of the graphs
          // eslint-disable-next-line no-param-reassign
          event.target.style.cursor = 'pointer';
        } else {
          // eslint-disable-next-line no-param-reassign
          event.target.style.cursor = 'default';
        }
      },
      click: (event, chartContext, config) => {
        if (redirectionUtils) {
          if (config.dataPointIndex >= 0) { // click on a bar
            const { dataPointIndex } = config;
            if (config.seriesIndex > 0 && redirectionUtils[dataPointIndex].series) { // for multi horizontal bars representing entities
              const seriesIndex = config.seriesIndex - 1;
              if (redirectionUtils[dataPointIndex].series[seriesIndex]) { // for series representing a single entity
                const link = resolveLink(redirectionUtils[dataPointIndex].series[seriesIndex].entity_type);
                const entityId = redirectionUtils[dataPointIndex].series[seriesIndex].id;
                navigate(`${link}/${entityId}`);
              }
            } else {
              const link = resolveLink(redirectionUtils[dataPointIndex].entity_type);
              const entityId = redirectionUtils[dataPointIndex].id;
              navigate(`${link}/${entityId}`);
            }
          }
        }
      },
    },
  },
  theme: {
    mode: theme.palette.mode,
  },
  dataLabels: {
    enabled: false,
  },
  colors: [
    theme.palette.primary.main,
    ...colors(theme.palette.mode === 'dark' ? 400 : 600),
  ],
  states: {
    hover: {
      filter: {
        type: 'lighten',
        value: 0.05,
      },
    },
  },
  grid: {
    borderColor:
      theme.palette.mode === 'dark'
        ? 'rgba(255, 255, 255, .1)'
        : 'rgba(0, 0, 0, .1)',
    strokeDashArray: 3,
  },
  legend: {
    show: legend,
    itemMargin: {
      horizontal: 5,
    },
  },
  tooltip: {
    theme: theme.palette.mode,
  },
  xaxis: {
    categories: categories ?? [],
    labels: {
      formatter: (value) => (xFormatter ? xFormatter(value) : value),
      style: {
        fontFamily: '"IBM Plex Sans", sans-serif',
      },
    },
    axisBorder: {
      show: false,
    },
    tickAmount: adjustTicks ? 1 : undefined,
  },
  yaxis: {
    labels: {
      formatter: (value) => (yFormatter ? yFormatter(value) : value),
      style: {
        fontFamily: '"IBM Plex Sans", sans-serif',
      },
    },
    axisBorder: {
      show: false,
    },
  },
  plotOptions: {
    bar: {
      horizontal: true,
      barHeight: '30%',
      borderRadius: 5,
      borderRadiusApplication: 'end',
      borderRadiusWhenStacked: 'last',
      distributed,
      dataLabels: {
        total: {
          enabled: total,
          offsetX: 0,
          style: {
            fontSize: '13px',
            fontWeight: 900,
            fontFamily: '"IBM Plex Sans", sans-serif',
          },
        },
      },
    },
  },
});

export const radarChartOptions = (
  theme,
  labels,
  chartColors = [],
  legend = false,
  offset = false,
) => ({
  chart: {
    type: 'radar',
    background: 'transparent',
    toolbar: {
      show: false,
    },
    offsetY: offset ? -20 : 0,
  },
  theme: {
    mode: theme.palette.mode,
  },
  labels,
  states: {
    hover: {
      filter: {
        type: 'lighten',
        value: 0.05,
      },
    },
  },
  legend: {
    show: legend,
    itemMargin: {
      horizontal: 5,
      vertical: 5,
    },
  },
  tooltip: {
    theme: theme.palette.mode,
  },
  fill: {
    opacity: 0.2,
    colors: [theme.palette.primary.main],
  },
  stroke: {
    show: true,
    width: 1,
    colors: [theme.palette.primary.main],
    dashArray: 0,
  },
  markers: {
    shape: 'circle',
    strokeColors: [theme.palette.primary.main],
    colors: [theme.palette.primary.main],
  },
  xaxis: {
    labels: {
      show: legend,
      style: {
        fontFamily: '"IBM Plex Sans", sans-serif',
        colors: chartColors,
      },
    },
    axisBorder: {
      show: false,
    },
  },
  yaxis: {
    show: false,
  },
  plotOptions: {
    radar: {
      polygons: {
        strokeColors:
          theme.palette.mode === 'dark'
            ? 'rgba(255, 255, 255, .1)'
            : 'rgba(0, 0, 0, .1)',
        connectorColors:
          theme.palette.mode === 'dark'
            ? 'rgba(255, 255, 255, .1)'
            : 'rgba(0, 0, 0, .1)',
        fill: { colors: [theme.palette.background.paper] },
      },
    },
  },
});

export const polarAreaChartOptions = (
  theme,
  labels,
  formatter = null,
  legendPosition = 'right',
) => ({
  chart: {
    type: 'polarArea',
    background: 'transparent',
    toolbar: {
      show: false,
    },
    foreColor: theme.palette.text.secondary,
  },
  theme: {
    mode: theme.palette.mode,
  },
  colors: colors(theme.palette.mode === 'dark' ? 400 : 600),
  labels,
  states: {
    hover: {
      filter: {
        type: 'lighten',
        value: 0.05,
      },
    },
  },
  legend: {
    show: true,
    position: legendPosition,
    floating: legendPosition === 'bottom',
    fontFamily: '"IBM Plex Sans", sans-serif',
  },
  tooltip: {
    theme: theme.palette.mode,
  },
  fill: {
    opacity: 0.5,
  },
  yaxis: {
    labels: {
      formatter: (value) => (formatter ? formatter(value) : value),
      style: {
        fontFamily: '"IBM Plex Sans", sans-serif',
      },
    },
    axisBorder: {
      show: false,
    },
  },
  plotOptions: {
    polarArea: {
      rings: {
        strokeWidth: 1,
        strokeColor:
          theme.palette.mode === 'dark'
            ? 'rgba(255, 255, 255, .1)'
            : 'rgba(0, 0, 0, .1)',
      },
      spokes: {
        strokeWidth: 1,
        connectorColors:
          theme.palette.mode === 'dark'
            ? 'rgba(255, 255, 255, .1)'
            : 'rgba(0, 0, 0, .1)',
      },
    },
  },
});

export const donutChartOptions = (
  theme,
  labels,
  legendPosition = 'bottom',
  reversed = false,
) => {
  const temp = theme.palette.mode === 'dark' ? 400 : 600;
  let chartColors = colors(temp);
  if (labels.length === 2 && labels[0] === 'true') {
    if (reversed) {
      chartColors = [C.red[temp], C.green[temp]];
    } else {
      chartColors = [C.green[temp], C.red[temp]];
    }
  } else if (labels.length === 2 && labels[0] === 'false') {
    if (reversed) {
      chartColors = [C.green[temp], C.red[temp]];
    } else {
      chartColors = [C.red[temp], C.green[temp]];
    }
  }
  return {
    chart: {
      type: 'donut',
      background: 'transparent',
      toolbar: {
        show: false,
      },
      foreColor: theme.palette.text.secondary,
    },
    theme: {
      mode: theme.palette.mode,
    },
    colors: chartColors,
    labels,
    fill: {
      opacity: 1,
    },
    states: {
      hover: {
        filter: {
          type: 'lighten',
          value: 0.05,
        },
      },
    },
    stroke: {
      curve: 'smooth',
      width: 3,
      colors: [theme.palette.background.paper],
    },
    legend: {
      show: true,
      position: legendPosition,
      fontFamily: '"IBM Plex Sans", sans-serif',
    },
    tooltip: {
      theme: theme.palette.mode,
    },
    dataLabels: {
      style: {
        fontSize: '12px',
        fontFamily: '"IBM Plex Sans", sans-serif',
        fontWeight: 600,
        colors: [theme.palette.text.primary],
      },
      background: {
        enabled: false,
      },
      dropShadow: {
        enabled: false,
      },
    },
    plotOptions: {
      pie: {
        donut: {
          background: 'transparent',
          size: '80%',
        },
      },
    },
  };
};

export const treeMapOptions = (
  theme,
  legendPosition = 'bottom',
  distributed = false,
) => {
  return {
    chart: {
      type: 'donut',
      background: 'transparent',
      toolbar: {
        show: false,
      },
      foreColor: theme.palette.text.secondary,
    },
    theme: {
      mode: theme.palette.mode,
    },
    colors: [
      theme.palette.primary.main,
      ...colors(theme.palette.mode === 'dark' ? 400 : 600),
    ],
    fill: {
      opacity: 1,
    },
    states: {
      hover: {
        filter: {
          type: 'lighten',
          value: 0.05,
        },
      },
    },
    stroke: {
      curve: 'smooth',
      width: 3,
      colors: [theme.palette.background.paper],
    },
    legend: {
      show: true,
      position: legendPosition,
      fontFamily: '"IBM Plex Sans", sans-serif',
    },
    tooltip: {
      theme: theme.palette.mode,
    },
    dataLabels: {
      style: {
        fontSize: '12px',
        fontFamily: '"IBM Plex Sans", sans-serif',
        fontWeight: 600,
        colors: [theme.palette.text.primary],
      },
      background: {
        enabled: false,
      },
      dropShadow: {
        enabled: false,
      },
    },
    plotOptions: {
      treemap: {
        distributed,
      },
    },
  };
};

export const heatMapOptions = (
  theme,
  isTimeSeries = false,
  xFormatter = null,
  yFormatter = null,
  tickAmount = undefined,
  isStacked = false,
  ranges = [],
) => ({
  chart: {
    type: 'heatmap',
    background: 'transparent',
    toolbar: {
      show: false,
    },
    foreColor: theme.palette.text.secondary,
    stacked: isStacked,
  },
  theme: {
    mode: theme.palette.mode,
  },
  dataLabels: {
    enabled: false,
  },
  stroke: {
    colors: [theme.palette.background.paper],
    width: 1,
  },
  states: {
    hover: {
      filter: {
        type: 'lighten',
        value: 0.05,
      },
    },
  },
  grid: {
    borderColor:
      theme.palette.mode === 'dark'
        ? 'rgba(255, 255, 255, .1)'
        : 'rgba(0, 0, 0, .1)',
    strokeDashArray: 3,
  },
  legend: {
    show: false,
  },
  tooltip: {
    theme: theme.palette.mode,
  },
  xaxis: {
    type: isTimeSeries ? 'datetime' : 'category',
    tickAmount,
    tickPlacement: 'on',
    labels: {
      formatter: (value) => (xFormatter ? xFormatter(value) : value),
      style: {
        fontSize: '12px',
        fontFamily: '"IBM Plex Sans", sans-serif',
      },
    },
    axisBorder: {
      show: false,
    },
  },
  yaxis: {
    labels: {
      formatter: (value) => (yFormatter ? yFormatter(value) : value),
      style: {
        fontSize: '14px',
        fontFamily: '"IBM Plex Sans", sans-serif',
      },
    },
    axisBorder: {
      show: false,
    },
  },
  plotOptions: {
    heatmap: {
      enableShades: false,
      distributed: false,
      colorScale: {
        ranges,
      },
    },
  },
});
