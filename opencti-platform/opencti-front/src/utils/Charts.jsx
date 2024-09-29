import * as C from '@mui/material/colors';
import { resolveLink } from './Entity';
import { truncate } from './String';
import { isColorCloseToWhite } from './Colors';

export const colors = (temp) => [
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

const toolbarOptions = {
  show: false,
  export: {
    csv: {
      columnDelimiter: ',',
      headerCategory: 'category',
      headerValue: 'value',
      // eslint-disable-next-line @typescript-eslint/no-shadow
      dateFormatter(timestamp) {
        return new Date(timestamp).toDateString();
      },
    },
  },
};

/**
 * A custom tooltip for ApexChart.
 * This tooltip only display the label of the data it hovers.
 *
 * Why custom tooltip? To manage text color of the tooltip that cannot be done by
 * the ApexChart API by default.
 *
 * @param {Theme} theme
 */
const simpleLabelTooltip = (theme) => ({ seriesIndex, w }) => (`
  <div style="background: ${theme.palette.background.nav}; color: ${theme.palette.text.primary}; padding: 2px 6px; font-size: 12px">
    ${w.config.labels[seriesIndex]}
  </div>
`);

/**
 * @param {Theme} theme
 * @param {boolean} isTimeSeries
 * @param {function} xFormatter
 * @param {function} yFormatter
 * @param {number | 'dataPoints'} tickAmount
 * @param {boolean} dataLabels
 * @param {boolean} legend
 */
export const lineChartOptions = (
  theme,
  isTimeSeries = false,
  xFormatter = null,
  yFormatter = null,
  tickAmount = undefined,
  dataLabels = false,
  legend = true,
) => ({
  chart: {
    type: 'line',
    background: theme.palette.background.paper,
    toolbar: toolbarOptions,
    foreColor: theme.palette.text.secondary,
    width: '100%',
    height: '100%',
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
      // maxWidth: 80,
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

/**
 * @param {Theme} theme
 * @param {boolean} isTimeSeries
 * @param {function} xFormatter
 * @param {function} yFormatter
 * @param {number | 'dataPoints'} tickAmount
 * @param {boolean} isStacked
 * @param {boolean} legend
 */
export const areaChartOptions = (
  theme,
  isTimeSeries = false,
  xFormatter = null,
  yFormatter = null,
  tickAmount = undefined,
  isStacked = false,
  legend = true,
) => ({
  chart: {
    type: 'area',
    background: theme.palette.background.paper,
    toolbar: toolbarOptions,
    foreColor: theme.palette.text.secondary,
    stacked: isStacked,
    width: '100%',
    height: '100%',
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
      // maxWidth: 80,
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

/**
 * @param {Theme} theme
 * @param {function} xFormatter
 * @param {function} yFormatter
 * @param {boolean} distributed
 * @param {boolean} isTimeSeries
 * @param {boolean} isStacked
 * @param {boolean} legend
 * @param {number | 'dataPoints'} tickAmount
 */
export const verticalBarsChartOptions = (
  theme,
  xFormatter,
  yFormatter,
  distributed = false,
  isTimeSeries = false,
  isStacked = false,
  legend = false,
  tickAmount = undefined,
) => ({
  chart: {
    type: 'bar',
    background: theme.palette.background.paper,
    toolbar: toolbarOptions,
    foreColor: theme.palette.text.secondary,
    stacked: isStacked,
    width: '100%',
    height: '100%',
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
      align: 'bottom',
      // maxWidth: "80px",
      // offsetY: "-20px",
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
      borderRadius: 4,
      borderRadiusApplication: 'end',
      borderRadiusWhenStacked: 'last',
      distributed,
    },
  },
});

/**
 * @param {Theme} theme
 * @param {boolean} adjustTicks
 * @param {function} xFormatter
 * @param {function} yFormatter
 * @param {boolean} distributed
 * @param {function} navigate
 * @param {object[]} redirectionUtils
 * @param {boolean} stacked
 * @param {boolean} total
 * @param {string[]} categories
 * @param {boolean} legend
 * @param {string} stackType
 */
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
  stackType = 'normal',
) => ({
  events: ['xAxisLabelClick'],
  chart: {
    type: 'bar',
    background: theme.palette.background.paper,
    toolbar: toolbarOptions,
    foreColor: theme.palette.text.secondary,
    stacked,
    stackType,
    width: '100%',
    height: '100%',
    events: {
      xAxisLabelClick: (event, chartContext, config) => {
        if (redirectionUtils) {
          const { labelIndex } = config;
          if (redirectionUtils[labelIndex].name === 'Restricted') {
            return;
          }
          const entityType = redirectionUtils[labelIndex].entity_type;
          const link = resolveLink(entityType);
          if (link) {
            const entityId = redirectionUtils[labelIndex].id;
            navigate(`${link}/${entityId}`);
          }
        }
      },
      mouseMove: (event, chartContext, config) => {
        const { dataPointIndex, seriesIndex } = config;
        if (redirectionUtils
          && (
            (dataPointIndex >= 0 // case click on a bar
              && (
                (seriesIndex >= 0 && redirectionUtils[dataPointIndex]?.series // case multi bars
                  && redirectionUtils[dataPointIndex].series[seriesIndex]?.entity_type
                  && resolveLink(redirectionUtils[dataPointIndex].series[seriesIndex]?.entity_type)
                )
                || (
                  !(seriesIndex >= 0 && redirectionUtils[dataPointIndex]?.series) // case not multi bars
                  && redirectionUtils[dataPointIndex]?.entity_type
                  && resolveLink(redirectionUtils[dataPointIndex].entity_type)
                )
              )
            )
            || event.target.parentNode.className.baseVal === 'apexcharts-text apexcharts-yaxis-label ' // case click on a label
          )
        ) {
          // for clickable parts of the graphs
          // eslint-disable-next-line no-param-reassign
          event.target.style.cursor = 'pointer';
          // eslint-disable-next-line no-param-reassign
          event.target.classList.add('noDrag');
        }
      },
      click: (event, chartContext, config) => {
        if (redirectionUtils) {
          const { dataPointIndex, seriesIndex } = config;
          if (dataPointIndex >= 0) {
            // click on a bar
            if (
              seriesIndex >= 0
              && redirectionUtils[dataPointIndex].series
            ) {
              // for multi horizontal bars representing entities
              if (redirectionUtils[dataPointIndex].series[seriesIndex]?.entity_type) {
                // for series representing a single entity
                const link = resolveLink(redirectionUtils[dataPointIndex].series[seriesIndex].entity_type);
                if (link) {
                  const entityId = redirectionUtils[dataPointIndex].series[seriesIndex].id;
                  navigate(`${link}/${entityId}`);
                }
              }
            } else {
              if (redirectionUtils[dataPointIndex].name === 'Restricted') {
                return;
              }
              const link = resolveLink(redirectionUtils[dataPointIndex].entity_type);
              if (link) {
                const entityId = redirectionUtils[dataPointIndex].id;
                navigate(`${link}/${entityId}`);
              }
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
    enabled: stackType === '100%',
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
    show: stackType !== '100%',
    borderColor:
      theme.palette.mode === 'dark'
        ? 'rgba(255, 255, 255, .1)'
        : 'rgba(0, 0, 0, .1)',
    strokeDashArray: 3,
    padding: {
      right: 20,
    },
  },
  legend: {
    show: legend,
    showForSingleSeries: true,
    itemMargin: {
      horizontal: 5,
    },
  },
  tooltip: {
    theme: theme.palette.mode,
    x: {
      show: stackType !== '100%',
    },
  },
  xaxis: {
    categories: categories ?? [],
    labels: {
      show: stackType !== '100%',
      formatter: (value) => (xFormatter ? xFormatter(value) : value),
      style: {
        fontFamily: '"IBM Plex Sans", sans-serif',
      },
    },
    axisBorder: {
      show: false,
    },
    axisTicks: {
      show: stackType !== '100%',
    },
    tickAmount: adjustTicks ? 1 : undefined,
  },
  yaxis: {
    show: stackType !== '100%',
    labels: {
      show: stackType !== '100%',
      formatter: (value) => (yFormatter ? yFormatter(value) : value),
      // maxWidth: 80,
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
      borderRadius: 4,
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

/**
 * @param {Theme} theme
 * @param {function} xFormatter
 * @param {string[]} labels
 * @param {string[]} chartColors
 * @param {boolean} legend
 * @param {string} background
 * @param {int} size
 * @param {function} handleClick
 */
export const radarChartOptions = (
  theme,
  labels,
  xFormatter = null,
  chartColors = [],
  legend = false,
  background = theme.palette.background.paper,
  size = undefined,
  handleClick = undefined,
) => ({
  chart: {
    type: 'radar',
    background,
    toolbar: toolbarOptions,
    width: '100%',
    height: '100%',
    events: {
      click: () => handleClick(),
      markerClick: () => handleClick(),
    },
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
    x: {
      formatter: (value) => value,
    },
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
      formatter: (value) => truncate(value, 25),
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
    labels: {
      formatter: (value) => (xFormatter ? xFormatter(value) : value),
    },
  },
  plotOptions: {
    radar: {
      size,
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

/**
 * @param {Theme} theme
 * @param {string[]} labels
 * @param {function} formatter
 * @param {string} legendPosition
 * @param {string[]} chartColors
 */
export const polarAreaChartOptions = (
  theme,
  labels,
  formatter = null,
  legendPosition = 'bottom',
  chartColors = [],
) => {
  const temp = theme.palette.mode === 'dark' ? 400 : 600;
  let chartFinalColors = chartColors;
  if (chartFinalColors.length === 0) {
    chartFinalColors = colors(temp);
    if (labels.length === 2 && labels[0] === 'true') {
      chartFinalColors = [C.green[temp], C.red[temp]];
    } else if (labels.length === 2 && labels[0] === 'false') {
      chartFinalColors = [C.red[temp], C.green[temp]];
    }
  }
  return {
    chart: {
      type: 'polarArea',
      background: theme.palette.background.paper,
      toolbar: toolbarOptions,
      foreColor: theme.palette.text.secondary,
      width: '100%',
      height: '100%',
    },
    theme: {
      mode: theme.palette.mode,
    },
    colors: chartFinalColors,
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
      custom: simpleLabelTooltip(theme),
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
  };
};

/**
 * @param {Theme} theme
 * @param {string[]} labels
 * @param {string} legendPosition
 * @param {boolean} reversed
 * @param {string[]} chartColors
 * @param {boolean} displayLegend
 * @param {boolean} displayLabels
 * @param {boolean} displayValue
 * @param {boolean} displayTooltip
 * @param {number} size
 * @param {boolean} withBackground
 * @returns ApexOptions
 */
export const donutChartOptions = (
  theme,
  labels,
  legendPosition = 'bottom',
  reversed = false,
  chartColors = [],
  displayLegend = true,
  displayLabels = true,
  displayValue = true,
  displayTooltip = true,
  size = 70,
  withBackground = true,
) => {
  const temp = theme.palette.mode === 'dark' ? 400 : 600;
  let dataLabelsColors = labels.map(() => theme.palette.text.primary);
  if (chartColors.length > 0) {
    dataLabelsColors = chartColors.map((n) => (n === '#ffffff' ? '#000000' : theme.palette.text.primary));
  }
  let chartFinalColors = chartColors;
  if (chartFinalColors.length === 0) {
    chartFinalColors = colors(temp);
    if (labels.length === 2 && labels[0] === 'true') {
      if (reversed) {
        chartFinalColors = [C.red[temp], C.green[temp]];
      } else {
        chartFinalColors = [C.green[temp], C.red[temp]];
      }
    } else if (labels.length === 2 && labels[0] === 'false') {
      if (reversed) {
        chartFinalColors = [C.green[temp], C.red[temp]];
      } else {
        chartFinalColors = [C.red[temp], C.green[temp]];
      }
    }
  }
  return {
    chart: {
      type: 'donut',
      background: withBackground ? theme.palette.background.paper : 'transparent',
      toolbar: toolbarOptions,
      foreColor: theme.palette.text.secondary,
      width: '100%',
      height: '100%',
    },
    theme: {
      mode: theme.palette.mode,
    },
    colors: chartFinalColors,
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
    tooltip: {
      enabled: displayTooltip,
      theme: theme.palette.mode,
      custom: simpleLabelTooltip(theme),
    },
    legend: {
      show: displayLegend,
      position: legendPosition,
      fontFamily: '"IBM Plex Sans", sans-serif',
    },
    dataLabels: {
      enabled: displayLabels,
      style: {
        fontSize: '10px',
        fontFamily: '"IBM Plex Sans", sans-serif',
        fontWeight: 600,
        colors: dataLabelsColors,
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
          value: {
            show: displayValue,
          },
          background: theme.palette.background.paper,
          size: `${size}%`,
        },
      },
    },
  };
};

/**
 *
 * @param {Theme} theme
 * @param {function} formatter
 * @param {string} legendPosition
 * @param {boolean} distributed
 */
export const treeMapOptions = (
  theme,
  formatter = null,
  legendPosition = 'bottom',
  distributed = false,
) => {
  return {
    chart: {
      type: 'treemap',
      background: theme.palette.background.paper,
      toolbar: toolbarOptions,
      foreColor: theme.palette.text.secondary,
      width: '100%',
      height: '100%',
    },
    theme: {
      mode: theme.palette.mode,
    },
    colors: distributed
      ? colors(theme.palette.mode === 'dark' ? 400 : 600).filter((c) => !isColorCloseToWhite(c))
      : [theme.palette.primary.main, ...colors(theme.palette.mode === 'dark' ? 400 : 600)],
    fill: {
      opacity: 1,
    },
    yaxis: {
      labels: {
        formatter: (value) => (formatter ? formatter(value) : value),
      },
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
        fontFamily: '"IBM Plex Sans", sans-serif',
        fontWeight: 600,
        colors: [theme.palette.text.primary, theme.palette.text.secondary],
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

/**
 * @param {Theme} theme
 * @param {boolean} isTimeSeries
 * @param {function} xFormatter
 * @param {function} yFormatter
 * @param {number | 'dataPoints'} tickAmount
 * @param {boolean} isStacked
 * @param {object[]} ranges
 */
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
    background: theme.palette.background.paper,
    toolbar: toolbarOptions,
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
