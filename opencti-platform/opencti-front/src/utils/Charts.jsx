import * as C from '@mui/material/colors';
import { resolveLink } from './Entity';
import { sanitize, truncate } from './String';
import { isColorCloseToWhite } from './Colors';
import { alpha } from '@mui/material/styles';
import { shouldOpenInNewTabMouseEvent } from './domEvent';

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

      dateFormatter(timestamp) {
        return new Date(timestamp).toDateString();
      },
    },
  },
};

const handleNavigate = (event, navigate, link) => {
  if (!link) return;
  event.preventDefault();
  event.stopPropagation();

  if (shouldOpenInNewTabMouseEvent(event)) {
    window.open(link, '_blank');
  } else {
    navigate(link);
  }
};

/**
 * `mouseMove` fires on every pointer move over the chart, and resolving a link
 * walks the filter keys schema then serialises a URL. A surface is identified by
 * its index pair, and the resolver lives exactly as long as the buckets it was
 * built from, so the answer is computed once per surface.
 */
const memoizeByPoint = (resolve) => {
  const cache = new Map();
  return (config) => {
    const key = `${config?.seriesIndex}:${config?.dataPointIndex}`;
    if (!cache.has(key)) cache.set(key, resolve(config));
    return cache.get(key);
  };
};

/**
 * ApexCharts calls `click` and `mouseMove` with `Object.assign({}, w, {
 * seriesIndex, dataPointIndex })` (Events.js:73-76): the series sit under
 * `config.config`, and both indices come from `getAttribute`, so they are
 * strings — or `null` when the pointer is not over a data point.
 */
const pointIndex = (value) => {
  // `Number(null)` is 0, which would silently resolve the first bucket.
  if (value === null || value === undefined || value === '') return null;
  const index = Number(value);
  return Number.isInteger(index) && index >= 0 ? index : null;
};

const pointIndexes = (config) => {
  const seriesIndex = pointIndex(config?.seriesIndex);
  const dataPointIndex = pointIndex(config?.dataPointIndex);
  if (seriesIndex === null || dataPointIndex === null) return null;
  return { seriesIndex, dataPointIndex };
};

/**
 * Builds both ApexCharts handlers from a single link resolver, so the pointer
 * cursor can never promise a navigation that the click does not perform.
 */
const drilldownHandlers = (rawLinkAt, navigate) => {
  const linkAt = memoizeByPoint(rawLinkAt);
  return {
    click: (event, chartContext, config) => {
      handleNavigate(event, navigate, linkAt(config));
    },
    mouseMove: (event, chartContext, config) => {
      if (!event?.target?.style) return;
      if (linkAt(config)) {
        event.target.style.cursor = 'pointer';
        // The surfaces are SVG nodes ApexCharts creates itself, so the class
        // that tells react-grid-layout not to drag has to be set here.
        event.target.classList?.add('noDrag');
      } else {
        event.target.style.cursor = 'default';
        event.target.classList?.remove('noDrag');
      }
    },
  };
};

/**
 * `resolveBucket` receives the resolved indexes and returns the clicked bucket,
 * or null when the surface carries no reproducible count.
 *
 * Returns an empty object when the widget has no drill-down, leaving charts
 * without any handler rather than an inert one.
 */
export const buildDrilldownEvents = (resolveBucket, drilldown) => {
  if (!drilldown) return {};
  const linkAt = (config) => {
    const indexes = pointIndexes(config);
    if (!indexes) return null;
    const bucket = resolveBucket(config, indexes);
    return bucket ? drilldown.getLink(indexes.seriesIndex, bucket) : null;
  };
  return drilldownHandlers(linkAt, drilldown.navigate);
};

/**
 * Distribution charts identify the clicked bucket by `dataPointIndex` alone:
 * pie slices (Pie.js:265) and radar markers (Radar.js:235) carry a `j`
 * attribute but no `i`, so ApexCharts cannot report a trustworthy series index
 * for them. None is needed either -- these widgets render a single data
 * selection, hence the hardcoded 0.
 *
 * `drilldown.buckets` comes from `buildDistributionBuckets` and is aligned with
 * the chart series index by index, gaps included.
 *
 * Exposed on its own so a chart that also carries a legacy redirection can ask
 * whether the drill-down resolves a link before deciding which one wins.
 *
 * @param {object} drilldown The widget drill-down descriptor.
 * @returns {(config: object) => (string|null)} Resolver returning the link for a clicked surface.
 */
const distributionBucketLink = (drilldown) => (config) => {
  const index = pointIndex(config?.dataPointIndex);
  if (index === null) return null;
  const bucket = drilldown.buckets?.[index];
  return bucket ? drilldown.getLink(0, bucket) : null;
};

/**
 * Builds the ApexCharts handlers navigating a distribution bucket to its
 * filtered list.
 *
 * @param {object} [drilldown] The widget drill-down descriptor, if any.
 * @returns {object} ApexCharts chart events, empty when there is no drill-down.
 */
export const distributionBucketEvents = (drilldown) => {
  if (!drilldown) return {};
  return drilldownHandlers(distributionBucketLink(drilldown), drilldown.navigate);
};

/**
 * A time-series point carries its bucket start on `x`, as the very value the
 * API returned (the containers build it with `new Date(entry.date)`).
 */
const timeSeriesBucketEvents = (drilldown) => buildDrilldownEvents(
  (config, { seriesIndex, dataPointIndex }) => {
    const point = config?.config?.series?.[seriesIndex]?.data?.[dataPointIndex];
    const date = Array.isArray(point) ? point[0] : point?.x;
    if (date === undefined || date === null) return null;
    const parsed = new Date(date);
    return Number.isNaN(parsed.getTime()) ? null : { kind: 'timeSeries', date: parsed.toISOString() };
  },
  drilldown,
);

// theme colors are always stored as 6-digit hex (see themeValidation.ts), so any other
// value is untrusted input and must be rejected rather than interpolated into CSS
const HEX_COLOR_REGEX = /^#[0-9a-fA-F]{6}$/;
const sanitizeCssColor = (value, fallback) => (HEX_COLOR_REGEX.test(value) ? value : fallback);

/**
 * A custom tooltip for ApexChart.
 * This tooltip only display the label of the data it hovers.
 *
 * Why custom tooltip? To manage text color of the tooltip that cannot be done by
 * the ApexChart API by default.
 *
 * @param {Theme} theme
 */
export const simpleLabelTooltip = (theme) => ({ seriesIndex, w }) => {
  const safeNavColor = sanitizeCssColor(theme.palette.background.nav, 'inherit');
  const safeTextColor = sanitizeCssColor(theme.palette.text.primary, 'inherit');
  const safeLabel = sanitize(String(w.config.labels[seriesIndex] ?? ''), true);
  return (`
  <div style="background: ${safeNavColor}; color: ${safeTextColor}; padding: 2px 6px; font-size: 12px">
    ${safeLabel}
  </div>
`);
};

/**
 * @param {Theme} theme
 * @param {boolean} isTimeSeries
 * @param {function} xFormatter
 * @param {function} yFormatter
 * @param {number | 'dataPoints'} tickAmount
 * @param {boolean} dataLabels
 * @param {boolean} legend
 * @param {{ getLink: function, navigate: function }} [drilldown] Drill-down descriptor, carrying the router navigate.
 */
export const lineChartOptions = (
  theme,
  isTimeSeries = false,
  xFormatter = null,
  yFormatter = null,
  tickAmount = undefined,
  dataLabels = false,
  legend = true,
  drilldown = undefined,
) => ({
  chart: {
    type: 'line',
    background: theme.palette.background.paper,
    toolbar: toolbarOptions,
    foreColor: theme.palette.text.secondary,
    width: '100%',
    height: '100%',
    events: timeSeriesBucketEvents(drilldown),
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

/**
 * @param {Theme} theme
 * @param {boolean} isTimeSeries
 * @param {function} xFormatter
 * @param {function} yFormatter
 * @param {number | 'dataPoints'} tickAmount
 * @param {boolean} isStacked
 * @param {boolean} legend
 * @param {{ getLink: function, navigate: function }} [drilldown] Drill-down descriptor, carrying the router navigate.
 */
export const areaChartOptions = (
  theme,
  isTimeSeries = false,
  xFormatter = null,
  yFormatter = null,
  tickAmount = undefined,
  isStacked = false,
  legend = true,
  drilldown = undefined,
) => ({
  chart: {
    type: 'area',
    background: theme.palette.background.paper,
    toolbar: toolbarOptions,
    foreColor: theme.palette.text.secondary,
    stacked: isStacked,
    width: '100%',
    height: '100%',
    events: timeSeriesBucketEvents(drilldown),
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

/**
 * @param {Theme} theme
 * @param {function} xFormatter
 * @param {function} yFormatter
 * @param {boolean} distributed
 * @param {boolean} isTimeSeries
 * @param {boolean} isStacked
 * @param {boolean} legend
 * @param {number | 'dataPoints'} tickAmount
 * @param {{ getLink: function, navigate: function }} [drilldown] Drill-down descriptor, carrying the router navigate.
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
  drilldown = undefined,
) => ({
  chart: {
    type: 'bar',
    background: theme.palette.background.paper,
    toolbar: toolbarOptions,
    foreColor: theme.palette.text.secondary,
    stacked: isStacked,
    width: '100%',
    height: '100%',
    events: timeSeriesBucketEvents(drilldown),
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
 * @param {(object|null)[]} redirectionUtils One entry per bucket, null where the bucket resolves to no entity.
 * @param {boolean} stacked
 * @param {boolean} total
 * @param {string[]} categories
 * @param {boolean} legend
 * @param {string} stackType
 * @param {{ getLink: function, navigate: function, buckets: (object | null)[] }} [drilldown] Distribution drill-down descriptor.
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
  drilldown = undefined,
) => {
  const drilldownEvents = distributionBucketEvents(drilldown);
  // A widget aggregating on an attribute no list filter reproduces (`internal_id`,
  // used by every Home dashboard bar chart) resolves no link. The drill-down only
  // takes over the surfaces it can actually serve, so the others keep navigating
  // to the entity page instead of going inert.
  const bucketLinkAt = drilldown ? memoizeByPoint(distributionBucketLink(drilldown)) : null;
  const hasDrilldownLink = (config) => !!bucketLinkAt?.(config);
  return {
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
            if (redirectionUtils[labelIndex]?.name === 'Restricted') {
              return;
            }
            const entityType = redirectionUtils[labelIndex]?.entity_type;
            const link = resolveLink(entityType);
            if (link) {
              const entityId = redirectionUtils[labelIndex]?.id;
              handleNavigate(event, navigate, `${link}/${entityId}`);
            }
          }
        },
        mouseMove: (event, chartContext, config) => {
        // With a drill-down, a bar opens the filtered list; without one it keeps
        // navigating to the entity page (public dashboards, multi-series bars).
          if (hasDrilldownLink(config)) {
            drilldownEvents.mouseMove(event, chartContext, config);
            return;
          }
          const { dataPointIndex, seriesIndex } = config;
          const isLegacyTarget = !!redirectionUtils
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
            );
          if (!event.target.style) return;
          if (isLegacyTarget) {
            // for clickable parts of the graphs
            event.target.style.cursor = 'pointer';
            event.target.classList.add('noDrag');
          } else {
            // ApexCharts reuses its SVG nodes between hovers, so a pointer set on
            // a previous target has to be taken back here or it lingers over
            // surfaces that navigate nowhere.
            event.target.style.cursor = 'default';
            event.target.classList?.remove('noDrag');
          }
        },
        click: (event, chartContext, config) => {
          if (hasDrilldownLink(config)) {
            drilldownEvents.click(event, chartContext, config);
            return;
          }
          if (redirectionUtils) {
            const { dataPointIndex, seriesIndex } = config;
            if (dataPointIndex >= 0) {
            // click on a bar
              if (
                seriesIndex >= 0
                && redirectionUtils[dataPointIndex]?.series
              ) {
              // for multi horizontal bars representing entities
                if (redirectionUtils[dataPointIndex].series[seriesIndex]?.entity_type) {
                // for series representing a single entity
                  const link = resolveLink(redirectionUtils[dataPointIndex].series[seriesIndex].entity_type);
                  if (link) {
                    const entityId = redirectionUtils[dataPointIndex].series[seriesIndex].id;
                    handleNavigate(event, navigate, `${link}/${entityId}`);
                  }
                }
              } else {
                if (redirectionUtils[dataPointIndex]?.name === 'Restricted') {
                  return;
                }
                const link = resolveLink(redirectionUtils[dataPointIndex]?.entity_type);
                if (link) {
                  const entityId = redirectionUtils[dataPointIndex]?.id;
                  handleNavigate(event, navigate, `${link}/${entityId}`);
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
        ? alpha(theme.palette.common.white, 0.1)
        : alpha(theme.palette.common.black, 0.1),
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
  };
};

/**
 * @param {Theme} theme
 * @param {function} xFormatter
 * @param {string[]} labels
 * @param {string[]} chartColors
 * @param {boolean} legend
 * @param {string} background
 * @param {int} size
 * @param {function} handleClick
 * @param {{ getLink: function, navigate: function, buckets: (object | null)[] }} [drilldown] Distribution drill-down descriptor.
 */
export const radarChartOptions = (
  theme,
  labels,
  xFormatter = null,
  chartColors = [],
  legend = false,
  // Ninth factory.
  background = theme.palette.background.paper,
  size = undefined,
  handleClick = undefined,
  drilldown = undefined,
) => {
  const drilldownEvents = distributionBucketEvents(drilldown);
  return {
    chart: {
      type: 'radar',
      background,
      toolbar: toolbarOptions,
      width: '100%',
      height: '100%',
      events: {
        ...drilldownEvents,
        // Only the opinions radar passes a handler; the dashboard widgets do not,
        // and calling it unconditionally used to throw on every click.
        ...(handleClick ? { markerClick: () => handleClick() } : {}),
        click: (event, chartContext, config) => {
          handleClick?.();
          drilldownEvents.click?.(event, chartContext, config);
        },
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
          // Coincides with the carrying surface, same rule as the chart background.
          fill: { colors: [theme.palette.background.paper] },
        },
      },
    },
  };
};

/**
 * @param {Theme} theme
 * @param {string[]} labels
 * @param {function} formatter
 * @param {string} legendPosition
 * @param {string[]} chartColors
 * @param {{ getLink: function, navigate: function, buckets: (object | null)[] }} [drilldown] Distribution drill-down descriptor.
 */
export const polarAreaChartOptions = (
  theme,
  labels,
  formatter = null,
  legendPosition = 'bottom',
  chartColors = [],
  drilldown = undefined,
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
      events: distributionBucketEvents(drilldown),
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
      floating: false,
      fontFamily: '"IBM Plex Sans", sans-serif',
      markers: { strokeWidth: 0 },
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
 * @param {{ getLink: function, navigate: function, buckets: (object | null)[] }} [drilldown] Distribution drill-down descriptor.
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
  drilldown = undefined,
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
      events: distributionBucketEvents(drilldown),
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
      // The slice separator reads as the surface showing through, so it follows
      // the surface: layer 1, not the hardcoded literal.
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
 * @param {{ getLink: function, navigate: function, buckets: (object | null)[] }} [drilldown] Distribution drill-down descriptor.
 */
export const treeMapOptions = (
  theme,
  formatter = null,
  legendPosition = 'bottom',
  distributed = false,
  drilldown = undefined,
) => {
  return {
    chart: {
      type: 'treemap',
      background: theme.palette.background.paper,
      toolbar: toolbarOptions,
      foreColor: theme.palette.text.secondary,
      width: '100%',
      height: '100%',
      events: distributionBucketEvents(drilldown),
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
      // The slice separator reads as the surface showing through, so it follows
      // the surface: layer 1, not the hardcoded literal.
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
    // Same rule as the other separators: it follows the carrying surface.
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
    show: true,
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
