export const areaChartOptions = (
  theme,
  isTimeSeries = false,
  xFormatter = null,
  yFormatter = null,
  tickAmount = undefined,
) => ({
  chart: {
    type: 'area',
    toolbar: {
      show: false,
    },
    foreColor: theme.palette.text.secondary,
  },
  dataLabels: {
    enabled: false,
  },
  stroke: {
    curve: 'smooth',
    width: 2,
  },
  colors: [theme.palette.primary.main],
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
  fill: {
    type: 'gradient',
    gradient: {
      shade: theme.palette.mode,
      shadeIntensity: 1,
      opacityFrom: 0.7,
      opacityTo: 0.4,
      gradientToColors: [theme.palette.background.default, theme.palette.primary.main],
    },
  },
  xaxis: {
    type: isTimeSeries ? 'datetime' : 'category',
    tickAmount,
    tickPlacement: 'on',
    labels: {
      formatter: (value) => (xFormatter ? xFormatter(value) : value),
      style: {
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
});

export const distributionChartOptions = (
  theme,
  adjustTicks = false,
  xFormatter = null,
  yFormatter = null,
) => ({
  chart: {
    type: 'bar',
    toolbar: {
      show: false,
    },
    foreColor: theme.palette.text.secondary,
  },
  dataLabels: {
    enabled: false,
  },
  colors: [theme.palette.primary.main],
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
    },
  },
});

export const polarAreaChartOptions = (theme, labels, formatter = null) => ({
  chart: {
    type: 'polarArea',
    toolbar: {
      show: false,
    },
    foreColor: theme.palette.text.secondary,
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
    show: true,
    position: 'right',
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
