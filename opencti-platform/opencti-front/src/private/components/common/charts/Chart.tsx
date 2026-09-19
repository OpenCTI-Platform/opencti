import { useMemo } from 'react';
import ApexChart, { Props as ApexProps } from 'react-apexcharts';
import ApexCharts from 'apexcharts';
import { sanitize } from '../../../../utils/String';

export interface OpenCTIChartProps extends ApexProps {
  onMounted?: (chart: ApexCharts) => void;
}

type ApexOptions = NonNullable<ApexProps['options']>;
type ApexFormatter = (value: never, options?: never) => string;

const toDisplayString = (value: unknown): string => {
  if (Array.isArray(value)) return value.join(' ');
  return String(value ?? '');
};

/**
 * Legend items and tooltips are the only parts of a chart that ApexCharts renders through
 * `innerHTML`; axis labels, data labels and exports all go through SVG text nodes. Escaping is
 * applied here, on the values on their way to those HTML outputs, so labels keep their original
 * characters (`&`, `<`, `>`) everywhere else.
 *
 * @param value Value about to be rendered as HTML.
 * @returns The escaped value.
 */
const escapeForHtmlOutput = (value: unknown): string => sanitize(toDisplayString(value), true);

/**
 * Build a formatter escaping the output of the formatter already configured on the chart, or the
 * output of `fallback` when no formatter is configured, so the displayed value stays the same.
 *
 * @param formatter Formatter configured on the chart, if any.
 * @param fallback Formatting applied by ApexCharts when no formatter is configured.
 * @returns The wrapped formatter.
 */
const wrapFormatter = (formatter: unknown, fallback?: (value: unknown) => unknown) => {
  return (value: unknown, formatterOptions: unknown) => {
    if (typeof formatter === 'function') {
      return escapeForHtmlOutput((formatter as ApexFormatter)(value as never, formatterOptions as never));
    }
    return escapeForHtmlOutput(fallback ? fallback(value) : value);
  };
};

/**
 * Resolve the formatter ApexCharts applies to a category before displaying it as the tooltip
 * title, so wrapping the tooltip preserves the formatting configured on the axis (date
 * conversion, truncation, ...) instead of falling back to the raw value.
 *
 * @param options Chart options.
 * @returns The axis formatter used for the tooltip title, if any.
 */
const getCategoryFormatter = (options: ApexOptions | undefined) => {
  if (options?.plotOptions?.bar?.horizontal !== true) {
    return options?.xaxis?.labels?.formatter;
  }
  const yaxis = Array.isArray(options.yaxis) ? options.yaxis[0] : options.yaxis;
  return yaxis?.labels?.formatter;
};

const Chart = ({
  options,
  series,
  type,
  width,
  height,
  onMounted,
}: OpenCTIChartProps) => {
  // Add in config a callback on 'mounted event' to retrieve chart context.
  // This context is used to export in different format.
  const apexOptions: ApexProps['options'] = useMemo(() => {
    const categoryFormatter = getCategoryFormatter(options);
    // A datetime axis builds its tooltip title through a dedicated path that a custom formatter
    // would bypass, and displays timestamps, so it is left untouched.
    const isDateTimeAxis = options?.xaxis?.type === 'datetime';
    const tooltipY = Array.isArray(options?.tooltip?.y) ? options?.tooltip?.y[0] : options?.tooltip?.y;
    return {
      ...options,
      chart: {
        ...options?.chart,
        events: {
          ...options?.chart?.events,
          mounted: onMounted,
        },
      },
      legend: {
        ...options?.legend,
        formatter: wrapFormatter(options?.legend?.formatter),
      },
      tooltip: {
        ...options?.tooltip,
        x: {
          ...options?.tooltip?.x,
          ...(isDateTimeAxis ? {} : {
            formatter: wrapFormatter(
              options?.tooltip?.x?.formatter,
              categoryFormatter && ((value: unknown) => (categoryFormatter as ApexFormatter)(value as never)),
            ),
          }),
        },
        y: {
          ...tooltipY,
          title: {
            ...tooltipY?.title,
            formatter: wrapFormatter(
              tooltipY?.title?.formatter,
              (value) => (value ? `${toDisplayString(value)}: ` : ''),
            ),
          },
        },
      },
    } as ApexOptions;
  }, [options]);

  return (
    <ApexChart
      options={apexOptions}
      series={series}
      type={type}
      width={width}
      height={height}
    />
  );
};

export default Chart;
