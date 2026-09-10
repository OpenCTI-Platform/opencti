import { useCallback } from 'react';
import { useIntl } from 'react-intl';
import { isNone } from '../../components/i18n';
import { EMPTY_VALUE } from '../String';

export type TimeSeriesAxisFormatter = (date: string | number | Date | null | undefined) => string;

const axisFormatOptions = (interval?: string | null): Intl.DateTimeFormatOptions => {
  if (interval === 'month' || interval === 'quarter') {
    return { month: 'long', year: 'numeric' };
  }
  if (interval === 'year') {
    return { year: 'numeric' };
  }
  return { day: 'numeric', month: 'short', year: 'numeric' };
};

/**
 * Labels a time series axis in UTC.
 *
 * The platform emits bucket starts as UTC instants, because Elasticsearch aggregates
 * on UTC calendar boundaries. Labelling them in the browser time zone would slide the
 * whole axis by one bucket for every reader whose offset differs from UTC, hiding the
 * last completed period. See https://github.com/OpenCTI-Platform/opencti/issues/12150
 */
const useTimeSeriesAxisFormatter = (interval?: string | null): TimeSeriesAxisFormatter => {
  const intl = useIntl();
  return useCallback((date) => {
    if (date === null || date === undefined || isNone(date)) {
      return EMPTY_VALUE;
    }
    return intl.formatDate(date, { ...axisFormatOptions(interval), timeZone: 'UTC' });
  }, [intl, interval]);
};

export default useTimeSeriesAxisFormatter;
