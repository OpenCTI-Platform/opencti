import moment from 'moment';
import type { Filter } from '../../filters/filtersHelpers-types';
import type { WidgetDateRange } from './widgetDrilldown-types';

const INTERVAL_UNITS: Record<string, moment.unitOfTime.DurationConstructor> = {
  day: 'day',
  week: 'week',
  month: 'month',
  quarter: 'quarter',
  year: 'year',
};

/**
 * Recovers the Elasticsearch bucket start from the date returned by the API.
 *
 * `fillTimeSeries` computes period starts using the offset carried by the dates
 * the frontend sent, so the returned instant is the local period start expressed
 * in UTC. Its local calendar day *is* the bucket. Reinterpreting that day at UTC
 * midnight yields the true Elasticsearch boundary.
 */
const toUtcBucketStart = (bucketDate: string) => {
  const local = moment(bucketDate, moment.ISO_8601);
  if (!local.isValid()) return null;
  return moment.utc(local.format('YYYY-MM-DD'), 'YYYY-MM-DD', true);
};

/**
 * Builds the date filters reproducing exactly the documents counted by one
 * time-series bucket: `[bucketStart, bucketEnd[`, clamped by the widget's own
 * range, since Elasticsearch truncates the first and last buckets.
 */
export const buildBucketDateFilter = (
  bucketDate: string,
  interval: string,
  range: WidgetDateRange,
  dateAttribute: string,
): Filter[] | null => {
  const unit = INTERVAL_UNITS[interval];
  if (!unit) return null;

  const bucketStart = toUtcBucketStart(bucketDate);
  if (!bucketStart || !bucketStart.isValid()) return null;
  const bucketEnd = bucketStart.clone().add(1, unit);

  const rangeStart = range.startDate ? moment.utc(range.startDate) : null;
  const rangeEnd = range.endDate ? moment.utc(range.endDate) : null;

  const lowerBound = rangeStart?.isValid() && rangeStart.isAfter(bucketStart) ? rangeStart : bucketStart;
  const isUpperClamped = !!rangeEnd?.isValid() && rangeEnd.isBefore(bucketEnd);
  const upperBound = isUpperClamped ? rangeEnd! : bucketEnd;

  return [
    { key: dateAttribute, values: [lowerBound.toISOString()], operator: 'gte', mode: 'or' },
    { key: dateAttribute, values: [upperBound.toISOString()], operator: isUpperClamped ? 'lte' : 'lt', mode: 'or' },
  ];
};
