import { isDateStringNone } from '../../i18n';
import { dayEndDate, daysAfter, daysAgo, jsDate, minutesBefore, minutesBetweenDates, timestamp } from '../../../utils/Time';
import { GraphLink } from '../graph.types';

export interface GraphTimeRange {
  interval: [Date, Date]
  values: {
    index: number,
    time: number,
    value: number
  }[]
}

/**
 * Determines start (min) and end (max) date in array of data.
 * By default start = now - 1 day, end = now.
 *
 * @param objects Array of objects to determine time range.
 * @returns [start, end] both date objects.
 */
export const computeTimeRangeInterval = (
  objects: GraphLink[],
): GraphTimeRange['interval'] => {
  let startDate = jsDate(daysAgo(1));
  let endDate = jsDate(dayEndDate());

  const filteredDates = objects.flatMap((o) => {
    const isRelationship = o.parent_types && o.parent_types.includes('basic-relationship');
    const date = !Number.isNaN(o.defaultDate.getTime()) ? o.defaultDate.toISOString() : null;
    if (!isRelationship || date === null || isDateStringNone(date)) return [];
    return jsDate(date);
  }).sort((a, b) => a.getTime() - b.getTime());

  if (filteredDates.length >= 1) {
    startDate = jsDate(daysAgo(1, filteredDates[0]));
    endDate = jsDate(daysAfter(1, filteredDates[0]));
  }
  if (filteredDates.length >= 2) {
    endDate = jsDate(daysAfter(1, filteredDates.slice(-1)[0]));
  }
  return [startDate, endDate];
};

/**
 * Determines how many objects there is by segment in the interval.
 *
 * @param interval The interval to make computation on.
 * @param objects Objects to split into segments.
 * @returns An array of tuples (time, number of objects inside segment).
 */
export const computeTimeRangeValues = (
  interval: GraphTimeRange['interval'],
  objects: GraphLink[],
): GraphTimeRange['values'] => {
  const minutes = minutesBetweenDates(interval[0], interval[1]);
  const intervalInMinutes = Math.ceil(minutes / 100);
  const intervalInSeconds = intervalInMinutes * 60;

  const elementsDates = objects.flatMap((o) => {
    const isRelationship = o.parent_types && o.parent_types.includes('basic-relationship');
    const date = !Number.isNaN(o.defaultDate.getTime()) ? o.defaultDate.toISOString() : null;
    if (!isRelationship || date === null || isDateStringNone(date)) return [];
    return timestamp(date);
  });

  return Array(100).fill(0).map((_, i) => {
    const time: number = timestamp(minutesBefore(minutes - i * intervalInMinutes, interval[1]));
    const datesInsideInterval = elementsDates.filter((d) => d >= time && d <= time + intervalInSeconds);
    return {
      time,
      index: 1,
      value: datesInsideInterval.length,
    };
  });
};

/**
 * Determines min and max of values domain.
 * Min is always 0, just to find the max.
 *
 * @param data Data to find max.
 * @returns [min, max] values.
 */
export const computeTimeRangeValuesDomain = (
  data: ReturnType<typeof computeTimeRangeValues>,
) => {
  return [0, Math.max.apply(null, data.map((entry) => entry.value))];
};
