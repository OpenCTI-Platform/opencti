import { DateTime } from 'luxon';
import convert, { type Unit } from 'convert';
import { FROM_START_STR, UNTIL_END_STR } from './format';

export type Formating = {
  locale: string;
  tz: string;
  unit_system: 'Imperial' | 'Metric';
  date_format: string;
};

export const DefaultFormating: Formating = {
  locale: 'en',
  tz: 'UTC',
  unit_system: 'Metric',
  date_format: 'MMMM dd yyyy, h:mm:ss a',
};

export const humanizeWeight = (value: number, format: Formating = DefaultFormating) => {
  const unit = format.unit_system === 'Imperial' ? 'lb' : 'kg';
  return convert<number, Unit>(value, 'kg').to(unit).toFixed(2) + ' (' + unit + ')';
};

export const humanizeHeight = (value: number, format: Formating = DefaultFormating) => {
  const unit = format.unit_system === 'Imperial' ? 'ft' : 'm';
  return convert<number, Unit>(value, 'm').to(unit).toFixed(2) + ' (' + unit + ')';
};

export const humanizeDate = (value: string, format: Formating = DefaultFormating) => {
  if (value === FROM_START_STR || value === UNTIL_END_STR) {
    return ''; // These values are considered empty for human
  }
  const isoDate = DateTime.fromISO(value);
  if (!isoDate.isValid) {
    return 'Invalid date';
  }
  return isoDate
    .setZone(format.tz)
    .setLocale(format.locale)
    .toFormat(format.date_format ?? 'MMMM dd yyyy, h:mm:ss a');
};
