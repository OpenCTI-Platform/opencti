import { describe, expect, it } from 'vitest';
import moment from 'moment';
import { confNameToEnvName } from '../../../src/config/conf';

// The relations deduplication window is computed with moment(date).subtract(past_days, 'days')
// and moment(date).add(next_days, 'days'). These tests lock the values accepted by past_days / next_days.
const REFERENCE_DATE = '2026-01-01T10:00:00.000Z';

const shiftToPast = (value: unknown) => moment.utc(REFERENCE_DATE).subtract(value as moment.DurationInputArg1, 'days').toISOString();
const shiftToNext = (value: unknown) => moment.utc(REFERENCE_DATE).add(value as moment.DurationInputArg1, 'days').toISOString();

describe('Relations deduplication window values', () => {
  it('should read a number as days', () => {
    expect(shiftToPast(30)).toEqual('2025-12-02T10:00:00.000Z');
    expect(shiftToNext(30)).toEqual('2026-01-31T10:00:00.000Z');
  });

  it('should read a numeric string as days', () => {
    expect(shiftToPast('30')).toEqual('2025-12-02T10:00:00.000Z');
  });

  it('should round fractional days', () => {
    expect(shiftToPast(0.0208)).toEqual(REFERENCE_DATE);
    expect(shiftToNext(0.5)).toEqual('2026-01-02T10:00:00.000Z');
  });

  it('should read an ISO 8601 duration, ignoring the days unit', () => {
    expect(shiftToPast('PT30M')).toEqual('2026-01-01T09:30:00.000Z');
    expect(shiftToNext('PT30M')).toEqual('2026-01-01T10:30:00.000Z');
    expect(shiftToNext('PT6H')).toEqual('2026-01-01T16:00:00.000Z');
    expect(shiftToPast('P1DT12H')).toEqual('2025-12-30T22:00:00.000Z');
  });

  it('should give a window of 0 for an invalid value', () => {
    expect(shiftToPast('30m')).toEqual(REFERENCE_DATE);
    expect(shiftToPast('Test')).toEqual(REFERENCE_DATE);
  });

  it('should expose the sighting override through a TYPES_OVERRIDES environment variable', () => {
    expect(confNameToEnvName('relations_deduplication:types_overrides:stix-sighting-relationship:past_days'))
      .toEqual('RELATIONS_DEDUPLICATION__TYPES_OVERRIDES__STIX-SIGHTING-RELATIONSHIP__PAST_DAYS');
  });
});
