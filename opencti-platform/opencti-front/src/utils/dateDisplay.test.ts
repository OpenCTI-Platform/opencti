import { describe, expect, it } from 'vitest';
import { createIntl } from 'react-intl';
import moment from 'moment';
import { DEFAULT_DATE_DISPLAY, formatTableDate, resolveDateDisplay } from './dateDisplay';
import { EMPTY_VALUE } from './String';

const intl = createIntl({ locale: 'en-us', messages: {} });
// Built in local time, as dates are displayed in the time zone of the browser.
const date = new Date(2024, 1, 6, 11, 54, 7);
const afternoon = new Date(2024, 1, 6, 15, 32, 7);
const offset = moment(date).format('Z');

describe('dateDisplay', () => {
  it('should let the user override the platform, and fall back to auto', () => {
    expect(resolveDateDisplay({}, {})).toEqual(DEFAULT_DATE_DISPLAY);
    expect(resolveDateDisplay({ date_format: 'auto', time_format: 'auto' }, { platform_date_format: 'iso', platform_time_format: 'minutes' }))
      .toEqual({ dateFormat: 'iso', timeFormat: 'minutes' });
    expect(resolveDateDisplay({ date_format: 'auto', time_format: 'none' }, { platform_date_format: 'iso', platform_time_format: 'seconds' }))
      .toEqual({ dateFormat: 'iso', timeFormat: 'none' });
    expect(resolveDateDisplay({ date_format: '%future added value' }, { platform_date_format: null }))
      .toEqual(DEFAULT_DATE_DISPLAY);
  });

  it('should keep the display of each column by default', () => {
    expect(formatTableDate(intl, date, DEFAULT_DATE_DISPLAY, 'none'))
      .toEqual(intl.formatDate(date, { day: 'numeric', month: 'short', year: 'numeric' }));
    expect(formatTableDate(intl, date, DEFAULT_DATE_DISPLAY, 'seconds'))
      .toEqual(intl.formatDate(date, { second: 'numeric', minute: 'numeric', hour: 'numeric', day: 'numeric', month: 'short', year: 'numeric' }));
  });

  it('should keep the month of the column, unless the date is written as ISO 8601', () => {
    expect(formatTableDate(intl, date, DEFAULT_DATE_DISPLAY, 'seconds', 'long'))
      .toEqual(intl.formatDate(date, { second: 'numeric', minute: 'numeric', hour: 'numeric', day: 'numeric', month: 'long', year: 'numeric' }));
    expect(formatTableDate(intl, date, { dateFormat: 'auto', timeFormat: 'none' }, 'seconds', 'numeric'))
      .toEqual(intl.formatDate(date, { day: 'numeric', month: 'numeric', year: 'numeric' }));
    expect(formatTableDate(intl, date, { dateFormat: 'iso', timeFormat: 'none' }, 'seconds', 'long')).toEqual('2024-02-06');
  });

  it('should force the time of every column', () => {
    expect(formatTableDate(intl, date, { dateFormat: 'auto', timeFormat: 'minutes' }, 'none'))
      .toEqual(intl.formatDate(date, { minute: 'numeric', hour: 'numeric', hourCycle: 'h23', day: 'numeric', month: 'short', year: 'numeric' }));
    expect(formatTableDate(intl, date, { dateFormat: 'auto', timeFormat: 'none' }, 'seconds'))
      .toEqual(intl.formatDate(date, { day: 'numeric', month: 'short', year: 'numeric' }));
  });

  it('should show a chosen time on 24 hours, whatever the language', () => {
    expect(formatTableDate(intl, afternoon, { dateFormat: 'auto', timeFormat: 'minutes' }, 'none')).toContain('15:32');
    expect(formatTableDate(intl, afternoon, { dateFormat: 'auto', timeFormat: 'seconds' }, 'none')).toContain('15:32:07');
    // The automatic display keeps the clock of the language.
    expect(formatTableDate(intl, afternoon, DEFAULT_DATE_DISPLAY, 'seconds')).toContain('3:32:07');
  });

  it('should write the date as ISO 8601, with the offset of its time', () => {
    expect(formatTableDate(intl, date, { dateFormat: 'iso', timeFormat: 'auto' }, 'none')).toEqual('2024-02-06');
    expect(formatTableDate(intl, date, { dateFormat: 'iso', timeFormat: 'auto' }, 'seconds')).toEqual(`2024-02-06 11:54:07${offset}`);
    expect(formatTableDate(intl, date, { dateFormat: 'iso', timeFormat: 'minutes' }, 'none')).toEqual(`2024-02-06 11:54${offset}`);
  });

  it('should not display an invalid date', () => {
    expect(formatTableDate(intl, 'not a date', DEFAULT_DATE_DISPLAY, 'none')).toEqual(EMPTY_VALUE);
    expect(formatTableDate(intl, 'not a date', { dateFormat: 'iso', timeFormat: 'seconds' }, 'none')).toEqual(EMPTY_VALUE);
  });
});
