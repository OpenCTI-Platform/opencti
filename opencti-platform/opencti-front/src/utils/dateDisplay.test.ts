import { describe, expect, it } from 'vitest';
import { createIntl } from 'react-intl';
import { DEFAULT_DATE_DISPLAY, formatTableDate, resolveDateDisplay } from './dateDisplay';

const intl = createIntl({ locale: 'en-us', messages: {} });
// Built in local time, as dates are displayed in the time zone of the browser.
const date = new Date(2024, 1, 6, 11, 54, 7);

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

  it('should force the time of every column', () => {
    expect(formatTableDate(intl, date, { dateFormat: 'auto', timeFormat: 'minutes' }, 'none'))
      .toEqual(intl.formatDate(date, { minute: 'numeric', hour: 'numeric', day: 'numeric', month: 'short', year: 'numeric' }));
    expect(formatTableDate(intl, date, { dateFormat: 'auto', timeFormat: 'none' }, 'seconds'))
      .toEqual(intl.formatDate(date, { day: 'numeric', month: 'short', year: 'numeric' }));
  });

  it('should write the date as ISO 8601', () => {
    expect(formatTableDate(intl, date, { dateFormat: 'iso', timeFormat: 'auto' }, 'none')).toEqual('2024-02-06');
    expect(formatTableDate(intl, date, { dateFormat: 'iso', timeFormat: 'auto' }, 'seconds')).toEqual('2024-02-06 11:54:07');
    expect(formatTableDate(intl, date, { dateFormat: 'iso', timeFormat: 'minutes' }, 'none')).toEqual('2024-02-06 11:54');
  });
});
