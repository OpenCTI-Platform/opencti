import React, { Component } from 'react';
import { injectIntl, useIntl } from 'react-intl';
import moment from 'moment-timezone';
import { startOfWeek, format } from 'date-fns';
import { bytesFormat, numberFormat } from '../utils/Number';

const FROM_START = 0;
const UNTIL_END = 100000000000000;

export const isDateStringNone = (dateString) => {
  if (!dateString) return true;
  if (dateString === (new Date(FROM_START).toISOString())) return true;
  if (dateString === (new Date(UNTIL_END).toISOString())) return true;
  return (
    dateString.startsWith('Invalid')
    || dateString.startsWith('1970')
    || dateString.startsWith('5138')
  );
};

export const isNone = (date) => {
  if (!date) return true;
  if (date.length === 0) return true;
  if (date === (new Date(FROM_START).toISOString())) return true;
  if (date === (new Date(UNTIL_END).toISOString())) return true;
  const parsedDate = moment(date).format();
  return isDateStringNone(parsedDate);
};

const inject18n = (WrappedComponent) => {
  class InjectIntl extends Component {
    render() {
      const { children } = this.props;
      const translate = (message) => this.props.intl.formatMessage({ id: message });
      const formatNumber = (number) => {
        if (number === null || number === '') {
          return '-';
        }
        return `${this.props.intl.formatNumber(numberFormat(number).number)}${
          numberFormat(number).symbol
        }`;
      };
      const formatBytes = (number) => `${this.props.intl.formatNumber(bytesFormat(number).number)}${
        bytesFormat(number).symbol
      }`;
      const longDate = (date) => {
        if (isNone(date)) {
          return '-';
        }
        return this.props.intl.formatDate(date, {
          day: 'numeric',
          month: 'long',
          year: 'numeric',
        });
      };
      const longDateTime = (date) => {
        if (isNone(date)) {
          return '-';
        }
        return this.props.intl.formatDate(date, {
          day: 'numeric',
          month: 'long',
          year: 'numeric',
          second: 'numeric',
          minute: 'numeric',
          hour: 'numeric',
        });
      };
      const shortDate = (date) => {
        if (isNone(date)) {
          return '-';
        }
        return this.props.intl.formatDate(date, {
          day: 'numeric',
          month: 'short',
          year: 'numeric',
        });
      };
      const shortNumericDate = (date) => {
        if (isNone(date)) {
          return '-';
        }
        return this.props.intl.formatDate(date, {
          day: 'numeric',
          month: 'numeric',
          year: 'numeric',
        });
      };
      const shortNumericDateTime = (date) => {
        if (isNone(date)) {
          return '-';
        }
        return this.props.intl.formatDate(date, {
          second: 'numeric',
          minute: 'numeric',
          hour: 'numeric',
          day: 'numeric',
          month: 'short',
          year: 'numeric',
        });
      };
      const standardDate = (date) => {
        if (isNone(date)) {
          return '-';
        }
        return this.props.intl.formatDate(date, {
          day: 'numeric',
          month: 'short',
          year: 'numeric',
        });
      };
      const monthDate = (date) => {
        if (isNone(date)) {
          return '-';
        }
        return this.props.intl.formatDate(date, {
          month: 'short',
          year: 'numeric',
        });
      };
      const monthTextDate = (date) => {
        if (isNone(date)) {
          return '-';
        }
        return this.props.intl.formatDate(date, { month: 'long' });
      };
      const monthTextYearDate = (date) => {
        if (isNone(date)) {
          return '-';
        }
        return this.props.intl.formatDate(date, {
          month: 'long',
          year: 'numeric',
        });
      };
      const yearDate = (date) => {
        if (isNone(date)) {
          return '-';
        }
        return this.props.intl.formatDate(date, { year: 'numeric' });
      };
      return (
        <WrappedComponent
          {...this.props}
          {...{ t: translate }}
          {...{ n: formatNumber }}
          {...{ b: formatBytes }}
          {...{ fld: longDate }}
          {...{ fldt: longDateTime }}
          {...{ fsd: shortDate }}
          {...{ nsd: shortNumericDate }}
          {...{ nsdt: shortNumericDateTime }}
          {...{ fd: standardDate }}
          {...{ md: monthDate }}
          {...{ mtd: monthTextDate }}
          {...{ mtdy: monthTextYearDate }}
          {...{ yd: yearDate }}
        >
          {children}
        </WrappedComponent>
      );
    }
  }
  return injectIntl(InjectIntl);
};

export const useFormatter = () => {
  const intl = useIntl();
  const translate = (message, { id, values } = {}) => intl.formatMessage({ id: id ?? message }, values);
  const formatNumber = (number) => {
    if (number === null || number === '') {
      return '-';
    }
    return `${intl.formatNumber(numberFormat(number).number)}${
      numberFormat(number).symbol
    }`;
  };
  const formatBytes = (number) => `${intl.formatNumber(bytesFormat(number).number)}${
    bytesFormat(number).symbol
  }`;
  const longDate = (date) => {
    if (isNone(date)) {
      return '-';
    }
    return intl.formatDate(date, {
      day: 'numeric',
      month: 'long',
      year: 'numeric',
    });
  };
  const longDateTime = (date) => {
    if (isNone(date)) {
      return '-';
    }
    return intl.formatDate(date, {
      day: 'numeric',
      month: 'long',
      year: 'numeric',
      second: 'numeric',
      minute: 'numeric',
      hour: 'numeric',
    });
  };
  const shortDate = (date) => {
    if (isNone(date)) {
      return '-';
    }
    return intl.formatDate(date, {
      day: 'numeric',
      month: 'short',
      year: 'numeric',
    });
  };
  const shortNumericDate = (date) => {
    if (isNone(date)) {
      return '-';
    }
    return intl.formatDate(date, {
      day: 'numeric',
      month: 'numeric',
      year: 'numeric',
    });
  };

  /**
   * A date that stop precision at minute. For example "06 Feb 2024 11:54 AM".
   * @param date
   * @returns {string}
   */
  const minuteHourDate = (date) => {
    if (isNone(date)) {
      return '-';
    }
    return intl.formatDate(date, {
      minute: 'numeric',
      hour: 'numeric',
      day: 'numeric',
      month: 'short',
      year: 'numeric',
    });
  };

  /**
   * A date that stop precision at minute. For example "02/06/2024 11:54 AM".
   * @param date
   * @returns {string}
   */
  const shortMinuteHourDate = (date) => {
    if (isNone(date)) {
      return '-';
    }
    return intl.formatDate(date, {
      minute: 'numeric',
      hour: 'numeric',
      day: 'numeric',
      month: 'numeric',
      year: 'numeric',
    }).replace(',', ''); // remove comma between date and hours
  };

  const MONTH_IN_MILLIS = 2.592e9;
  const WEEK_IN_MILLIS = 6.048e8;
  const DAY_IN_MILLIS = 8.64e7;
  const HOUR_IN_MILLIS = 3.6e6;
  const MIN_IN_MILLIS = 6e4;
  const SEC_IN_MILLIS = 1e3;

  const timeUnits = [
    { unit: 'month', interval: MONTH_IN_MILLIS },
    { unit: 'week', interval: WEEK_IN_MILLIS },
    { unit: 'day', interval: DAY_IN_MILLIS },
    { unit: 'hour', interval: HOUR_IN_MILLIS },
    { unit: 'minute', interval: MIN_IN_MILLIS },
    { unit: 'second', interval: SEC_IN_MILLIS },
  ];

  const roundedValue = (diff, interval) => Math.round(diff / interval);

  /**
   * Relative from now in word. Like "2 months ago", "in 3 minutes"...
   * @param date
   * @returns {string}
   */
  const relativeDate = (date) => {
    if (isNone(date)) {
      return '-';
    }
    const diff = new Date(date) - new Date();
    for (const { unit, interval } of timeUnits) {
      if (Math.abs(diff) > interval) {
        const rounded = roundedValue(diff, interval);
        return intl.formatRelativeTime(rounded, unit);
      }
    }

    const rounded = roundedValue(diff, SEC_IN_MILLIS);
    return intl.formatRelativeTime(rounded, 'second');
  };

  const shortNumericDateTime = (date) => {
    if (isNone(date)) {
      return '-';
    }
    return intl.formatDate(date, {
      second: 'numeric',
      minute: 'numeric',
      hour: 'numeric',
      day: 'numeric',
      month: 'short',
      year: 'numeric',
    });
  };
  const fullNumericDateTime = (date) => {
    if (isNone(date)) {
      return '-';
    }
    return intl.formatDate(date, {
      second: 'numeric',
      minute: 'numeric',
      hour: 'numeric',
      day: 'numeric',
      month: 'numeric',
      year: 'numeric',
    });
  };
  const standardDate = (date) => {
    if (isNone(date)) {
      return '-';
    }
    return intl.formatDate(date, {
      day: 'numeric',
      month: 'short',
      year: 'numeric',
    });
  };
  const monthDate = (date) => {
    if (isNone(date)) {
      return '-';
    }
    return intl.formatDate(date, {
      month: 'short',
      year: 'numeric',
    });
  };
  const monthTextDate = (date) => {
    if (isNone(date)) {
      return '-';
    }
    return intl.formatDate(date, { month: 'long' });
  };
  const monthTextYearDate = (date) => {
    if (isNone(date)) {
      return '-';
    }
    return intl.formatDate(date, { month: 'long', year: 'numeric' });
  };
  const yearDate = (date) => {
    if (isNone(date)) {
      return '-';
    }
    return intl.formatDate(date, { year: 'numeric' });
  };
  const numericTime = (date) => {
    if (isNone(date)) {
      return '-';
    }
    return intl.formatDate(date, {
      second: 'numeric',
      minute: 'numeric',
      hour: 'numeric',
    });
  };
  const yearWeeksIntoYear = (date) => {
    if (isNone(date)) {
      return '-';
    }
    // the following few lines get the date to display as the number of weeks into the year with weeks starting on Mondays
    const value = new Date(date);
    const weekStart = startOfWeek(value, { weekStartsOn: 1 });
    const weekEnd = new Date(weekStart);
    weekEnd.setDate(weekEnd.getDate() + 6);
    return `${format(weekStart, 'MMM dd')} - ${format(weekEnd, 'MMM dd')}`;
  };
  return {
    t_i18n: translate,
    n: formatNumber,
    b: formatBytes,
    fld: longDate,
    fldt: longDateTime,
    fsd: shortDate,
    nsd: shortNumericDate,
    nsdt: shortNumericDateTime,
    fndt: fullNumericDateTime,
    fd: standardDate,
    md: monthDate,
    mtd: monthTextDate,
    mtdy: monthTextYearDate,
    yd: yearDate,
    nt: numericTime,
    mhd: minuteHourDate,
    smhd: shortMinuteHourDate,
    rd: relativeDate,
    ywiy: yearWeeksIntoYear,
  };
};

export default inject18n;
