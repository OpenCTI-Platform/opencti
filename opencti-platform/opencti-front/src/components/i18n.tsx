import React, { Component, ReactNode, ComponentType } from 'react';
import { injectIntl, useIntl, WrappedComponentProps, IntlShape } from 'react-intl';
import moment from 'moment-timezone';
import { bytesFormat, numberFormat } from '../utils/Number';
import { EMPTY_VALUE } from '../utils/String';

const FROM_START = 0;
const UNTIL_END = 100000000000000;

export const isDateStringNone = (dateString: string): boolean => {
  if (!dateString) return true;
  if (dateString === (new Date(FROM_START).toISOString())) return true;
  if (dateString === (new Date(UNTIL_END).toISOString())) return true;
  return (
    dateString.startsWith('Invalid')
    || dateString.startsWith('1970')
    || dateString.startsWith('5138')
  );
};

export const isNone = (date: string | number | Date | null | undefined): boolean => {
  if (!date) return true;
  if (typeof date === 'string' && date.length === 0) return true;
  if (date === (new Date(FROM_START).toISOString())) return true;
  if (date === (new Date(UNTIL_END).toISOString())) return true;
  const parsedDate = moment(date).format();
  return isDateStringNone(parsedDate);
};

interface InjectedFormatterProps {
  t: (message: string) => string;
  n: (number: number | string | null | undefined) => string;
  b: (number: number | string | null | undefined) => string;
  fld: (date: string | number | Date | null | undefined) => string;
  fldt: (date: string | number | Date | null | undefined) => string;
  fsd: (date: string | number | Date | null | undefined) => string;
  nsd: (date: string | number | Date | null | undefined) => string;
  nsdt: (date: string | number | Date | null | undefined) => string;
  fd: (date: string | number | Date | null | undefined) => string;
  md: (date: string | number | Date | null | undefined) => string;
  mtd: (date: string | number | Date | null | undefined) => string;
  mtdy: (date: string | number | Date | null | undefined) => string;
  yd: (date: string | number | Date | null | undefined) => string;
}

const inject18n = <P extends InjectedFormatterProps>(WrappedComponent: ComponentType<P>) => {
  class InjectIntl extends Component<P & WrappedComponentProps & { children?: ReactNode }> {
    render() {
      const { children, intl, ...otherProps } = this.props;

      const translate = (message: string) => intl.formatMessage({ id: message });

      const formatNumber = (number: number | string | null | undefined) => {
        if (number === null || number === '') return EMPTY_VALUE;
        const formatted = numberFormat(number as number);
        return `${intl.formatNumber(formatted.number)}${formatted.symbol}`;
      };

      const formatBytes = (number: number | string | null | undefined) => {
        const formatted = bytesFormat(number as number);
        return `${intl.formatNumber(formatted.number)}${formatted.symbol}`;
      };

      // Helper to handle the "isNone" logic for all date functions
      const formatDate = (date: string | number | Date | null | undefined, options: Intl.DateTimeFormatOptions) => {
        return isNone(date) ? EMPTY_VALUE : intl.formatDate(date as Date, options);
      };

      // Group all injected props into a single typed object
      const injected: InjectedFormatterProps = {
        t: translate,
        n: formatNumber,
        b: formatBytes,
        fld: (d) => formatDate(d, { day: 'numeric', month: 'long', year: 'numeric' }),
        fldt: (d) => formatDate(d, { day: 'numeric', month: 'long', year: 'numeric', second: 'numeric', minute: 'numeric', hour: 'numeric' }),
        fsd: (d) => formatDate(d, { day: 'numeric', month: 'short', year: 'numeric' }),
        nsd: (d) => formatDate(d, { day: 'numeric', month: 'numeric', year: 'numeric' }),
        nsdt: (d) => formatDate(d, { second: 'numeric', minute: 'numeric', hour: 'numeric', day: 'numeric', month: 'short', year: 'numeric' }),
        fd: (d) => formatDate(d, { day: 'numeric', month: 'short', year: 'numeric' }),
        md: (d) => formatDate(d, { month: 'short', year: 'numeric' }),
        mtd: (d) => formatDate(d, { month: 'long' }),
        mtdy: (d) => formatDate(d, { month: 'long', year: 'numeric' }),
        yd: (d) => formatDate(d, { year: 'numeric' }),
      };

      return (
        <WrappedComponent
          {...(otherProps as P)}
          {...(injected as P)}
        >
          {children}
        </WrappedComponent>
      );
    }
  }
  // Use "ComponentType<any>" here only for the internal react-intl HOC wrapper
  // to avoid complex internal library type mismatches
  return injectIntl(InjectIntl as ComponentType<any>);
};

export const useFormatter = () => {
  const intl: IntlShape = useIntl();
  const translate = (message: string, { id, values }: { id?: string; values?: Record<string, any> } = {}): string => intl.formatMessage({ id: id ?? message }, values);
  const formatNumber = (number: number | string | null | undefined): string => {
    if (number === null || number === '') {
      return EMPTY_VALUE;
    }
    const formatted = numberFormat(number as number);
    return `${intl.formatNumber(formatted.number)}${
      formatted.symbol
    }`;
  };
  const formatBytes = (number: number | string | null | undefined): string => {
    const formatted = bytesFormat(number as number);
    return `${intl.formatNumber(formatted.number)}${
      formatted.symbol
    }`;
  };
  const longDate = (date: string | number | Date | null | undefined): string => {
    if (isNone(date)) {
      return EMPTY_VALUE;
    }
    return intl.formatDate(date as Date, {
      day: 'numeric',
      month: 'long',
      year: 'numeric',
    });
  };
  const longDateTime = (date: string | number | Date | null | undefined): string => {
    if (isNone(date)) {
      return EMPTY_VALUE;
    }
    return intl.formatDate(date as Date, {
      day: 'numeric',
      month: 'long',
      year: 'numeric',
      second: 'numeric',
      minute: 'numeric',
      hour: 'numeric',
    });
  };
  const shortDate = (date: string | number | Date | null | undefined): string => {
    if (isNone(date)) {
      return EMPTY_VALUE;
    }
    return intl.formatDate(date as Date, {
      day: 'numeric',
      month: 'short',
      year: 'numeric',
    });
  };
  const shortNumericDate = (date: string | number | Date | null | undefined): string => {
    if (isNone(date)) {
      return EMPTY_VALUE;
    }
    return intl.formatDate(date as Date, {
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
  const minuteHourDate = (date: string | number | Date | null | undefined): string => {
    if (isNone(date)) {
      return EMPTY_VALUE;
    }
    return intl.formatDate(date as Date, {
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
  const shortMinuteHourDate = (date: string | number | Date | null | undefined): string => {
    if (isNone(date)) {
      return EMPTY_VALUE;
    }
    return intl.formatDate(date as Date, {
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

  interface TimeUnit {
    unit: Intl.RelativeTimeFormatUnit;
    interval: number;
  }

  const timeUnits: TimeUnit[] = [
    { unit: 'month', interval: MONTH_IN_MILLIS },
    { unit: 'week', interval: WEEK_IN_MILLIS },
    { unit: 'day', interval: DAY_IN_MILLIS },
    { unit: 'hour', interval: HOUR_IN_MILLIS },
    { unit: 'minute', interval: MIN_IN_MILLIS },
    { unit: 'second', interval: SEC_IN_MILLIS },
  ];

  const roundedValue = (diff: number, interval: number): number => Math.round(diff / interval);

  /**
   * Relative from now in word. Like "2 months ago", "in 3 minutes"...
   * @param date
   * @returns {string}
   */
  const relativeDate = (date: string | number | Date | null | undefined): string => {
    if (isNone(date)) {
      return EMPTY_VALUE;
    }
    const diff = new Date(date as Date).getTime() - new Date().getTime();
    for (const { unit, interval } of timeUnits) {
      if (Math.abs(diff) > interval) {
        const rounded = roundedValue(diff, interval);
        return intl.formatRelativeTime(rounded, unit);
      }
    }

    const rounded = roundedValue(diff, SEC_IN_MILLIS);
    return intl.formatRelativeTime(rounded, 'second');
  };

  const shortNumericDateTime = (date: string | number | Date | null | undefined): string => {
    if (isNone(date)) {
      return EMPTY_VALUE;
    }
    return intl.formatDate(date as Date, {
      second: 'numeric',
      minute: 'numeric',
      hour: 'numeric',
      day: 'numeric',
      month: 'short',
      year: 'numeric',
    });
  };
  const fullNumericDateTime = (date: string | number | Date | null | undefined): string => {
    if (isNone(date)) {
      return EMPTY_VALUE;
    }
    return intl.formatDate(date as Date, {
      second: 'numeric',
      minute: 'numeric',
      hour: 'numeric',
      day: 'numeric',
      month: 'numeric',
      year: 'numeric',
    });
  };
  const standardDate = (date: string | number | Date | null | undefined): string => {
    if (isNone(date)) {
      return EMPTY_VALUE;
    }
    return intl.formatDate(date as Date, {
      day: 'numeric',
      month: 'short',
      year: 'numeric',
    });
  };
  const monthDate = (date: string | number | Date | null | undefined): string => {
    if (isNone(date)) {
      return EMPTY_VALUE;
    }
    return intl.formatDate(date as Date, {
      month: 'short',
      year: 'numeric',
    });
  };
  const monthTextDate = (date: string | number | Date | null | undefined): string => {
    if (isNone(date)) {
      return EMPTY_VALUE;
    }
    return intl.formatDate(date as Date, { month: 'long' });
  };
  const monthTextYearDate = (date: string | number | Date | null | undefined): string => {
    if (isNone(date)) {
      return EMPTY_VALUE;
    }
    return intl.formatDate(date as Date, { month: 'long', year: 'numeric' });
  };
  const yearDate = (date: string | number | Date | null | undefined): string => {
    if (isNone(date)) {
      return EMPTY_VALUE;
    }
    return intl.formatDate(date as Date, { year: 'numeric' });
  };
  const numericTime = (date: string | number | Date | null | undefined): string => {
    if (isNone(date)) {
      return EMPTY_VALUE;
    }
    return intl.formatDate(date as Date, {
      second: 'numeric',
      minute: 'numeric',
      hour: 'numeric',
    });
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
  };
};

export default inject18n;
