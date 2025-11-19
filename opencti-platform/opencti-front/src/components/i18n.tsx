import React, { Component, PropsWithChildren } from 'react';
import { injectIntl, IntlShape, useIntl } from 'react-intl';
import moment from 'moment-timezone';
import { bytesFormat, numberFormat } from '../utils/Number';

const FROM_START = 0;
const UNTIL_END = 100000000000000;

export const isDateStringNone = (dateString: string | null | undefined) => {
  if (!dateString) return true;
  if (dateString === (new Date(FROM_START).toISOString())) return true;
  if (dateString === (new Date(UNTIL_END).toISOString())) return true;
  return (
    dateString.startsWith('Invalid')
    || dateString.startsWith('1970')
    || dateString.startsWith('5138')
  );
};

export const isNone = (date: string | Date | null | undefined | number) => {
  if (!date) return true;
  if (typeof date === 'string' && date.length === 0) return true;
  if (date === (new Date(FROM_START).toISOString())) return true;
  if (date === (new Date(UNTIL_END).toISOString())) return true;
  const parsedDate = moment(date).format();
  return isDateStringNone(parsedDate);
};

/**
 * Wrapper of i18n functions to avoid defining two times the functions
 * in hook and in class.
 */
const i18nFunctions = (intl: IntlShape) => {
  const translate = (
    message: string | undefined | null,
    { id, values }: { id?: string, values?: Record<string, unknown> } = {},
  ) => {
    return intl.formatMessage({ id: id ?? message ?? undefined }, values) as string;
  };

  const formatNumber = (number: unknown) => {
    if (number === null || number === '') {
      return '-';
    }
    return `${intl.formatNumber(numberFormat(number).number)}${
      numberFormat(number).symbol
    }`;
  };

  const formatBytes = (number: unknown) => {
    const bytes = bytesFormat(number);
    return `${intl.formatNumber(bytes.number as number)}${bytes.symbol}`;
  };

  const longDate = (date: string | Date | undefined | null | number) => {
    if (isNone(date) || date === null) {
      return '-';
    }
    return intl.formatDate(date, {
      day: 'numeric',
      month: 'long',
      year: 'numeric',
    });
  };

  const longDateTime = (date: string | Date | undefined | null | number) => {
    if (isNone(date) || date === null) {
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

  const shortDate = (date: string | Date | undefined | null | number) => {
    if (isNone(date) || date === null) {
      return '-';
    }
    return intl.formatDate(date, {
      day: 'numeric',
      month: 'short',
      year: 'numeric',
    });
  };

  const shortNumericDate = (date: string | Date | undefined | null | number) => {
    if (isNone(date) || date === null) {
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
   */
  const minuteHourDate = (date: string | Date | undefined | null | number) => {
    if (isNone(date) || date === null) {
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
   */
  const shortMinuteHourDate = (date: string | Date | undefined | null | number) => {
    if (isNone(date) || date === null) {
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

  const timeUnits: { unit: Intl.RelativeTimeFormatUnit, interval: number }[] = [
    { unit: 'month', interval: MONTH_IN_MILLIS },
    { unit: 'week', interval: WEEK_IN_MILLIS },
    { unit: 'day', interval: DAY_IN_MILLIS },
    { unit: 'hour', interval: HOUR_IN_MILLIS },
    { unit: 'minute', interval: MIN_IN_MILLIS },
    { unit: 'second', interval: SEC_IN_MILLIS },
  ];

  const roundedValue = (diff: number, interval: number) => {
    return Math.round(diff / interval);
  };

  /**
   * Relative from now in word. Like "2 months ago", "in 3 minutes"...
   * @param date
   */
  const relativeDate = (date: string | Date | undefined | null | number) => {
    if (isNone(date) || date === undefined || date === null) {
      return '-';
    }
    const diff = new Date(date).getTime() - new Date().getTime();
    for (const { unit, interval } of timeUnits) {
      if (Math.abs(diff) > interval) {
        const rounded = roundedValue(diff, interval);
        return intl.formatRelativeTime(rounded, unit);
      }
    }

    const rounded = roundedValue(diff, SEC_IN_MILLIS);
    return intl.formatRelativeTime(rounded, 'second');
  };

  const shortNumericDateTime = (date: string | Date | undefined | null | number) => {
    if (isNone(date) || date === null) {
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

  const fullNumericDateTime = (date: string | Date | undefined | null | number) => {
    if (isNone(date) || date === null) {
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

  const standardDate = (date: string | Date | undefined | null | number) => {
    if (isNone(date) || date === null) {
      return '-';
    }
    return intl.formatDate(date, {
      day: 'numeric',
      month: 'short',
      year: 'numeric',
    });
  };

  const monthDate = (date: string | Date | undefined | null | number) => {
    if (isNone(date) || date === null) {
      return '-';
    }
    return intl.formatDate(date, {
      month: 'short',
      year: 'numeric',
    });
  };

  const monthTextDate = (date: string | Date | undefined | null | number) => {
    if (isNone(date) || date === null) {
      return '-';
    }
    return intl.formatDate(date, { month: 'long' });
  };

  const monthTextYearDate = (date: string | Date | undefined | null | number) => {
    if (isNone(date) || date === null) {
      return '-';
    }
    return intl.formatDate(date, { month: 'long', year: 'numeric' });
  };

  const yearDate = (date: string | Date | undefined | null | number) => {
    if (isNone(date) || date === null) {
      return '-';
    }
    return intl.formatDate(date, { year: 'numeric' });
  };

  const numericTime = (date: string | Date | undefined | null | number) => {
    if (isNone(date) || date === null) {
      return '-';
    }
    return intl.formatDate(date, {
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

type InjectIntlProps = PropsWithChildren & ReturnType<typeof i18nFunctions> & {
  intl: IntlShape
};

type WrappedComponentProps = InjectIntlProps & {
  [key: string]: unknown
};

type WrappedComponentType = React.FC<WrappedComponentProps>;

const inject18n = (WrappedComponent: WrappedComponentType) => {
  class InjectIntl extends Component<WrappedComponentProps> {
    render() {
      const { children, intl } = this.props;
      const functions = i18nFunctions(intl);

      return (
        <WrappedComponent {...this.props} {...functions}>
          {children}
        </WrappedComponent>
      );
    }
  }
  return injectIntl<'intl', WrappedComponentProps>(InjectIntl);
};

export const useFormatter = () => {
  const intl = useIntl();
  return i18nFunctions(intl);
};

export default inject18n;
