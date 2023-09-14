import { Component } from 'react';
import { useIntl, injectIntl } from 'react-intl';
import moment from 'moment-timezone';
import { bytesFormat, numberFormat } from '../utils/Number';
import { getLengthUnitForLocale, getWeightUnitForLocale } from '../utils/UnitSystems';
import convert from 'convert';

export const isDateStringNone = (dateString) => {
  if (!dateString) return true;
  return (
    dateString.startsWith('Invalid')
    || dateString.startsWith('1970')
    || dateString.startsWith('5138')
  );
};

export const isNone = (date) => {
  if (!date) return true;
  if (date.length === 0) return true;
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
  const translate = (message) => intl.formatMessage({ id: message });
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

  /**
   * Formats a length number.
   * @param {string | number} number Length to format.
   * @param {string} toUnit Unit type to convert to. Optional.
   * @param {string} fromUnit Unit type to convert from. Optional.
   * @param {string} unitDisplay How to display the unit. Optional.
   * @param {number} precision Amount of precision to use. Optional.
   * @returns A formatted unit of length.
   */
  const formatLength = (number, toUnit = null, fromUnit = null, unitDisplay = 'long', precision = 0) => {
    const localeUnit = getLengthUnitForLocale(intl.locale);
    const converted = convert(number, fromUnit || localeUnit).to(toUnit || localeUnit);
    const formatOpts = { maximumFractionDigits: precision, unitDisplay };
    if (toUnit) {
      formatOpts['style'] = 'unit';
      formatOpts['unit'] = toUnit;
    }
    if (toUnit === 'foot' && unitDisplay === 'narrow') {
      const feet = Math.floor(converted);
      const inches = Math.round((converted - feet) * 12)
      return `${feet}'${inches}"`
    }
    return intl.formatNumber(Number(converted), formatOpts);
  };

  /**
   * Formats a weight number.
   * @param {string | number} number Weight to format.
   * @param {string} toUnit Unit type to convert to. Optional.
   * @param {string} fromUnit Unit type to convert from. Optional.
   * @param {string} unitDisplay How to display the unit. Optional.
   * @param {number} precision Amount of precision to use. Optional.
   * @returns A formatted unit of weight.
   */
  const formatWeight = (number, toUnit = null, fromUnit = null, unitDisplay = 'long', precision = 2) => {
    const localeUnit = getWeightUnitForLocale(intl.locale);
    const converted = convert(number, fromUnit || localeUnit).to(toUnit || localeUnit);
    const formatOpts = { maximumFractionDigits: precision, unitDisplay };
    if (toUnit) {
      formatOpts['style'] = 'unit';
      formatOpts['unit'] = toUnit;
    }
    return intl.formatNumber(Number(converted), formatOpts);
  };

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
  return {
    t: translate,
    n: formatNumber,
    b: formatBytes,
    len: formatLength,
    wgt: formatWeight,
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
  };
};

export default inject18n;
