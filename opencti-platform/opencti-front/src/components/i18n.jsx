import { Component } from 'react';
import { useIntl, injectIntl } from 'react-intl';
import moment from 'moment-timezone';
import convert from 'convert';
import { bytesFormat, numberFormat } from '../utils/Number';
import useUserMetric, { BASE_LENGTH_TYPE, BASE_WEIGHT_TYPE } from '../utils/hooks/useUserMetric';
import { isEmptyField } from '../utils/utils';

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
  const { lengthPrimaryUnit, weightPrimaryUnit } = useUserMetric();
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
  const formatLength = (number) => {
    if (isEmptyField(number)) return '';
    const converted = convert(number, BASE_LENGTH_TYPE).to(lengthPrimaryUnit);
    const formatOpts = { maximumFractionDigits: 2, unitDisplay: 'long' };
    return intl.formatNumber(Number(converted), formatOpts);
  };
  const formatWeight = (number) => {
    if (isEmptyField(number)) return '';
    const converted = convert(number, BASE_WEIGHT_TYPE).to(weightPrimaryUnit);
    const formatOpts = { maximumFractionDigits: 2, unitDisplay: 'long' };
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
