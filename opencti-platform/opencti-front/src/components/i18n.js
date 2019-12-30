import React, { Component } from 'react';
import { injectIntl } from 'react-intl';
import { numberFormat } from '../utils/Number';

const inject18n = (WrappedComponent) => {
  class InjectIntl extends Component {
    render() {
      const { children } = this.props;
      const translate = (message) => this.props.intl.formatMessage({ id: message });
      const formatNumber = (number) => `${this.props.intl.formatNumber(numberFormat(number).number)}${
        numberFormat(number).symbol
      }`;
      const longDate = (date) => this.props.intl.formatDate(date, {
        day: 'numeric',
        month: 'long',
        year: 'numeric',
      });
      const shortDate = (date) => this.props.intl.formatDate(date, {
        day: 'numeric',
        month: 'short',
        year: 'numeric',
      });
      const shortNumericDate = (date) => this.props.intl.formatDate(date, {
        day: 'numeric',
        month: 'numeric',
        year: 'numeric',
      });
      const shortNumericDateTime = (date) => this.props.intl.formatDate(date, {
        second: 'numeric',
        minute: 'numeric',
        hour: 'numeric',
        day: 'numeric',
        month: 'numeric',
        year: 'numeric',
      });
      const standardDate = (date) => this.props.intl.formatDate(date);
      const monthDate = (date) => this.props.intl.formatDate(date, { month: 'short', year: 'numeric' });
      const yearDate = (date) => this.props.intl.formatDate(date, { year: 'numeric' });
      return (
        <WrappedComponent
          {...this.props}
          {...{ t: translate }}
          {...{ n: formatNumber }}
          {...{ fld: longDate }}
          {...{ fsd: shortDate }}
          {...{ nsd: shortNumericDate }}
          {...{ nsdt: shortNumericDateTime }}
          {...{ fd: standardDate }}
          {...{ md: monthDate }}
          {...{ yd: yearDate }}>
          {children}
        </WrappedComponent>
      );
    }
  }
  return injectIntl(InjectIntl);
};

export default inject18n;
