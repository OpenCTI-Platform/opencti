import React, { Component } from 'react';
import { injectIntl } from 'react-intl';

const inject18n = (WrappedComponent) => {
  class InjectIntl extends Component {
    render() {
      const { children } = this.props;
      const translate = message => this.props.intl.formatMessage({ id: message });
      const longDate = date => this.props.intl.formatDate(date, { day: 'numeric', month: 'long', year: 'numeric' });
      const shortDate = date => this.props.intl.formatDate(date, { day: 'numeric', month: 'short', year: 'numeric' });
      const shortNumericDate = date => this.props.intl.formatDate(date, { day: 'numeric', month: 'numeric', year: 'numeric' });
      const standardDate = date => this.props.intl.formatDate(date);
      const monthDate = date => this.props.intl.formatDate(date, { month: 'short', year: 'numeric' });
      const yearDate = date => this.props.intl.formatDate(date, { day: 'numeric', month: 'numeric', year: 'numeric' });
      return (
        <WrappedComponent {...this.props}
                          {...{ t: translate }}
                          {...{ fld: longDate }}
                          {...{ fsd: shortDate }}
                          {...{ nsd: shortNumericDate }}
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
