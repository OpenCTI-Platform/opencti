import React, { Component } from 'react';
import { injectIntl } from 'react-intl';

const inject18n = (WrappedComponent) => {
  class InjectIntl extends Component {
    render() {
      const { children } = this.props;
      const translate = message => this.props.intl.formatMessage({ id: message });
      const shortNumericDate = date => this.props.intl.formatDate(date, { day: 'numeric', month: 'numeric', year: 'numeric' });
      const shortDate = date => this.props.intl.formatDate(date, { day: 'numeric', month: 'short', year: 'numeric' });
      const standardDate = date => this.props.intl.formatDate(date);
      return (
        <WrappedComponent {...this.props}
                          {...{ t: translate }}
                          {...{ fsd: shortDate }}
                          {...{ nsd: shortNumericDate }}
                          {...{ fd: standardDate }}>
          {children}
        </WrappedComponent>
      );
    }
  }
  return injectIntl(InjectIntl);
};

export default inject18n;
