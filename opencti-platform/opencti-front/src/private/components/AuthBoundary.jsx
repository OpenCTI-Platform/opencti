import React from 'react';
import { compose, includes } from 'ramda';
import * as PropTypes from 'prop-types';
import LtsLicenseRoot from './LtsLicenseRoot';
import { getErrorCodes, HighLevelError, reportFrontendError } from './Error';
import LoginRoot from '../../public/LoginRoot';
import withRouter from '../../utils/compat_router/withRouter';

// Error codes redirected to a dedicated login / activation screen: expected, so not reported
const AUTH_BOUNDARY_HANDLED_CODES = ['AUTH_REQUIRED', 'IP_FORBIDDEN', 'LTS_REQUIRED_ACTIVATION', 'OTP_REQUIRED', 'OTP_REQUIRED_ACTIVATION'];

class AuthBoundaryComponent extends React.Component {
  constructor(props) {
    super(props);
    this.state = { error: null, stack: null };
  }

  componentDidCatch(error, stack) {
    this.setState({ error, stack });
    reportFrontendError(error, stack?.componentStack, AUTH_BOUNDARY_HANDLED_CODES);
  }

  render() {
    if (this.state.error) {
      const types = getErrorCodes(this.state.error);
      // If user not authenticated, redirect to login with encoded path
      if (includes('LTS_REQUIRED_ACTIVATION', types)) {
        return <LtsLicenseRoot />;
      }
      if (includes('AUTH_REQUIRED', types)) {
        return <LoginRoot type="LOGIN" />;
      }
      if (includes('IP_FORBIDDEN', types)) {
        return <LoginRoot type="LOGIN" />;
      }
      if (includes('OTP_REQUIRED_ACTIVATION', types)) {
        return <LoginRoot type="2FA_ACTIVATION" />;
      }
      if (includes('OTP_REQUIRED', types)) {
        return <LoginRoot type="2FA_VALIDATION" />;
      }
      return <HighLevelError />;
    }
    return this.props.children;
  }
}
AuthBoundaryComponent.propTypes = {
  children: PropTypes.node,
};
export default compose(withRouter)(AuthBoundaryComponent);
