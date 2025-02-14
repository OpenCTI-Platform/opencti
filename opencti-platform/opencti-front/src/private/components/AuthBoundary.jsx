import React from 'react';
import { compose, includes, map } from 'ramda';
import * as PropTypes from 'prop-types';
import { HighLevelError } from './Error';
import LoginRoot from '../../public/LoginRoot';
import withRouter from '../../utils/compat_router/withRouter';

class AuthBoundaryComponent extends React.Component {
  constructor(props) {
    super(props);
    this.state = { error: null, stack: null };
  }

  componentDidCatch(error, stack) {
    this.setState({ error, stack });
  }

  render() {
    if (this.state.error) {
      const baseErrors = this.state.error.res?.errors ?? [];
      const retroErrors = this.state.error.data?.res?.errors ?? [];
      const types = map((e) => e.extensions.code, [...baseErrors, ...retroErrors]);
      // If user not authenticated, redirect to login with encoded path
      if (includes('AUTH_REQUIRED', types)) {
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
